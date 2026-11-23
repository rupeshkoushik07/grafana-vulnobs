package plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

// The "Scan now" button on the Assets page starts one run of the cluster scan
// CronJob, the same way `kubectl create job --from=cronjob/vulnobs-scan` does.
// The scan itself stays in the CronJob's pod template; the app only asks
// Kubernetes to run it early.
//
// It needs a Kubernetes service account, which the app doesn't have by
// default. The Tanka environment mounts one (scanNow: true) that may read the
// scan CronJob, list jobs and create jobs in the app's own namespace.

const (
	defaultServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultScanCronJob       = "vulnobs-scan"
	// In-cluster DNS name of the API server; its certificate always carries it.
	defaultKubeAPIServer = "https://kubernetes.default.svc"

	// manualAnnotation marks a job started by hand, as kubectl does.
	manualAnnotation = "cronjob.kubernetes.io/instantiate"
)

// clusterScanner starts and reports on runs of the scan CronJob.
type clusterScanner struct {
	apiServer string
	namespace string
	cronJob   string
	tokenPath string
	http      *http.Client
}

// errNoServiceAccount means the app can't reach Kubernetes at all, which is
// the normal state outside a cluster or with scanNow off.
var errNoServiceAccount = errors.New("Grafana has no Kubernetes service account, so it can't start the cluster scan. " +
	"Deploy with scanNow enabled (see deploy/tanka), or wait for the scheduled scan")

// newClusterScanner builds a scanner from the service account files mounted
// into the Grafana pod and the app's settings.
func newClusterScanner(cfg appSettings, saDir string) (*clusterScanner, error) {
	tokenPath := filepath.Join(saDir, "token")
	if _, err := os.Stat(tokenPath); err != nil {
		return nil, errNoServiceAccount
	}
	ca, err := os.ReadFile(filepath.Join(saDir, "ca.crt")) // #nosec G304 -- fixed service account directory.
	if err != nil {
		return nil, fmt.Errorf("read the cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("the service account's ca.crt holds no certificates")
	}

	namespace := strings.TrimSpace(cfg.KubernetesNamespace)
	if namespace == "" {
		raw, err := os.ReadFile(filepath.Join(saDir, "namespace")) // #nosec G304 -- fixed service account directory.
		if err != nil {
			return nil, fmt.Errorf("read the service account namespace: %w", err)
		}
		namespace = strings.TrimSpace(string(raw))
	}

	apiServer := strings.TrimRight(strings.TrimSpace(cfg.KubernetesAPIServer), "/")
	if apiServer == "" {
		apiServer = defaultKubeAPIServer
		// Grafana doesn't pass these on to plugins everywhere, hence the DNS default.
		if host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"); host != "" && port != "" {
			apiServer = "https://" + net.JoinHostPort(host, port)
		}
	}
	if u, err := url.Parse(apiServer); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the Kubernetes API server address %q must be an https URL", apiServer)
	}

	cronJob := strings.TrimSpace(cfg.ScanCronJob)
	if cronJob == "" {
		cronJob = defaultScanCronJob
	}

	return &clusterScanner{
		apiServer: apiServer,
		namespace: namespace,
		cronJob:   cronJob,
		tokenPath: tokenPath,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// kubeError is a non-2xx answer from the Kubernetes API.
type kubeError struct {
	status  int
	message string
}

func (e kubeError) Error() string { return fmt.Sprintf("Kubernetes API: %d %s", e.status, e.message) }

func (c *clusterScanner) do(ctx context.Context, method, path string, body, out any) error {
	// Read on every call: the kubelet rotates projected tokens.
	token, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return fmt.Errorf("read the service account token: %w", err)
	}
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiServer+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req) // #nosec G704 -- the API server address comes from admin-only app settings.
	if err != nil {
		return fmt.Errorf("reach the Kubernetes API: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var status struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &status)
		if status.Message == "" {
			status.Message = http.StatusText(resp.StatusCode)
		}
		return kubeError{status: resp.StatusCode, message: status.Message}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

type kubeMeta struct {
	Name            string            `json:"name,omitempty"`
	GenerateName    string            `json:"generateName,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	OwnerReferences []kubeOwner       `json:"ownerReferences,omitempty"`
}

type kubeOwner struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller"`
}

type kubeCronJob struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		Schedule    string `json:"schedule"`
		JobTemplate struct {
			Metadata kubeMeta `json:"metadata"`
			// Passed through untouched, so a manual run is exactly a scheduled one.
			Spec json.RawMessage `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

type kubeJob struct {
	APIVersion string          `json:"apiVersion,omitempty"`
	Kind       string          `json:"kind,omitempty"`
	Metadata   kubeMeta        `json:"metadata"`
	Spec       json.RawMessage `json:"spec,omitempty"`
	Status     struct {
		StartTime      *time.Time `json:"startTime,omitempty"`
		CompletionTime *time.Time `json:"completionTime,omitempty"`
		Conditions     []struct {
			Type               string     `json:"type"`
			Status             string     `json:"status"`
			LastTransitionTime *time.Time `json:"lastTransitionTime,omitempty"`
		} `json:"conditions,omitempty"`
	} `json:"status,omitempty"`
}

// ScanRun is one run of the scan CronJob, as shown on the Assets page.
type ScanRun struct {
	Name    string     `json:"name"`
	Trigger string     `json:"trigger"` // "manual" or "schedule"
	State   string     `json:"state"`   // "running", "succeeded" or "failed"
	Started *time.Time `json:"started,omitempty"`
	Ended   *time.Time `json:"ended,omitempty"`
}

// ClusterScanStatus is the answer to GET /cluster-scan.
type ClusterScanStatus struct {
	Available bool     `json:"available"`
	Reason    string   `json:"reason,omitempty"` // why not, when unavailable
	CronJob   string   `json:"cronJob,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Schedule  string   `json:"schedule,omitempty"`
	Running   bool     `json:"running"`
	Last      *ScanRun `json:"last,omitempty"` // the most recently started run
	// Mode is "agent" when runs are started by the in-cluster scan agent
	// instead of by the app itself (clusterMode "remote").
	Mode string `json:"mode,omitempty"`
	// Request is the latest "Scan now" request, in that mode, until the run it
	// started shows up as Last.
	Request *ScanRequest `json:"request,omitempty"`
}

func (j kubeJob) run() ScanRun {
	r := ScanRun{Name: j.Metadata.Name, Trigger: "schedule", State: "running", Started: j.Status.StartTime}
	if j.Metadata.Annotations[manualAnnotation] == "manual" {
		r.Trigger = "manual"
	}
	for _, c := range j.Status.Conditions {
		if c.Status != "True" {
			continue
		}
		switch c.Type {
		case "Complete":
			r.State, r.Ended = "succeeded", j.Status.CompletionTime
		case "Failed":
			r.State, r.Ended = "failed", c.LastTransitionTime
		}
	}
	return r
}

func (c *clusterScanner) cronJobPath() string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(c.namespace) + "/cronjobs/" + url.PathEscape(c.cronJob)
}

func (c *clusterScanner) jobsPath() string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(c.namespace) + "/jobs"
}

// runs returns the CronJob's runs, most recently started first.
func (c *clusterScanner) runs(ctx context.Context, cron *kubeCronJob) ([]ScanRun, error) {
	var list struct {
		Items []kubeJob `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, c.jobsPath()+"?limit=500", nil, &list); err != nil {
		return nil, err
	}
	var runs []ScanRun
	for _, job := range list.Items {
		for _, owner := range job.Metadata.OwnerReferences {
			if owner.Kind == "CronJob" && owner.UID == cron.Metadata.UID {
				runs = append(runs, job.run())
				break
			}
		}
	}
	sort.SliceStable(runs, func(i, j int) bool {
		a, b := runs[i].Started, runs[j].Started
		switch {
		case a == nil || b == nil:
			return a == nil && b != nil // a job that hasn't started yet is the newest
		default:
			return a.After(*b)
		}
	})
	return runs, nil
}

func (c *clusterScanner) status(ctx context.Context) (*ClusterScanStatus, *kubeCronJob, error) {
	var cron kubeCronJob
	if err := c.do(ctx, http.MethodGet, c.cronJobPath(), nil, &cron); err != nil {
		return nil, nil, err
	}
	runs, err := c.runs(ctx, &cron)
	if err != nil {
		return nil, nil, err
	}
	st := &ClusterScanStatus{Available: true, CronJob: c.cronJob, Namespace: c.namespace, Schedule: cron.Spec.Schedule}
	for i := range runs {
		if runs[i].State == "running" {
			st.Running = true
		}
	}
	if len(runs) > 0 {
		st.Last = &runs[0]
	}
	return st, &cron, nil
}

// errScanRunning is returned by start while a run is still going.
var errScanRunning = errors.New("a cluster scan is already running")

// start creates a job from the CronJob's template and returns the new status.
func (c *clusterScanner) start(ctx context.Context) (*ClusterScanStatus, error) {
	st, cron, err := c.status(ctx)
	if err != nil {
		return nil, err
	}
	if st.Running {
		return st, errScanRunning
	}

	annotations := map[string]string{}
	for k, v := range cron.Spec.JobTemplate.Metadata.Annotations {
		annotations[k] = v
	}
	annotations[manualAnnotation] = "manual"
	job := kubeJob{
		APIVersion: "batch/v1",
		Kind:       "Job",
		Metadata: kubeMeta{
			GenerateName: c.cronJob + "-manual-",
			Namespace:    c.namespace,
			Labels:       cron.Spec.JobTemplate.Metadata.Labels,
			Annotations:  annotations,
			// Owned by the CronJob, like a scheduled run: its history limits
			// clean the job up, and its concurrency policy sees it.
			OwnerReferences: []kubeOwner{{
				APIVersion: "batch/v1", Kind: "CronJob", Name: cron.Metadata.Name, UID: cron.Metadata.UID, Controller: true,
			}},
		},
		Spec: cron.Spec.JobTemplate.Spec,
	}
	var created kubeJob
	if err := c.do(ctx, http.MethodPost, c.jobsPath(), job, &created); err != nil {
		return nil, err
	}
	run := created.run()
	st.Running, st.Last = true, &run
	return st, nil
}

// explainKubeError turns an API failure into something an operator can act on.
// A 404 can only come from the scan CronJob lookup: lists don't return it.
func (c *clusterScanner) explainKubeError(err error) (int, string) {
	var ke kubeError
	if !errors.As(err, &ke) {
		return http.StatusBadGateway, "could not reach the Kubernetes API"
	}
	switch ke.status {
	case http.StatusNotFound:
		return http.StatusNotFound, fmt.Sprintf("no CronJob %q in namespace %q; set scanCronJob in the app's settings if yours has another name", c.cronJob, c.namespace)
	case http.StatusForbidden, http.StatusUnauthorized:
		return http.StatusForbidden, "Grafana's service account isn't allowed to do that: " + ke.message
	default:
		return http.StatusBadGateway, ke.Error()
	}
}

// mayStartScan reports whether the calling user may start a scan: editors and
// admins, since a run pulls and scans every image in the cluster.
func mayStartScan(ctx context.Context) bool {
	user := backend.UserFromContext(ctx)
	return user != nil && (user.Role == "Admin" || user.Role == "Editor")
}

// handleClusterScan reports on the cluster scan and starts a run on demand.
//
//	GET  /resources/cluster-scan   whether "Scan now" is available, and the latest run
//	POST /resources/cluster-scan   start a run now (editors and admins)
func (a *App) handleClusterScan(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use GET for the status or POST to start a scan")
		return
	}
	if a.remote {
		a.handleRemoteClusterScan(w, req)
		return
	}
	if a.cluster == nil {
		reason := errNoServiceAccount.Error()
		if a.clusterErr != nil {
			reason = a.clusterErr.Error()
		}
		if req.Method == http.MethodPost {
			writeError(w, http.StatusServiceUnavailable, reason)
			return
		}
		writeJSON(w, ClusterScanStatus{Available: false, Reason: reason})
		return
	}

	if req.Method == http.MethodGet {
		st, _, err := a.cluster.status(req.Context())
		if err != nil {
			_, reason := a.cluster.explainKubeError(err)
			writeJSON(w, ClusterScanStatus{Available: false, Reason: reason, CronJob: a.cluster.cronJob, Namespace: a.cluster.namespace})
			return
		}
		writeJSON(w, st)
		return
	}

	if !mayStartScan(req.Context()) {
		writeError(w, http.StatusForbidden, "only editors and admins can start a cluster scan")
		return
	}
	st, err := a.cluster.start(req.Context())
	switch {
	case errors.Is(err, errScanRunning):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(st)
	case err != nil:
		backend.Logger.Error("Could not start the cluster scan", "cronJob", a.cluster.cronJob, "error", err)
		status, reason := a.cluster.explainKubeError(err)
		writeError(w, status, reason)
	default:
		backend.Logger.Info("Started a cluster scan", "job", st.Last.Name)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(st)
	}
}
