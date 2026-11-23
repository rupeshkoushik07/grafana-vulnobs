// Package agent is the in-cluster half of "Scan now" when Grafana runs outside
// the cluster. It polls the Vulnobs app for scan requests, starts the scan
// CronJob for each, and tells the app how the CronJob is doing. Every
// connection goes from the cluster to Grafana, so Grafana needs no access to
// the Kubernetes API and the cluster needs no inbound route.
//
// In Kubernetes it may read one CronJob and list and create jobs in its own
// namespace: what "kubectl create job --from=cronjob/vulnobs-scan" needs.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// TokenHeader carries the scanner token to the app. Authorization is left
	// for Grafana's own login.
	TokenHeader = "X-Vulnobs-Scanner-Token"

	// manualAnnotation marks a job started by hand, as kubectl does.
	manualAnnotation = "cronjob.kubernetes.io/instantiate"
	// requestAnnotation records which scan request a job serves.
	requestAnnotation = "vulnobs.io/scan-request"
)

// Run is one run of the scan CronJob, in the app's JSON.
type Run struct {
	Name    string     `json:"name"`
	Trigger string     `json:"trigger"` // "manual" or "schedule"
	State   string     `json:"state"`   // "running", "succeeded" or "failed"
	Started *time.Time `json:"started,omitempty"`
	Ended   *time.Time `json:"ended,omitempty"`
}

// Report is the body of a poll: the state of the scan CronJob.
type Report struct {
	CronJob   string `json:"cronJob"`
	Namespace string `json:"namespace"`
	Schedule  string `json:"schedule,omitempty"`
	Running   bool   `json:"running"`
	Last      *Run   `json:"last,omitempty"`
	// ExcludeNamespaces is null when the CronJob doesn't say, [] when it
	// excludes nothing.
	ExcludeNamespaces []string `json:"excludeNamespaces"`
	PollSeconds       int      `json:"pollSeconds"`
	Error             string   `json:"error,omitempty"`
}

// Request is a scan request handed out by the app.
type Request struct {
	ID string `json:"id"`
}

// Kube is the slice of the Kubernetes API the agent uses.
type Kube struct {
	APIServer string
	TokenPath string
	Namespace string
	CronJob   string
	HTTP      *http.Client
}

// InCluster builds a Kube from the service account files mounted into the pod.
func InCluster(tokenPath, caPath, namespace, cronJob string) (*Kube, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set (not running in a cluster?)")
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("no certificates found in %s", caPath)
	}
	return &Kube{
		APIServer: "https://" + net.JoinHostPort(host, port),
		TokenPath: tokenPath,
		Namespace: namespace,
		CronJob:   cronJob,
		HTTP: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

type meta struct {
	Name            string            `json:"name,omitempty"`
	GenerateName    string            `json:"generateName,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	OwnerReferences []ownerRef        `json:"ownerReferences,omitempty"`
}

type ownerRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller"`
}

type cronJob struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Schedule    string `json:"schedule"`
		JobTemplate struct {
			Metadata meta `json:"metadata"`
			// Passed through untouched, so a requested run is exactly a scheduled one.
			Spec json.RawMessage `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

type job struct {
	APIVersion string          `json:"apiVersion,omitempty"`
	Kind       string          `json:"kind,omitempty"`
	Metadata   meta            `json:"metadata"`
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

func (j job) run() Run {
	r := Run{Name: j.Metadata.Name, Trigger: "schedule", State: "running", Started: j.Status.StartTime}
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

func (k *Kube) do(ctx context.Context, method, path string, body, out any) error {
	// Read on every call: the kubelet rotates projected tokens, and the agent
	// runs for longer than one lives.
	token, err := os.ReadFile(k.TokenPath)
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
	req, err := http.NewRequestWithContext(ctx, method, k.APIServer+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.HTTP.Do(req)
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
			status.Message = resp.Status
		}
		return fmt.Errorf("Kubernetes API: %s", status.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (k *Kube) cronJobPath() string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(k.Namespace) + "/cronjobs/" + url.PathEscape(k.CronJob)
}

func (k *Kube) jobsPath() string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(k.Namespace) + "/jobs"
}

// excludes reads the namespaces the scan job skips off the CronJob's discover
// step, so the app's workloads list can skip the same ones.
func excludes(spec json.RawMessage) []string {
	var js struct {
		Template struct {
			Spec struct {
				InitContainers []struct {
					Args []string `json:"args"`
				} `json:"initContainers"`
				Containers []struct {
					Args []string `json:"args"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	}
	if json.Unmarshal(spec, &js) != nil {
		return nil
	}
	split := func(s string) []string {
		out := []string{} // found but empty means "exclude nothing", not "unknown"
		for _, item := range strings.Split(s, ",") {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
		return out
	}
	for _, ct := range append(js.Template.Spec.InitContainers, js.Template.Spec.Containers...) {
		for i, arg := range ct.Args {
			if value, found := strings.CutPrefix(arg, "-exclude-namespaces="); found {
				return split(value)
			}
			if (arg == "-exclude-namespaces" || arg == "--exclude-namespaces") && i+1 < len(ct.Args) {
				return split(ct.Args[i+1])
			}
		}
	}
	return nil
}

// Status reads the CronJob and its runs.
func (k *Kube) Status(ctx context.Context) (Report, *cronJob, error) {
	report := Report{CronJob: k.CronJob, Namespace: k.Namespace}
	var cron cronJob
	if err := k.do(ctx, http.MethodGet, k.cronJobPath(), nil, &cron); err != nil {
		return report, nil, err
	}
	var list struct {
		Items []job `json:"items"`
	}
	if err := k.do(ctx, http.MethodGet, k.jobsPath()+"?limit=500", nil, &list); err != nil {
		return report, nil, err
	}
	var runs []Run
	for _, j := range list.Items {
		for _, owner := range j.Metadata.OwnerReferences {
			if owner.Kind == "CronJob" && owner.UID == cron.Metadata.UID {
				runs = append(runs, j.run())
				break
			}
		}
	}
	// Most recently started first; a job that hasn't started yet is the newest.
	sort.SliceStable(runs, func(i, j int) bool {
		a, b := runs[i].Started, runs[j].Started
		if a == nil || b == nil {
			return a == nil && b != nil
		}
		return a.After(*b)
	})
	report.Schedule = cron.Spec.Schedule
	report.ExcludeNamespaces = excludes(cron.Spec.JobTemplate.Spec)
	for i := range runs {
		if runs[i].State == "running" {
			report.Running = true
		}
	}
	if len(runs) > 0 {
		report.Last = &runs[0]
	}
	return report, &cron, nil
}

// Start creates a job from the CronJob's template for a scan request and
// returns its name.
func (k *Kube) Start(ctx context.Context, cron *cronJob, requestID string) (string, error) {
	annotations := map[string]string{}
	for key, v := range cron.Spec.JobTemplate.Metadata.Annotations {
		annotations[key] = v
	}
	annotations[manualAnnotation] = "manual"
	annotations[requestAnnotation] = requestID
	created := job{}
	err := k.do(ctx, http.MethodPost, k.jobsPath(), job{
		APIVersion: "batch/v1",
		Kind:       "Job",
		Metadata: meta{
			GenerateName: k.CronJob + "-manual-",
			Namespace:    k.Namespace,
			Labels:       cron.Spec.JobTemplate.Metadata.Labels,
			Annotations:  annotations,
			// Owned by the CronJob, like a scheduled run: its history limits
			// clean the job up.
			OwnerReferences: []ownerRef{{
				APIVersion: "batch/v1", Kind: "CronJob", Name: cron.Metadata.Name, UID: cron.Metadata.UID, Controller: true,
			}},
		},
		Spec: cron.Spec.JobTemplate.Spec,
	}, &created)
	return created.Metadata.Name, err
}

// App is the Vulnobs app's resource API, as the agent sees it.
type App struct {
	// BaseURL is ".../api/plugins/rupeshkoushik07-vulnobs-app/resources".
	BaseURL string
	// ScannerToken authenticates the agent to the app.
	ScannerToken string
	// GrafanaToken, when set, is a Grafana service account token for a Grafana
	// that requires login.
	GrafanaToken string
	HTTP         *http.Client
}

func (a *App) post(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.BaseURL, "/")+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(TokenHeader, a.ScannerToken)
	if a.GrafanaToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.GrafanaToken)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("reach the Vulnobs app: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = e.Message
		}
		return fmt.Errorf("Vulnobs app: %s %s", resp.Status, e.Error)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// Agent ties the two together.
type Agent struct {
	Kube     *Kube
	App      *App
	Interval time.Duration
	Logf     func(format string, args ...any)
}

// Step is one round: report the CronJob's state, and serve the request the
// app hands back, if any.
func (a *Agent) Step(ctx context.Context) error {
	report, cron, kubeErr := a.Kube.Status(ctx)
	report.PollSeconds = int(a.Interval / time.Second)
	if kubeErr != nil {
		// Still poll: the app shows the reason instead of a dead button.
		report.Error = kubeErr.Error()
	}
	var answer struct {
		Request *Request `json:"request"`
	}
	if err := a.App.post(ctx, "/scan-agent/poll", report, &answer); err != nil {
		return err
	}
	if kubeErr != nil {
		return kubeErr
	}
	if answer.Request == nil {
		return nil
	}

	id := answer.Request.ID
	outcome := map[string]string{"id": id, "state": "running"}
	switch {
	case report.Running && report.Last != nil:
		// A run is going already (the schedule, or a request whose report got
		// lost): the request follows that one.
		outcome["job"] = report.Last.Name
		a.Logf("scan request %s: run %s is already going", id, report.Last.Name)
	default:
		name, err := a.Kube.Start(ctx, cron, id)
		if err != nil {
			outcome["state"], outcome["message"] = "failed", err.Error()
			a.Logf("scan request %s: could not start a run: %v", id, err)
		} else {
			outcome["job"] = name
			a.Logf("scan request %s: started job %s", id, name)
		}
	}
	return a.App.post(ctx, "/scan-agent/report", outcome, nil)
}

// Run polls until the context ends. Failures are logged and retried: the app
// or the API server being away for a while is normal.
func (a *Agent) Run(ctx context.Context) {
	if a.Logf == nil {
		a.Logf = log.Printf
	}
	failing := ""
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()
	for {
		stepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := a.Step(stepCtx)
		cancel()
		switch {
		case err != nil && err.Error() != failing:
			// Once per distinct failure, not once per poll.
			failing = err.Error()
			a.Logf("poll failed (retrying every %s): %v", a.Interval, err)
		case err == nil && failing != "":
			failing = ""
			a.Logf("poll works again")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
