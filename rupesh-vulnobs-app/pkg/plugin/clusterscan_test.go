package plugin

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

// fakeKube is the slice of the Kubernetes API the scanner uses: one CronJob
// and the jobs in its namespace.
type fakeKube struct {
	mu      sync.Mutex
	jobs    []map[string]any
	created []kubeJob
	forbid  bool
	auth    []string
	// cronJob replaces the default CronJob body, when set.
	cronJob string
	// pods serves the pod list, when the test has one.
	pods func(http.ResponseWriter, *http.Request) bool
}

const cronJobJSON = `{
  "apiVersion": "batch/v1", "kind": "CronJob",
  "metadata": {"name": "vulnobs-scan", "namespace": "vulnobs", "uid": "cron-uid"},
  "spec": {
    "schedule": "0 * * * *",
    "jobTemplate": {
      "metadata": {"labels": {"team": "sec"}},
      "spec": {"backoffLimit": 1, "template": {"spec": {"restartPolicy": "Never",
        "containers": [{"name": "push", "image": "curlimages/curl:8.22.0"}]}}}
    }
  }
}`

func (f *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	if f.forbid {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"kind":"Status","message":"cronjobs.batch \"vulnobs-scan\" is forbidden","code":403}`)
		return
	}
	if f.pods != nil && f.pods(w, r) {
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/apis/batch/v1/namespaces/vulnobs/cronjobs/vulnobs-scan":
		body := cronJobJSON
		if f.cronJob != "" {
			body = f.cronJob
		}
		_, _ = io.WriteString(w, body)
	case r.Method == http.MethodGet && r.URL.Path == "/apis/batch/v1/namespaces/vulnobs/jobs":
		_ = json.NewEncoder(w).Encode(map[string]any{"items": f.jobs})
	case r.Method == http.MethodPost && r.URL.Path == "/apis/batch/v1/namespaces/vulnobs/jobs":
		var job kubeJob
		if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.created = append(f.created, job)
		job.Metadata.Name = job.Metadata.GenerateName + "abc12"
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(job)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"kind":"Status","message":"not found","code":404}`)
	}
}

func job(name, ownerUID, started string, annotations map[string]string, condition string) map[string]any {
	status := map[string]any{"startTime": started}
	if condition != "" {
		status["conditions"] = []map[string]any{{"type": condition, "status": "True", "lastTransitionTime": started}}
		status["completionTime"] = started
	}
	return map[string]any{
		"metadata": map[string]any{
			"name": name, "annotations": annotations,
			"ownerReferences": []map[string]any{{"kind": "CronJob", "uid": ownerUID}},
		},
		"status": status,
	}
}

// newTestScanner points a scanner at a fake API server, through the same
// service account files a pod gets.
func newTestScanner(t *testing.T, kube *fakeKube) *clusterScanner {
	t.Helper()
	srv := httptest.NewTLSServer(kube)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	for name, content := range map[string][]byte{"token": []byte("sa-token\n"), "ca.crt": ca, "namespace": []byte("vulnobs")} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := newClusterScanner(appSettings{KubernetesAPIServer: srv.URL}, dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNoServiceAccount(t *testing.T) {
	if _, err := newClusterScanner(appSettings{}, t.TempDir()); !errors.Is(err, errNoServiceAccount) {
		t.Errorf("want errNoServiceAccount, got %v", err)
	}
}

func TestClusterScanStatus(t *testing.T) {
	kube := &fakeKube{jobs: []map[string]any{
		job("vulnobs-scan-100", "cron-uid", "2026-01-01T10:00:00Z", nil, "Complete"),
		job("vulnobs-scan-manual-x", "cron-uid", "2026-01-01T11:30:00Z", map[string]string{manualAnnotation: "manual"}, "Failed"),
		job("someone-elses-job", "other-uid", "2026-01-01T12:00:00Z", nil, ""),
	}}
	st, _, err := newTestScanner(t, kube).status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Available || st.Running || st.Schedule != "0 * * * *" || st.Namespace != "vulnobs" {
		t.Errorf("status = %+v", st)
	}
	if st.Last == nil || st.Last.Name != "vulnobs-scan-manual-x" || st.Last.Trigger != "manual" || st.Last.State != "failed" {
		t.Errorf("last run = %+v, want the failed manual one", st.Last)
	}
	if kube.auth[0] != "Bearer sa-token" {
		t.Errorf("authorization = %q", kube.auth[0])
	}
}

func TestClusterScanStart(t *testing.T) {
	kube := &fakeKube{}
	st, err := newTestScanner(t, kube).start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Running || st.Last == nil || st.Last.Name != "vulnobs-scan-manual-abc12" || st.Last.Trigger != "manual" {
		t.Errorf("status after start = %+v, last %+v", st, st.Last)
	}

	if len(kube.created) != 1 {
		t.Fatalf("created %d jobs, want 1", len(kube.created))
	}
	created := kube.created[0]
	if created.Metadata.GenerateName != "vulnobs-scan-manual-" || created.Metadata.Labels["team"] != "sec" ||
		created.Metadata.Annotations[manualAnnotation] != "manual" {
		t.Errorf("job metadata = %+v", created.Metadata)
	}
	if o := created.Metadata.OwnerReferences; len(o) != 1 || o[0].UID != "cron-uid" || o[0].Kind != "CronJob" || !o[0].Controller {
		t.Errorf("owner references = %+v", o)
	}
	// The pod template must be the CronJob's, untouched.
	var want, got any
	var cron kubeCronJob
	_ = json.Unmarshal([]byte(cronJobJSON), &cron)
	_ = json.Unmarshal(cron.Spec.JobTemplate.Spec, &want)
	_ = json.Unmarshal(created.Spec, &got)
	if w, g := mustJSON(want), mustJSON(got); w != g {
		t.Errorf("job spec:\n got %s\nwant %s", g, w)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestClusterScanStartWhileRunning(t *testing.T) {
	kube := &fakeKube{jobs: []map[string]any{job("vulnobs-scan-200", "cron-uid", "2026-01-01T10:00:00Z", nil, "")}}
	st, err := newTestScanner(t, kube).start(context.Background())
	if !errors.Is(err, errScanRunning) {
		t.Fatalf("want errScanRunning, got %v", err)
	}
	if st == nil || !st.Running || len(kube.created) != 0 {
		t.Errorf("status = %+v, created %d jobs", st, len(kube.created))
	}
}

// callClusterScan sends a resource call as a user with the given org role.
func callClusterScan(t *testing.T, app *App, method, role string) *backend.CallResourceResponse {
	t.Helper()
	var sender mockCallResourceResponseSender
	req := &backend.CallResourceRequest{Method: method, Path: "cluster-scan"}
	if role != "" {
		req.PluginContext.User = &backend.User{Login: "someone", Role: role}
	}
	if err := app.CallResource(context.Background(), req, &sender); err != nil {
		t.Fatal(err)
	}
	return sender.response
}

func TestHandleClusterScan(t *testing.T) {
	inst, err := NewApp(context.Background(), backend.AppInstanceSettings{})
	if err != nil {
		t.Fatal(err)
	}
	app := inst.(*App)

	// No service account (the default, and what tests run with).
	app.cluster = nil
	resp := callClusterScan(t, app, http.MethodGet, "Viewer")
	var st ClusterScanStatus
	if err := json.Unmarshal(resp.Body, &st); err != nil || resp.Status != http.StatusOK || st.Available || st.Reason == "" {
		t.Errorf("unavailable status = %d %s", resp.Status, resp.Body)
	}
	if resp := callClusterScan(t, app, http.MethodPost, "Admin"); resp.Status != http.StatusServiceUnavailable {
		t.Errorf("POST without a service account = %d, want 503", resp.Status)
	}

	kube := &fakeKube{}
	app.cluster = newTestScanner(t, kube)
	if resp := callClusterScan(t, app, http.MethodPost, "Viewer"); resp.Status != http.StatusForbidden {
		t.Errorf("viewer POST = %d, want 403", resp.Status)
	}
	if resp := callClusterScan(t, app, http.MethodPost, ""); resp.Status != http.StatusForbidden {
		t.Errorf("anonymous POST = %d, want 403", resp.Status)
	}
	if len(kube.created) != 0 {
		t.Fatalf("a refused request created %d jobs", len(kube.created))
	}
	if resp := callClusterScan(t, app, http.MethodPost, "Editor"); resp.Status != http.StatusAccepted || len(kube.created) != 1 {
		t.Errorf("editor POST = %d %s, created %d", resp.Status, resp.Body, len(kube.created))
	}

	// A running job blocks a second one.
	kube.jobs = []map[string]any{job("vulnobs-scan-manual-abc12", "cron-uid", "2026-01-01T10:00:00Z", nil, "")}
	if resp := callClusterScan(t, app, http.MethodPost, "Admin"); resp.Status != http.StatusConflict || len(kube.created) != 1 {
		t.Errorf("POST while running = %d, created %d", resp.Status, len(kube.created))
	}

	// Missing RBAC is reported, not hidden: GET says why the button is off.
	kube.forbid = true
	resp = callClusterScan(t, app, http.MethodGet, "Viewer")
	st = ClusterScanStatus{}
	_ = json.Unmarshal(resp.Body, &st)
	if st.Available || !strings.Contains(st.Reason, "forbidden") {
		t.Errorf("forbidden status = %s", resp.Body)
	}
	if resp := callClusterScan(t, app, http.MethodPost, "Admin"); resp.Status != http.StatusForbidden {
		t.Errorf("POST without RBAC = %d, want 403", resp.Status)
	}
}
