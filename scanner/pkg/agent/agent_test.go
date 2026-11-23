package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const cronJobJSON = `{
  "metadata": {"name": "vulnobs-scan", "namespace": "vulnobs", "uid": "cron-uid"},
  "spec": {
    "schedule": "0 * * * *",
    "jobTemplate": {
      "metadata": {"labels": {"team": "sec"}},
      "spec": {"backoffLimit": 1, "template": {"spec": {"restartPolicy": "Never",
        "initContainers": [{"name": "discover", "args": ["-exclude-namespaces", "kube-system,vulnobs"]}],
        "containers": [{"name": "push", "image": "curlimages/curl:8.22.0"}]}}}
    }
  }
}`

// fakeKube serves one CronJob and the jobs in its namespace.
type fakeKube struct {
	jobs    []map[string]any
	created []job
	forbid  string // refuse this method
	auth    []string
}

func (f *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	if f.forbid == r.Method {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message": "jobs.batch is forbidden"}`)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/apis/batch/v1/namespaces/vulnobs/cronjobs/vulnobs-scan":
		_, _ = io.WriteString(w, cronJobJSON)
	case r.Method == http.MethodGet && r.URL.Path == "/apis/batch/v1/namespaces/vulnobs/jobs":
		_ = json.NewEncoder(w).Encode(map[string]any{"items": f.jobs})
	case r.Method == http.MethodPost && r.URL.Path == "/apis/batch/v1/namespaces/vulnobs/jobs":
		var j job
		_ = json.NewDecoder(r.Body).Decode(&j)
		f.created = append(f.created, j)
		j.Metadata.Name = j.Metadata.GenerateName + "abc12"
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(j)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// fakeApp is the Vulnobs app: it records what the agent sends and hands out
// one request.
type fakeApp struct {
	pending string // request id to hand out on the next poll
	polls   []Report
	reports []map[string]string
	headers []http.Header
}

func (f *fakeApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.headers = append(f.headers, r.Header.Clone())
	if r.Header.Get(TokenHeader) != "scanner-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error": "missing or wrong scanner token"}`)
		return
	}
	switch r.URL.Path {
	case "/resources/scan-agent/poll":
		var report Report
		_ = json.NewDecoder(r.Body).Decode(&report)
		f.polls = append(f.polls, report)
		if f.pending != "" {
			_, _ = io.WriteString(w, `{"request": {"id": "`+f.pending+`", "state": "pending"}}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	case "/resources/scan-agent/report":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.reports = append(f.reports, body)
		f.pending = ""
		_, _ = io.WriteString(w, `{"ok": true}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newAgent(t *testing.T, kube *fakeKube, app *fakeApp) *Agent {
	t.Helper()
	kubeSrv, appSrv := httptest.NewServer(kube), httptest.NewServer(app)
	t.Cleanup(kubeSrv.Close)
	t.Cleanup(appSrv.Close)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Agent{
		Kube:     &Kube{APIServer: kubeSrv.URL, TokenPath: tokenPath, Namespace: "vulnobs", CronJob: "vulnobs-scan", HTTP: kubeSrv.Client()},
		App:      &App{BaseURL: appSrv.URL + "/resources/", ScannerToken: "scanner-secret", GrafanaToken: "glsa_x", HTTP: appSrv.Client()},
		Interval: 10 * time.Second,
		Logf:     t.Logf,
	}
}

func jobJSON(name, started string, annotations map[string]string, condition string) map[string]any {
	status := map[string]any{"startTime": started}
	if condition != "" {
		status["conditions"] = []map[string]any{{"type": condition, "status": "True", "lastTransitionTime": started}}
		status["completionTime"] = started
	}
	return map[string]any{
		"metadata": map[string]any{
			"name": name, "annotations": annotations,
			"ownerReferences": []map[string]any{{"kind": "CronJob", "uid": "cron-uid"}},
		},
		"status": status,
	}
}

// With nothing requested, a step only reports the CronJob's state.
func TestStepReports(t *testing.T) {
	kube := &fakeKube{jobs: []map[string]any{
		jobJSON("vulnobs-scan-100", "2026-01-01T10:00:00Z", nil, "Complete"),
		jobJSON("vulnobs-scan-manual-x", "2026-01-01T11:30:00Z", map[string]string{manualAnnotation: "manual"}, "Failed"),
		{"metadata": map[string]any{"name": "someone-elses-job"}, "status": map[string]any{"startTime": "2026-01-01T12:00:00Z"}},
	}}
	app := &fakeApp{}
	if err := newAgent(t, kube, app).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(app.polls) != 1 || len(app.reports) != 0 || len(kube.created) != 0 {
		t.Fatalf("polls %d, reports %d, created %d", len(app.polls), len(app.reports), len(kube.created))
	}
	p := app.polls[0]
	if p.CronJob != "vulnobs-scan" || p.Namespace != "vulnobs" || p.Schedule != "0 * * * *" || p.Running || p.PollSeconds != 10 {
		t.Errorf("report = %+v", p)
	}
	if p.Last == nil || p.Last.Name != "vulnobs-scan-manual-x" || p.Last.Trigger != "manual" || p.Last.State != "failed" {
		t.Errorf("last run = %+v, want the failed manual one", p.Last)
	}
	if !reflect.DeepEqual(p.ExcludeNamespaces, []string{"kube-system", "vulnobs"}) {
		t.Errorf("exclusions = %v", p.ExcludeNamespaces)
	}
	// Both tokens travel, in different headers; the Kubernetes token goes to
	// Kubernetes only.
	h := app.headers[0]
	if h.Get(TokenHeader) != "scanner-secret" || h.Get("Authorization") != "Bearer glsa_x" {
		t.Errorf("headers to the app = %v", h)
	}
	if kube.auth[0] != "Bearer sa-token" {
		t.Errorf("authorization to Kubernetes = %q", kube.auth[0])
	}
}

// A request starts a job from the CronJob's template and the agent says which.
func TestStepStartsRequestedScan(t *testing.T) {
	kube, app := &fakeKube{}, &fakeApp{pending: "req-1"}
	if err := newAgent(t, kube, app).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(kube.created) != 1 {
		t.Fatalf("created %d jobs, want 1", len(kube.created))
	}
	created := kube.created[0]
	if created.Metadata.GenerateName != "vulnobs-scan-manual-" || created.Metadata.Labels["team"] != "sec" ||
		created.Metadata.Annotations[manualAnnotation] != "manual" || created.Metadata.Annotations[requestAnnotation] != "req-1" {
		t.Errorf("job metadata = %+v", created.Metadata)
	}
	if o := created.Metadata.OwnerReferences; len(o) != 1 || o[0].UID != "cron-uid" || o[0].Kind != "CronJob" || !o[0].Controller {
		t.Errorf("owner references = %+v", o)
	}
	// The pod template must be the CronJob's, untouched.
	var cron cronJob
	_ = json.Unmarshal([]byte(cronJobJSON), &cron)
	var want, got any
	_ = json.Unmarshal(cron.Spec.JobTemplate.Spec, &want)
	_ = json.Unmarshal(created.Spec, &got)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("job spec:\n got %v\nwant %v", got, want)
	}
	want2 := []map[string]string{{"id": "req-1", "state": "running", "job": "vulnobs-scan-manual-abc12"}}
	if !reflect.DeepEqual(app.reports, want2) {
		t.Errorf("reports = %v, want %v", app.reports, want2)
	}
}

// While a run is going, a request joins it instead of starting a second one.
func TestStepJoinsRunningScan(t *testing.T) {
	kube := &fakeKube{jobs: []map[string]any{jobJSON("vulnobs-scan-200", "2026-01-01T10:00:00Z", nil, "")}}
	app := &fakeApp{pending: "req-2"}
	if err := newAgent(t, kube, app).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(kube.created) != 0 {
		t.Errorf("created %d jobs while one was running", len(kube.created))
	}
	want := []map[string]string{{"id": "req-2", "state": "running", "job": "vulnobs-scan-200"}}
	if !reflect.DeepEqual(app.reports, want) {
		t.Errorf("reports = %v, want %v", app.reports, want)
	}
}

func TestStepFailures(t *testing.T) {
	// Not allowed to create jobs: the request fails with the reason.
	kube, app := &fakeKube{forbid: http.MethodPost}, &fakeApp{pending: "req-3"}
	if err := newAgent(t, kube, app).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(app.reports) != 1 || app.reports[0]["state"] != "failed" || !strings.Contains(app.reports[0]["message"], "forbidden") {
		t.Errorf("reports = %v", app.reports)
	}

	// Not allowed to read the CronJob: the app is still told, so the page can say why.
	kube, app = &fakeKube{forbid: http.MethodGet}, &fakeApp{pending: "req-4"}
	if err := newAgent(t, kube, app).Step(context.Background()); err == nil {
		t.Error("want the Kubernetes error back")
	}
	if len(app.polls) != 1 || !strings.Contains(app.polls[0].Error, "forbidden") || len(app.reports) != 0 {
		t.Errorf("polls = %+v, reports = %v", app.polls, app.reports)
	}

	// A wrong scanner token is an error, and nothing is started.
	kube, app = &fakeKube{}, &fakeApp{pending: "req-5"}
	a := newAgent(t, kube, app)
	a.App.ScannerToken = "wrong"
	if err := a.Step(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("want a 401 error, got %v", err)
	}
	if len(kube.created) != 0 {
		t.Error("a refused agent started a job")
	}
}

func TestExcludes(t *testing.T) {
	spec := func(args string) json.RawMessage {
		return json.RawMessage(`{"template": {"spec": {"initContainers": [{"args": ` + args + `}]}}}`)
	}
	for args, want := range map[string][]string{
		`["-exclude-namespaces", "kube-system,vulnobs", "-targets", "/work/t"]`: {"kube-system", "vulnobs"},
		`["-exclude-namespaces=kube-system, shop"]`:                             {"kube-system", "shop"},
		`["-exclude-namespaces", ""]`:                                           {},
		`["-targets", "/work/t"]`:                                               nil,
	} {
		if got := excludes(spec(args)); !reflect.DeepEqual(got, want) {
			t.Errorf("args %s: got %#v, want %#v", args, got, want)
		}
	}
}
