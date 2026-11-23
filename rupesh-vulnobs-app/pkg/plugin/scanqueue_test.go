package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

const testScannerToken = "0123456789abcdef0123456789abcdef"

// remoteCall sends a resource call to a remote-mode app. token is the scanner
// token header; role is the calling Grafana user's.
func remoteCall(t *testing.T, app *App, method, path, role, token string, body any) *backend.CallResourceResponse {
	t.Helper()
	req := &backend.CallResourceRequest{Method: method, Path: path, Headers: map[string][]string{}}
	if body != nil {
		req.Body, _ = json.Marshal(body)
	}
	if token != "" {
		req.Headers[scannerTokenHeader] = []string{token}
	}
	if role != "" {
		req.PluginContext.User = &backend.User{Login: "rosa", Role: role}
	}
	var sender mockCallResourceResponseSender
	if err := app.CallResource(context.Background(), req, &sender); err != nil {
		t.Fatal(err)
	}
	return sender.response
}

func scanStatus(t *testing.T, app *App) ClusterScanStatus {
	t.Helper()
	resp := remoteCall(t, app, http.MethodGet, "cluster-scan", "Viewer", "", nil)
	var st ClusterScanStatus
	if err := json.Unmarshal(resp.Body, &st); err != nil || resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, resp.Body)
	}
	return st
}

func agentPoll(t *testing.T, app *App, report AgentReport) *ScanRequest {
	t.Helper()
	resp := remoteCall(t, app, http.MethodPost, "scan-agent/poll", "", testScannerToken, report)
	if resp.Status != http.StatusOK {
		t.Fatalf("poll: %d %s", resp.Status, resp.Body)
	}
	var out struct {
		Request *ScanRequest `json:"request"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Request
}

// The whole round trip: click, the agent picks the request up, starts a job,
// and its later reports finish the request.
func TestScanRequestFlow(t *testing.T) {
	app := remoteApp(t, `{"clusterMode": "remote"}`, map[string]string{"scannerToken": testScannerToken})
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	app.scans.now = func() time.Time { return now }
	idle := AgentReport{CronJob: "vulnobs-scan", Namespace: "vulnobs", Schedule: "0 * * * *", PollSeconds: 10}

	// Before any agent connects there is nobody to run a scan.
	if st := scanStatus(t, app); st.Available || st.Mode != "agent" || !strings.Contains(st.Reason, "No scan agent") {
		t.Errorf("no agent yet: %+v", st)
	}
	if resp := remoteCall(t, app, http.MethodPost, "cluster-scan", "Admin", "", nil); resp.Status != http.StatusServiceUnavailable {
		t.Errorf("POST without an agent = %d, want 503", resp.Status)
	}

	if req := agentPoll(t, app, idle); req != nil {
		t.Fatalf("nothing was requested, got %+v", req)
	}
	if st := scanStatus(t, app); !st.Available || st.Running || st.Schedule != "0 * * * *" || st.CronJob != "vulnobs-scan" {
		t.Errorf("idle: %+v", st)
	}

	// Who may click is the same as in-cluster.
	for _, role := range []string{"Viewer", ""} {
		if resp := remoteCall(t, app, http.MethodPost, "cluster-scan", role, "", nil); resp.Status != http.StatusForbidden {
			t.Errorf("POST as %q = %d, want 403", role, resp.Status)
		}
	}
	resp := remoteCall(t, app, http.MethodPost, "cluster-scan", "Editor", "", nil)
	var st ClusterScanStatus
	_ = json.Unmarshal(resp.Body, &st)
	if resp.Status != http.StatusAccepted || !st.Running || st.Request == nil || st.Request.State != "pending" || st.Request.RequestedBy != "rosa" {
		t.Fatalf("editor POST = %d %s", resp.Status, resp.Body)
	}
	id := st.Request.ID

	// A second click while one is waiting is a conflict, with the status to follow.
	resp = remoteCall(t, app, http.MethodPost, "cluster-scan", "Admin", "", nil)
	st = ClusterScanStatus{}
	_ = json.Unmarshal(resp.Body, &st)
	if resp.Status != http.StatusConflict || st.Request == nil || st.Request.ID != id {
		t.Errorf("second POST = %d %s", resp.Status, resp.Body)
	}

	// The agent gets the request, and gets it again if its answer was lost.
	for i := 0; i < 2; i++ {
		if req := agentPoll(t, app, idle); req == nil || req.ID != id {
			t.Fatalf("poll %d: want request %s, got %+v", i, id, req)
		}
	}
	report := map[string]string{"id": id, "state": "running", "job": "vulnobs-scan-manual-abc12"}
	if resp := remoteCall(t, app, http.MethodPost, "scan-agent/report", "", testScannerToken, report); resp.Status != http.StatusOK {
		t.Fatalf("report: %d %s", resp.Status, resp.Body)
	}
	// Picked up: not handed out again, and the button stays busy even though
	// the agent's last report predates the job.
	st = scanStatus(t, app)
	if !st.Running || st.Request == nil || st.Request.State != "running" || st.Request.Job != "vulnobs-scan-manual-abc12" {
		t.Errorf("after pickup: %+v", st)
	}
	if st.Last == nil || st.Last.Name != "vulnobs-scan-manual-abc12" || st.Last.State != "running" {
		t.Errorf("the page should already see the new run, got last = %+v", st.Last)
	}
	started := now
	running := idle
	running.Running = true
	running.Last = &ScanRun{Name: "vulnobs-scan-manual-abc12", Trigger: "manual", State: "running", Started: &started}
	if req := agentPoll(t, app, running); req != nil {
		t.Errorf("a picked-up request was handed out again: %+v", req)
	}
	if st := scanStatus(t, app); !st.Running || st.Last == nil || st.Last.Name != "vulnobs-scan-manual-abc12" {
		t.Errorf("while running: %+v", st)
	}

	// The job finishes: the next poll says so and the button is free again.
	now = now.Add(90 * time.Second)
	ended := now
	done := idle
	done.Last = &ScanRun{Name: "vulnobs-scan-manual-abc12", Trigger: "manual", State: "succeeded", Started: &started, Ended: &ended}
	agentPoll(t, app, done)
	st = scanStatus(t, app)
	if st.Running || st.Request != nil || st.Last == nil || st.Last.State != "succeeded" || st.Last.Trigger != "manual" {
		t.Errorf("after the run: %+v (last %+v)", st, st.Last)
	}
	if resp := remoteCall(t, app, http.MethodPost, "cluster-scan", "Editor", "", nil); resp.Status != http.StatusAccepted {
		t.Errorf("POST after the run = %d, want 202", resp.Status)
	}
}

func TestScanRequestFailures(t *testing.T) {
	app := remoteApp(t, `{"clusterMode": "remote"}`, map[string]string{"scannerToken": testScannerToken})
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	app.scans.now = func() time.Time { return now }
	idle := AgentReport{CronJob: "vulnobs-scan", Namespace: "vulnobs", PollSeconds: 10}
	click := func() string {
		t.Helper()
		resp := remoteCall(t, app, http.MethodPost, "cluster-scan", "Editor", "", nil)
		var st ClusterScanStatus
		_ = json.Unmarshal(resp.Body, &st)
		if resp.Status != http.StatusAccepted {
			t.Fatalf("POST = %d %s", resp.Status, resp.Body)
		}
		return st.Request.ID
	}

	// The agent couldn't create the job: the reason reaches the page, and a
	// new request is possible.
	agentPoll(t, app, idle)
	id := click()
	agentPoll(t, app, idle)
	remoteCall(t, app, http.MethodPost, "scan-agent/report", "", testScannerToken,
		map[string]string{"id": id, "state": "failed", "message": "jobs.batch is forbidden"})
	st := scanStatus(t, app)
	if st.Running || st.Request == nil || st.Request.State != "failed" || st.Request.Message != "jobs.batch is forbidden" {
		t.Errorf("after a failed start: %+v", st)
	}
	if resp := remoteCall(t, app, http.MethodPost, "scan-agent/report", "", testScannerToken,
		map[string]string{"id": "nope", "state": "running"}); resp.Status != http.StatusBadRequest {
		t.Errorf("report on an unknown request = %d, want 400", resp.Status)
	}

	// A run the agent stops reporting (the job was deleted) is given up on.
	id = click()
	remoteCall(t, app, http.MethodPost, "scan-agent/report", "", testScannerToken,
		map[string]string{"id": id, "state": "running", "job": "vulnobs-scan-manual-gone"})
	agentPoll(t, app, idle)
	if st := scanStatus(t, app); !st.Running {
		t.Errorf("a just-started run should still count as running: %+v", st)
	}
	now = now.Add(runLostAfter + time.Second)
	agentPoll(t, app, idle)
	if st := scanStatus(t, app); st.Running {
		t.Errorf("a lost run should not block the button for ever: %+v", st)
	}

	// The agent can't read the CronJob: say so instead of offering the button.
	agentPoll(t, app, AgentReport{CronJob: "vulnobs-scan", Namespace: "vulnobs", Error: "cronjobs.batch is forbidden"})
	if st := scanStatus(t, app); st.Available || !strings.Contains(st.Reason, "forbidden") {
		t.Errorf("unreadable CronJob: %+v", st)
	}

	// An agent that went away: the button goes with it.
	agentPoll(t, app, idle)
	now = now.Add(agentMinStale + time.Second)
	if st := scanStatus(t, app); st.Available || !strings.Contains(st.Reason, "last connected") {
		t.Errorf("stale agent: %+v", st)
	}
}

// The scan agent's endpoints take the scanner token and nothing else.
func TestScanAgentAuth(t *testing.T) {
	app := remoteApp(t, `{"clusterMode": "remote"}`, map[string]string{"scannerToken": testScannerToken})
	for _, path := range []string{"scan-agent/poll", "scan-agent/report"} {
		// A logged-in Grafana admin without the token is still refused.
		for _, token := range []string{"", "wrong", testScannerToken + "x"} {
			if resp := remoteCall(t, app, http.MethodPost, path, "Admin", token, AgentReport{}); resp.Status != http.StatusUnauthorized {
				t.Errorf("%s with token %q = %d, want 401", path, token, resp.Status)
			}
		}
		if resp := remoteCall(t, app, http.MethodGet, path, "", testScannerToken, nil); resp.Status != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", path, resp.Status)
		}
	}
	if app.scans.report != nil {
		t.Error("a refused poll changed the agent state")
	}

	// No token configured, or a weak one: nobody gets in, and the page says why.
	for _, secure := range []map[string]string{nil, {"scannerToken": "short"}} {
		app := remoteApp(t, `{"clusterMode": "remote"}`, secure)
		if resp := remoteCall(t, app, http.MethodPost, "scan-agent/poll", "", secure["scannerToken"], AgentReport{}); resp.Status != http.StatusServiceUnavailable {
			t.Errorf("poll with settings %v = %d, want 503", secure, resp.Status)
		}
		if st := scanStatus(t, app); st.Available || !strings.Contains(st.Reason, "scanner token") {
			t.Errorf("status with settings %v: %+v", secure, st)
		}
	}

	// The default mode has no agent endpoints at all.
	inst, _ := NewApp(context.Background(), backend.AppInstanceSettings{DecryptedSecureJSONData: map[string]string{"scannerToken": testScannerToken}})
	if resp := remoteCall(t, inst.(*App), http.MethodPost, "scan-agent/poll", "", testScannerToken, AgentReport{}); resp.Status != http.StatusNotFound {
		t.Errorf("poll in the default mode = %d, want 404", resp.Status)
	}
}

// Saving the app's settings builds a new instance; a waiting request must
// still be there for the agent.
func TestScanQueueSurvivesNewInstance(t *testing.T) {
	settings := backend.AppInstanceSettings{
		JSONData:                []byte(`{"clusterMode": "remote"}`),
		DecryptedSecureJSONData: map[string]string{"scannerToken": "a-token-only-this-test-uses-0123456789"},
	}
	first, _ := NewApp(context.Background(), settings)
	second, _ := NewApp(context.Background(), settings)
	if first.(*App).scans != second.(*App).scans {
		t.Error("two instances with the same token should share one queue")
	}
	settings.DecryptedSecureJSONData = map[string]string{"scannerToken": "another-token-0123456789-0123456789"}
	third, _ := NewApp(context.Background(), settings)
	if third.(*App).scans == first.(*App).scans {
		t.Error("a different token should get its own queue")
	}
}
