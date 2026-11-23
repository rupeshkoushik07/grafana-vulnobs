package plugin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

// Remote mode: "Scan now" without the Kubernetes API.
//
// The app can't create the scan job itself, so the button only records a
// request. A small agent in the cluster (vulnobs-agent, see scanner/) asks for
// it every few seconds, starts the scan CronJob there, and tells the app how
// the CronJob is doing with every poll. All traffic goes from the cluster to
// Grafana; nothing in Grafana needs to reach the cluster.
//
//	POST /resources/scan-agent/poll     agent: the CronJob's state; answer: a pending request
//	POST /resources/scan-agent/report   agent: what became of a request
//
// Both need the scanner token (app setting scannerToken, a secret) in the
// X-Vulnobs-Scanner-Token header. Grafana's own login, if it requires one, is
// separate and uses the Authorization header as usual.
//
// Requests are kept in memory. A Grafana restart forgets a request that no
// agent has picked up yet (click again), and several Grafana replicas don't
// share them.

const (
	scannerTokenHeader = "X-Vulnobs-Scanner-Token"
	// minScannerTokenLen keeps guessable tokens out, like the storage token's rule.
	minScannerTokenLen = 32

	// An agent that hasn't polled for this long is treated as gone.
	agentMinStale = 45 * time.Second
	// A started run the agent no longer reports is given up on after this long.
	runLostAfter = 2 * time.Minute
)

// ScanRequest is one click on "Scan now" in remote mode.
type ScanRequest struct {
	ID          string    `json:"id"`
	RequestedAt time.Time `json:"requestedAt"`
	RequestedBy string    `json:"requestedBy,omitempty"`
	// State: "pending" until the agent picks it up, then "running", then
	// "succeeded" or "failed".
	State   string `json:"state"`
	Job     string `json:"job,omitempty"`     // the run that serves it
	Message string `json:"message,omitempty"` // why it failed
	updated time.Time
}

// AgentReport is what the scan agent says about the scan CronJob on each poll.
type AgentReport struct {
	CronJob   string   `json:"cronJob"`
	Namespace string   `json:"namespace"`
	Schedule  string   `json:"schedule"`
	Running   bool     `json:"running"`
	Last      *ScanRun `json:"last,omitempty"`
	// ExcludeNamespaces is the scan job's own list, when the agent could read it.
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
	// PollSeconds is how often the agent polls, so the app knows when to miss it.
	PollSeconds int `json:"pollSeconds,omitempty"`
	// Error is set instead of the rest when the agent can't read the CronJob.
	Error string `json:"error,omitempty"`
}

// scanQueue holds the latest agent report and the latest scan request.
type scanQueue struct {
	mu      sync.Mutex
	now     func() time.Time
	report  *AgentReport
	seen    time.Time
	request *ScanRequest
}

func newScanQueue() *scanQueue { return &scanQueue{now: time.Now} }

// The queue outlives app instances: Grafana builds a new instance whenever the
// app's settings are saved, and a pending request must survive that. One queue
// per scanner token keeps organisations with different tokens apart.
var (
	scanQueuesMu sync.Mutex
	scanQueues   = map[[sha256.Size]byte]*scanQueue{}
)

func sharedScanQueue(token string) *scanQueue {
	scanQueuesMu.Lock()
	defer scanQueuesMu.Unlock()
	key := sha256.Sum256([]byte(token))
	if scanQueues[key] == nil {
		scanQueues[key] = newScanQueue()
	}
	return scanQueues[key]
}

var errNoAgent = errors.New("no scan agent is connected")

func (q *scanQueue) staleAfter() time.Duration {
	if q.report != nil {
		if d := 3 * time.Duration(q.report.PollSeconds) * time.Second; d > agentMinStale {
			return d
		}
	}
	return agentMinStale
}

// status is the answer to GET /cluster-scan. Callers hold no lock.
func (q *scanQueue) status() ClusterScanStatus {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.statusLocked()
}

func (q *scanQueue) statusLocked() ClusterScanStatus {
	st := ClusterScanStatus{Mode: "agent"}
	switch {
	case q.report == nil:
		st.Reason = "No scan agent has connected yet. Deploy it in the cluster with the same scanner token (scanAgent in deploy/tanka)"
		return st
	case q.now().Sub(q.seen) > q.staleAfter():
		st.Reason = fmt.Sprintf("The scan agent last connected %s ago. Check that its pod is running and can reach Grafana",
			q.now().Sub(q.seen).Round(time.Second))
		return st
	case q.report.Error != "":
		st.CronJob, st.Namespace = q.report.CronJob, q.report.Namespace
		st.Reason = "The scan agent can't read the scan CronJob: " + q.report.Error
		return st
	}
	st.Available = true
	st.CronJob, st.Namespace, st.Schedule = q.report.CronJob, q.report.Namespace, q.report.Schedule
	st.Running, st.Last = q.report.Running, q.report.Last
	if r := q.request; r != nil {
		switch r.State {
		case "pending", "running":
			// The agent's report can lag behind by a poll: until it shows the
			// run that serves the request, show that run as just started.
			st.Running = true
			copied := *r
			st.Request = &copied
			if r.Job != "" && (st.Last == nil || st.Last.Name != r.Job) {
				started := r.updated
				st.Last = &ScanRun{Name: r.Job, Trigger: "manual", State: "running", Started: &started}
			}
		case "failed":
			// A request that never became a run has no job to show it.
			if r.Job == "" {
				copied := *r
				st.Request = &copied
			}
		}
	}
	return st
}

// enqueue records a "Scan now" click. It returns errScanRunning, with the
// status, while a run or a request is already going.
func (q *scanQueue) enqueue(by string) (ClusterScanStatus, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	st := q.statusLocked()
	if !st.Available {
		return st, errNoAgent
	}
	if st.Running {
		return st, errScanRunning
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return st, err
	}
	now := q.now().UTC()
	q.request = &ScanRequest{ID: hex.EncodeToString(id), RequestedAt: now, RequestedBy: by, State: "pending", updated: now}
	return q.statusLocked(), nil
}

// poll stores the agent's report and hands out the pending request, if any.
// The request stays pending until the agent reports on it, so one lost answer
// doesn't lose the request.
func (q *scanQueue) poll(report AgentReport) *ScanRequest {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()
	q.report, q.seen = &report, now

	r := q.request
	if r == nil {
		return nil
	}
	switch r.State {
	case "pending":
		copied := *r
		return &copied
	case "running":
		switch last := report.Last; {
		case last != nil && last.Name == r.Job && last.State != "running":
			r.State, r.updated = last.State, now
		case !report.Running && (last == nil || last.Name != r.Job) && now.Sub(r.updated) > runLostAfter:
			r.State, r.Message, r.updated = "failed", "the scan agent no longer reports this run", now
		}
	}
	return nil
}

// update records what the agent did with a request.
func (q *scanQueue) update(id, state, job, message string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	r := q.request
	if r == nil || r.ID != id {
		return errors.New("no such scan request")
	}
	switch state {
	case "running", "succeeded", "failed":
	default:
		return fmt.Errorf("unknown state %q", state)
	}
	if r.State == "succeeded" || r.State == "failed" {
		return nil // already settled; a late duplicate changes nothing
	}
	r.State, r.Message, r.updated = state, message, q.now().UTC()
	if job != "" {
		r.Job = job
	}
	return nil
}

func (q *scanQueue) excludes() ([]string, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.report == nil || q.report.ExcludeNamespaces == nil {
		return nil, false
	}
	return q.report.ExcludeNamespaces, true
}

// scannerTokenProblem says why the scanner token can't be used, or "".
func (a *App) scannerTokenProblem() string {
	switch {
	case a.scannerToken == "":
		return "No scanner token is set. Set one in the app's configuration and give the same token to the scan agent in the cluster"
	case len(a.scannerToken) < minScannerTokenLen:
		return fmt.Sprintf("The scanner token is too short: use %d characters or more", minScannerTokenLen)
	}
	return ""
}

// handleRemoteClusterScan is /cluster-scan in remote mode: the status comes
// from the scan agent's reports, and POST records a request for it.
func (a *App) handleRemoteClusterScan(w http.ResponseWriter, req *http.Request) {
	if problem := a.scannerTokenProblem(); problem != "" {
		if req.Method == http.MethodPost {
			writeError(w, http.StatusServiceUnavailable, problem)
			return
		}
		writeJSON(w, ClusterScanStatus{Mode: "agent", Reason: problem})
		return
	}
	if req.Method == http.MethodGet {
		writeJSON(w, a.scans.status())
		return
	}
	if !mayStartScan(req.Context()) {
		writeError(w, http.StatusForbidden, "only editors and admins can start a cluster scan")
		return
	}
	by := ""
	if user := backend.UserFromContext(req.Context()); user != nil {
		by = user.Login
	}
	st, err := a.scans.enqueue(by)
	switch {
	case errors.Is(err, errScanRunning):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(st)
	case errors.Is(err, errNoAgent):
		writeError(w, http.StatusServiceUnavailable, st.Reason)
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not record the scan request")
	default:
		backend.Logger.Info("Recorded a cluster scan request", "id", st.Request.ID, "by", by)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(st)
	}
}

// authorizeAgent checks the scanner token on a scan agent call and writes the
// refusal itself.
func (a *App) authorizeAgent(w http.ResponseWriter, req *http.Request) bool {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return false
	}
	if !a.remote {
		writeError(w, http.StatusNotFound, "the app is not in remote mode (clusterMode), so it takes no scan agent")
		return false
	}
	if problem := a.scannerTokenProblem(); problem != "" {
		writeError(w, http.StatusServiceUnavailable, problem)
		return false
	}
	// Hashed first, so the comparison takes the same time whatever was sent.
	got, want := sha256.Sum256([]byte(req.Header.Get(scannerTokenHeader))), sha256.Sum256([]byte(a.scannerToken))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		writeError(w, http.StatusUnauthorized, "missing or wrong scanner token in the "+scannerTokenHeader+" header")
		return false
	}
	return true
}

func (a *App) handleScanAgentPoll(w http.ResponseWriter, req *http.Request) {
	if !a.authorizeAgent(w, req) {
		return
	}
	var report AgentReport
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp := struct {
		Request *ScanRequest `json:"request,omitempty"`
	}{a.scans.poll(report)}
	writeJSON(w, resp)
}

func (a *App) handleScanAgentReport(w http.ResponseWriter, req *http.Request) {
	if !a.authorizeAgent(w, req) {
		return
	}
	var body struct {
		ID      string `json:"id"`
		State   string `json:"state"`
		Job     string `json:"job"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := a.scans.update(body.ID, body.State, body.Job, body.Message); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	backend.Logger.Info("Scan agent reported on a request", "id", body.ID, "state", body.State, "job", body.Job)
	writeJSON(w, map[string]bool{"ok": true})
}
