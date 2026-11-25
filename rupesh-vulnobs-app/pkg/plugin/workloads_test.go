package plugin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

const (
	digestA = "1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "2222222222222222222222222222222222222222222222222222222222222222"
)

func ownedBy(kind, name string) string {
	return `"ownerReferences": [{"kind": "` + kind + `", "name": "` + name + `", "controller": true}]`
}

// A pod list shaped like the API server's, in two pages.
var podPages = map[string]string{
	"": `{"metadata": {"continue": "page-2"}, "items": [
	  {"metadata": {"name": "api-7d9f8c-aaaaa", "namespace": "shop", "labels": {"pod-template-hash": "7d9f8c"}, ` + ownedBy("ReplicaSet", "api-7d9f8c") + `},
	   "spec": {"initContainers": [{"name": "migrate", "image": "flyway/flyway:10"}], "containers": [{"name": "api", "image": "python:3.12"}]},
	   "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
	     "containerStatuses": [{"name": "api", "imageID": "docker.io/library/python@sha256:` + digestA + `"}]}},
	  {"metadata": {"name": "api-7d9f8c-bbbbb", "namespace": "shop", "labels": {"pod-template-hash": "7d9f8c"}, ` + ownedBy("ReplicaSet", "api-7d9f8c") + `},
	   "spec": {"containers": [{"name": "api", "image": "python:3.12"}]},
	   "status": {"phase": "Pending", "conditions": [{"type": "Ready", "status": "False"}],
	     "containerStatuses": [{"name": "api", "imageID": ""}]}},
	  {"metadata": {"name": "coredns-1", "namespace": "kube-system", ` + ownedBy("ReplicaSet", "coredns-5d78") + `},
	   "spec": {"containers": [{"name": "coredns", "image": "coredns:1.11"}]}, "status": {"phase": "Running"}}
	]}`,
	"page-2": `{"metadata": {}, "items": [
	  {"metadata": {"name": "db-0", "namespace": "shop", ` + ownedBy("StatefulSet", "db") + `},
	   "spec": {"containers": [{"name": "db", "image": "postgres:17"}]},
	   "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
	     "containerStatuses": [{"name": "db", "imageID": "sha256:` + digestB + `"}]}},
	  {"metadata": {"name": "report-29-xyz", "namespace": "batch", ` + ownedBy("Job", "report-29") + `},
	   "spec": {"containers": [{"name": "report", "image": "busybox:1.36"}]}, "status": {"phase": "Succeeded"}},
	  {"metadata": {"name": "vulnobs-scan-manual-abc12-xk2p9", "namespace": "vulnobs", ` + ownedBy("Job", "vulnobs-scan-manual-abc12") + `},
	   "spec": {"initContainers": [{"name": "discover", "image": "vulnobs:1"}, {"name": "trivy", "image": "trivy:0.74"}], "containers": [{"name": "push", "image": "curl:8"}]},
	   "status": {"phase": "Pending",
	     "initContainerStatuses": [{"name": "discover", "state": {"terminated": {"exitCode": 0}}}, {"name": "trivy", "state": {"running": {}}}],
	     "containerStatuses": [{"name": "push", "state": {"waiting": {}}}]}},
	  {"metadata": {"name": "vulnobs-scan-29-done", "namespace": "vulnobs", ` + ownedBy("Job", "vulnobs-scan-29") + `},
	   "spec": {"containers": [{"name": "push", "image": "curl:8"}]}, "status": {"phase": "Succeeded"}},
	  {"metadata": {"name": "debug", "namespace": "batch"},
	   "spec": {"containers": [{"name": "sh", "image": "busybox:1.36"}]},
	   "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}}
	]}`,
}

func servePods(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/api/v1/pods" {
		return false
	}
	page, ok := podPages[r.URL.Query().Get("continue")]
	if !ok {
		http.Error(w, "bad continue token", http.StatusBadRequest)
		return true
	}
	_, _ = io.WriteString(w, page)
	return true
}

func TestWorkloads(t *testing.T) {
	kube := &fakeKube{pods: servePods}
	got, scanPods, err := newTestScanner(t, kube).workloads(context.Background(), []string{"kube-system", " ", "vulnobs"})
	if err != nil {
		t.Fatal(err)
	}
	// The scan job's running pod is reported on its own, although its
	// namespace is excluded, with the step that is working; its finished
	// pod is not.
	wantScan := []ScanPod{{Namespace: "vulnobs", Job: "vulnobs-scan-manual-abc12", Pod: "vulnobs-scan-manual-abc12-xk2p9",
		Step: "trivy", Images: []string{"vulnobs:1", "trivy:0.74", "curl:8"}}}
	if !reflect.DeepEqual(scanPods, wantScan) {
		t.Errorf("scan pods:\n got %+v\nwant %+v", scanPods, wantScan)
	}
	want := []Workload{
		// No owner: the pod is its own workload.
		{Namespace: "batch", Kind: "Pod", Name: "debug", Pods: 1, Ready: 1, Images: []WorkloadImage{{Image: "busybox:1.36"}}},
		// Two replicas of one Deployment, named from the ReplicaSet minus the
		// pod-template-hash. The replica that hasn't started adds no second
		// python entry; the init container's image counts.
		{Namespace: "shop", Kind: "Deployment", Name: "api", Pods: 2, Ready: 1, Images: []WorkloadImage{
			{Image: "flyway/flyway:10"},
			{Image: "python:3.12", Digest: "sha256:" + digestA},
		}},
		// A local image id is not a registry digest.
		{Namespace: "shop", Kind: "StatefulSet", Name: "db", Pods: 1, Ready: 1, Images: []WorkloadImage{{Image: "postgres:17"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("workloads:\n got %+v\nwant %+v", got, want)
	}
}

func TestScanPodStep(t *testing.T) {
	c := &clusterScanner{namespace: "vulnobs", cronJob: "vulnobs-scan"}
	pod := func(status string) kubePod {
		var p kubePod
		raw := `{"metadata": {"name": "vulnobs-scan-1-x", "namespace": "vulnobs", ` + ownedBy("Job", "vulnobs-scan-1") + `},
		  "spec": {"initContainers": [{"name": "discover", "image": "a"}], "containers": [{"name": "push", "image": "b"}]},
		  "status": {"phase": "Running"` + status + `}}`
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, tc := range map[string]struct{ status, want string }{
		"no container has started": {``, ""},
		"first step":               {`, "initContainerStatuses": [{"name": "discover", "state": {"running": {}}}]`, "discover"},
		"last step": {`, "initContainerStatuses": [{"name": "discover", "state": {"terminated": {}}}],
			"containerStatuses": [{"name": "push", "state": {"running": {}}}]`, "push"},
		"everything ended": {`, "initContainerStatuses": [{"name": "discover", "state": {"terminated": {}}}],
			"containerStatuses": [{"name": "push", "state": {"terminated": {}}}]`, scanStepDone},
	} {
		got, ok := c.scanPod(pod(tc.status))
		if !ok || got.Step != tc.want {
			t.Errorf("%s: step %q (scan pod %v), want %q", name, got.Step, ok, tc.want)
		}
	}
	// Another namespace's job of the same name is not the scan job.
	other := pod(``)
	other.Metadata.Namespace = "shop"
	if _, ok := c.scanPod(other); ok {
		t.Error("a pod in another namespace was taken for the scan job")
	}
}

func TestHandleWorkloads(t *testing.T) {
	inst, err := NewApp(context.Background(), backend.AppInstanceSettings{})
	if err != nil {
		t.Fatal(err)
	}
	app := inst.(*App)
	call := func() WorkloadsResponse {
		var sender mockCallResourceResponseSender
		if err := app.CallResource(context.Background(), &backend.CallResourceRequest{Method: http.MethodGet, Path: "workloads"}, &sender); err != nil {
			t.Fatal(err)
		}
		if sender.response.Status != http.StatusOK {
			t.Fatalf("status %d: %s", sender.response.Status, sender.response.Body)
		}
		var resp WorkloadsResponse
		if err := json.Unmarshal(sender.response.Body, &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// No service account: unavailable, with a reason, and an empty list (not null).
	app.cluster = nil
	if resp := call(); resp.Available || resp.Reason == "" || resp.Workloads == nil {
		t.Errorf("without a service account: %+v", resp)
	}

	// The fake CronJob names no exclusions, so the default applies: kube-system is dropped.
	kube := &fakeKube{pods: servePods}
	app.cluster = newTestScanner(t, kube)
	resp := call()
	if !resp.Available || len(resp.Workloads) != 3 {
		t.Fatalf("workloads = %+v", resp)
	}
	for _, w := range resp.Workloads {
		if w.Namespace == "kube-system" {
			t.Errorf("kube-system should be excluded by default: %+v", w)
		}
	}

	// The app's own setting wins over both.
	app.excludeNamespaces = []string{"shop", "batch"}
	if resp := call(); len(resp.Workloads) != 1 || resp.Workloads[0].Namespace != "kube-system" {
		t.Errorf("with excludeNamespaces [shop batch]: %+v", resp.Workloads)
	}
	app.excludeNamespaces = nil

	// A service account that may start scans but not list pods.
	kube.forbid = true
	if resp := call(); resp.Available || !strings.Contains(resp.Reason, "forbidden") {
		t.Errorf("without permission: %+v", resp)
	}
}

// The page skips the namespaces the scan job skips, read from the CronJob.
func TestScanJobExcludes(t *testing.T) {
	for args, want := range map[string][]string{
		`["-exclude-namespaces", "kube-system,vulnobs", "-targets", "/work/t"]`: {"kube-system", "vulnobs"},
		`["-exclude-namespaces=kube-system, shop"]`:                             {"kube-system", "shop"},
		`["-exclude-namespaces", ""]`:                                           nil,
	} {
		kube := &fakeKube{cronJob: `{"metadata": {"uid": "u"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {
		  "initContainers": [{"name": "discover", "args": ` + args + `}], "containers": [{"name": "push"}]}}}}}}`}
		got, ok := newTestScanner(t, kube).scanJobExcludes(context.Background())
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("args %s: got %v (ok=%v), want %v", args, got, ok, want)
		}
	}

	// No such argument, or no access: the caller falls back to the default.
	if _, ok := newTestScanner(t, &fakeKube{}).scanJobExcludes(context.Background()); ok {
		t.Error("a CronJob without the argument should report ok=false")
	}
	if _, ok := newTestScanner(t, &fakeKube{forbid: true}).scanJobExcludes(context.Background()); ok {
		t.Error("an unreadable CronJob should report ok=false")
	}
}
