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
	got, err := newTestScanner(t, kube).workloads(context.Background(), []string{"kube-system", " "})
	if err != nil {
		t.Fatal(err)
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
