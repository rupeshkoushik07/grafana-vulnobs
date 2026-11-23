package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

func sample(labels ...string) promSample {
	m := map[string]string{}
	for i := 0; i+1 < len(labels); i += 2 {
		m[labels[i]] = labels[i+1]
	}
	return promSample{Metric: m}
}

// clusterMetrics is the cluster of podPages (workloads_test.go) as
// kube-state-metrics describes it.
func clusterMetrics() promResults {
	return promResults{
		InitContainers: []promSample{
			sample("namespace", "shop", "pod", "api-7d9f8c-aaaaa", "container", "migrate",
				"image_spec", "flyway/flyway:10", "image", "docker.io/flyway/flyway:10", "image_id", ""),
		},
		Containers: []promSample{
			sample("namespace", "shop", "pod", "api-7d9f8c-aaaaa", "container", "api",
				"image_spec", "python:3.12", "image", "docker.io/library/python:3.12",
				"image_id", "docker.io/library/python@sha256:"+digestA),
			// Not started yet: no image id.
			sample("namespace", "shop", "pod", "api-7d9f8c-bbbbb", "container", "api",
				"image_spec", "python:3.12", "image", "python:3.12", "image_id", ""),
			sample("namespace", "kube-system", "pod", "coredns-1", "container", "coredns", "image_spec", "coredns:1.11"),
			sample("namespace", "shop", "pod", "db-0", "container", "db",
				"image_spec", "postgres:17", "image_id", "sha256:"+digestB),
			sample("namespace", "batch", "pod", "report-29-xyz", "container", "report", "image_spec", "busybox:1.36"),
			sample("namespace", "batch", "pod", "debug", "container", "sh", "image_spec", "busybox:1.36"),
		},
		Owners: []promSample{
			sample("namespace", "shop", "pod", "api-7d9f8c-aaaaa", "owner_kind", "ReplicaSet", "owner_name", "api-7d9f8c", "owner_is_controller", "true"),
			sample("namespace", "shop", "pod", "api-7d9f8c-bbbbb", "owner_kind", "ReplicaSet", "owner_name", "api-7d9f8c", "owner_is_controller", "true"),
			sample("namespace", "kube-system", "pod", "coredns-1", "owner_kind", "ReplicaSet", "owner_name", "coredns-5d78", "owner_is_controller", "true"),
			sample("namespace", "shop", "pod", "db-0", "owner_kind", "StatefulSet", "owner_name", "db", "owner_is_controller", "true"),
			sample("namespace", "batch", "pod", "report-29-xyz", "owner_kind", "Job", "owner_name", "report-29", "owner_is_controller", "true"),
			// kube-state-metrics' way of saying "no owner".
			sample("namespace", "batch", "pod", "debug", "owner_kind", "<none>", "owner_name", "<none>", "owner_is_controller", "<none>"),
		},
		ReplicaSets: []promSample{
			sample("namespace", "shop", "replicaset", "api-7d9f8c", "owner_kind", "Deployment", "owner_name", "api"),
			// Same ReplicaSet name in another namespace must not be mixed up.
			sample("namespace", "other", "replicaset", "coredns-5d78", "owner_kind", "Deployment", "owner_name", "wrong"),
		},
		Ready: []promSample{
			sample("namespace", "shop", "pod", "api-7d9f8c-aaaaa"),
			sample("namespace", "shop", "pod", "db-0"),
			sample("namespace", "batch", "pod", "debug"),
		},
		Finished: []promSample{sample("namespace", "batch", "pod", "report-29-xyz")},
		Present:  []promSample{sample()},
	}
}

// The metrics path must give the rows TestWorkloads expects of the Kubernetes
// path for the same cluster.
func TestWorkloadsFromMetrics(t *testing.T) {
	got := workloadsFromMetrics(clusterMetrics(), []string{"kube-system", " "})
	want := []Workload{
		{Namespace: "batch", Kind: "Pod", Name: "debug", Pods: 1, Ready: 1, Images: []WorkloadImage{{Image: "busybox:1.36"}}},
		{Namespace: "shop", Kind: "Deployment", Name: "api", Pods: 2, Ready: 1, Images: []WorkloadImage{
			{Image: "flyway/flyway:10"},
			{Image: "python:3.12", Digest: "sha256:" + digestA},
		}},
		{Namespace: "shop", Kind: "StatefulSet", Name: "db", Pods: 1, Ready: 1, Images: []WorkloadImage{{Image: "postgres:17"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("workloads:\n got %+v\nwant %+v", got, want)
	}
}

func TestWorkloadsFromMetricsOwners(t *testing.T) {
	res := promResults{
		Containers: []promSample{
			// An old kube-state-metrics has no image_spec: the runtime's name is all there is.
			sample("namespace", "web", "pod", "bare-rs-x", "container", "c", "image", "docker.io/library/nginx:1.27"),
			sample("namespace", "kube-system", "pod", "coredns-1", "container", "c", "image_spec", "coredns:1.11"),
			sample("namespace", "web", "pod", "agent-abc", "container", "c", "image_spec", "agent:1"),
			sample("namespace", "web", "pod", "agent-abc", "container", "sidecar", "image_spec", "proxy:2"),
		},
		Owners: []promSample{
			// A ReplicaSet nobody owns stays a ReplicaSet.
			sample("namespace", "web", "pod", "bare-rs-x", "owner_kind", "ReplicaSet", "owner_name", "bare-rs", "owner_is_controller", "true"),
			sample("namespace", "kube-system", "pod", "coredns-1", "owner_kind", "ReplicaSet", "owner_name", "coredns-5d78", "owner_is_controller", "true"),
			// An owner that isn't the controller doesn't name the workload.
			sample("namespace", "web", "pod", "agent-abc", "owner_kind", "Node", "owner_name", "node-1", "owner_is_controller", "false"),
			sample("namespace", "web", "pod", "agent-abc", "owner_kind", "DaemonSet", "owner_name", "agent", "owner_is_controller", "true"),
		},
		ReplicaSets: []promSample{
			sample("namespace", "kube-system", "replicaset", "coredns-5d78", "owner_kind", "Deployment", "owner_name", "coredns"),
			sample("namespace", "web", "replicaset", "bare-rs", "owner_kind", "<none>", "owner_name", "<none>"),
		},
	}
	got := workloadsFromMetrics(res, nil)
	want := []Workload{
		{Namespace: "kube-system", Kind: "Deployment", Name: "coredns", Pods: 1, Images: []WorkloadImage{{Image: "coredns:1.11"}}},
		{Namespace: "web", Kind: "DaemonSet", Name: "agent", Pods: 1, Images: []WorkloadImage{{Image: "agent:1"}, {Image: "proxy:2"}}},
		{Namespace: "web", Kind: "ReplicaSet", Name: "bare-rs", Pods: 1, Images: []WorkloadImage{{Image: "docker.io/library/nginx:1.27"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("workloads:\n got %+v\nwant %+v", got, want)
	}
}

func TestWorkloadQueries(t *testing.T) {
	q, err := workloadQueries([]string{"kube-system", " vulnobs ", `bad"name`}, `cluster="prod"`)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"containers":     `group by (namespace, pod, container, image, image_spec, image_id) (kube_pod_container_info{namespace!~"kube-system|vulnobs",cluster="prod"})`,
		"initContainers": `group by (namespace, pod, container, image, image_spec, image_id) (kube_pod_init_container_info{namespace!~"kube-system|vulnobs",cluster="prod"})`,
		"owners":         `group by (namespace, pod, owner_kind, owner_name, owner_is_controller) (kube_pod_owner{namespace!~"kube-system|vulnobs",cluster="prod"})`,
		"replicaSets":    `group by (namespace, replicaset, owner_kind, owner_name) (kube_replicaset_owner{namespace!~"kube-system|vulnobs",cluster="prod"})`,
		"ready":          `group by (namespace, pod) (kube_pod_status_ready{condition="true",namespace!~"kube-system|vulnobs",cluster="prod"} == 1)`,
		"finished":       `group by (namespace, pod) (kube_pod_status_phase{phase=~"Succeeded|Failed",namespace!~"kube-system|vulnobs",cluster="prod"} == 1)`,
		"present":        `count(kube_pod_container_info{cluster="prod"})`,
	}
	if !reflect.DeepEqual(q, want) {
		t.Errorf("queries:\n got %v\nwant %v", q, want)
	}

	if q, _ := workloadQueries(nil, ""); q["containers"] != `group by (namespace, pod, container, image, image_spec, image_id) (kube_pod_container_info{})` {
		t.Errorf("no matchers: %s", q["containers"])
	}
	for _, bad := range []string{`cluster="prod"} or vector(1) #`, `cluster`, `{cluster="a"}`, `a="b",`} {
		if _, err := workloadQueries(nil, bad); err == nil {
			t.Errorf("selector %q should be refused", bad)
		}
	}
	if _, err := workloadQueries(nil, `cluster=~"a|b", env!="dev"`); err != nil {
		t.Errorf("two matchers: %v", err)
	}
}

func remoteApp(t *testing.T, jsonData string, secure map[string]string) *App {
	t.Helper()
	inst, err := NewApp(context.Background(), backend.AppInstanceSettings{JSONData: []byte(jsonData), DecryptedSecureJSONData: secure})
	if err != nil {
		t.Fatal(err)
	}
	app := inst.(*App)
	app.scans = newScanQueue() // not the process-wide one: tests must not share state
	return app
}

func TestHandlePrometheusWorkloads(t *testing.T) {
	call := func(app *App, method string, body any) WorkloadsResponse {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		var sender mockCallResourceResponseSender
		if err := app.CallResource(context.Background(), &backend.CallResourceRequest{Method: method, Path: "workloads", Body: raw}, &sender); err != nil {
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

	// Remote mode without a data source says what is missing.
	app := remoteApp(t, `{"clusterMode": "remote"}`, nil)
	if app.cluster != nil {
		t.Fatal("remote mode must not build a Kubernetes client")
	}
	if resp := call(app, http.MethodGet, nil); resp.Available || resp.Source != "prometheus" || !strings.Contains(resp.Reason, "data source") {
		t.Errorf("without a data source: %+v", resp)
	}

	app = remoteApp(t, `{"clusterMode": "remote", "prometheusDatasourceUid": "prom-1"}`, nil)
	resp := call(app, http.MethodGet, nil)
	if !resp.Available || resp.Prometheus == nil || resp.Prometheus.DatasourceUID != "prom-1" || len(resp.Prometheus.Queries) != 7 {
		t.Fatalf("queries: %+v", resp)
	}
	// The scan job's default exclusions, as in the Kubernetes path.
	if q := resp.Prometheus.Queries["containers"]; !strings.Contains(q, `namespace!~"kube-system|kube-public|kube-node-lease|local-path-storage"`) {
		t.Errorf("default exclusions missing: %s", q)
	}

	resp = call(app, http.MethodPost, clusterMetrics())
	if !resp.Available || resp.Source != "prometheus" || len(resp.Workloads) != 3 {
		t.Fatalf("workloads: %+v", resp)
	}

	// What the scan agent read off the CronJob replaces the default...
	app.scans.poll(AgentReport{CronJob: "vulnobs-scan", ExcludeNamespaces: []string{"shop"}})
	if resp := call(app, http.MethodPost, clusterMetrics()); len(resp.Workloads) != 2 || resp.Workloads[0].Namespace != "batch" || resp.Workloads[1].Namespace != "kube-system" {
		t.Errorf("with the agent's exclusions: %+v", resp.Workloads)
	}
	// ...and the app's own setting wins over both.
	app.excludeNamespaces = []string{"shop", "batch"}
	if resp := call(app, http.MethodPost, clusterMetrics()); len(resp.Workloads) != 1 || resp.Workloads[0].Namespace != "kube-system" {
		t.Errorf("with excludeNamespaces [shop batch]: %+v", resp.Workloads)
	}

	// No kube-state-metrics series at all is a missing source, not an empty cluster.
	if resp := call(app, http.MethodPost, promResults{}); resp.Available || !strings.Contains(resp.Reason, "kube-state-metrics") {
		t.Errorf("without series: %+v", resp)
	}
	// Series only in excluded namespaces is an empty list.
	if resp := call(app, http.MethodPost, promResults{Present: []promSample{sample()}}); !resp.Available || len(resp.Workloads) != 0 {
		t.Errorf("nothing outside the excluded namespaces: %+v", resp)
	}

	app = remoteApp(t, `{"clusterMode": "remote", "prometheusDatasourceUid": "prom-1", "metricsSelector": "cluster"}`, nil)
	if resp := call(app, http.MethodGet, nil); resp.Available || !strings.Contains(resp.Reason, "selector") {
		t.Errorf("bad selector: %+v", resp)
	}
}
