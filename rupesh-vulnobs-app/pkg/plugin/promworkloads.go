package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Remote mode: the workloads list without the Kubernetes API.
//
// kube-state-metrics already exports what the list needs, and most clusters
// already ship it to a Prometheus that Grafana can query. So the list is built
// from those series instead of from pods:
//
//	GET  /resources/workloads   which data source to ask, and the queries
//	POST /resources/workloads   the answers, mapped to the same rows as the
//	                            Kubernetes path
//
// The page runs the queries itself, through Grafana's data source API. That
// way they run with the viewer's own permissions on the data source, and the
// app's backend needs neither a Grafana token nor a route to Prometheus.

// maxMetricsBytes caps the query answers the page posts back (64 MiB): a few
// instant vectors with a handful of labels per container.
const maxMetricsBytes = 64 << 20

// PrometheusQueries tells the page what to ask the data source.
type PrometheusQueries struct {
	DatasourceUID string `json:"datasourceUid"`
	// Queries are instant queries, keyed by the field of the POST body their
	// result vector goes in.
	Queries map[string]string `json:"queries"`
}

// promSample is one series of an instant vector. Only labels are read: every
// query is written so that a series being there is the answer.
type promSample struct {
	Metric map[string]string `json:"metric"`
}

// promResults is the POST body: the result vector of each query.
type promResults struct {
	Containers     []promSample `json:"containers"`
	InitContainers []promSample `json:"initContainers"`
	Owners         []promSample `json:"owners"`
	ReplicaSets    []promSample `json:"replicaSets"`
	Ready          []promSample `json:"ready"`
	Finished       []promSample `json:"finished"`
	// Present is non-empty when the data source has kube-state-metrics series
	// at all, in any namespace.
	Present []promSample `json:"present"`
}

var (
	// A Kubernetes namespace name: safe to put in a PromQL regex unescaped.
	namespaceName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	// Label matchers as PromQL writes them, e.g. `cluster="prod",env=~"a|b"`.
	labelMatchers = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*\s*(=~|!~|!=|=)\s*"(?:[^"\\]|\\.)*"(\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*(=~|!~|!=|=)\s*"(?:[^"\\]|\\.)*")*$`)
)

// workloadQueries builds the kube-state-metrics queries. Each is grouped by
// just the labels the mapping reads, which drops scrape labels (instance, job)
// and keeps the answer small. Excluded namespaces are left out by Prometheus
// already; workloadsFromMetrics filters again, so a name that can't go in a
// regex is still excluded.
func workloadQueries(excludeNamespaces []string, selector string) (map[string]string, error) {
	if selector != "" && !labelMatchers.MatchString(selector) {
		return nil, fmt.Errorf("the metrics selector %q is not a list of label matchers such as cluster=\"prod\"", selector)
	}
	var names []string
	for _, ns := range excludeNamespaces {
		if ns = strings.TrimSpace(ns); namespaceName.MatchString(ns) {
			names = append(names, ns)
		}
	}
	var matchers []string
	if len(names) > 0 {
		matchers = append(matchers, `namespace!~"`+strings.Join(names, "|")+`"`)
	}
	if selector != "" {
		matchers = append(matchers, selector)
	}
	sel := func(extra ...string) string {
		return "{" + strings.Join(append(extra, matchers...), ",") + "}"
	}
	const image = "namespace, pod, container, image, image_spec, image_id"
	return map[string]string{
		"containers":     "group by (" + image + ") (kube_pod_container_info" + sel() + ")",
		"initContainers": "group by (" + image + ") (kube_pod_init_container_info" + sel() + ")",
		"owners":         "group by (namespace, pod, owner_kind, owner_name, owner_is_controller) (kube_pod_owner" + sel() + ")",
		"replicaSets":    "group by (namespace, replicaset, owner_kind, owner_name) (kube_replicaset_owner" + sel() + ")",
		"ready":          "group by (namespace, pod) (kube_pod_status_ready" + sel(`condition="true"`) + " == 1)",
		"finished":       "group by (namespace, pod) (kube_pod_status_phase" + sel(`phase=~"Succeeded|Failed"`) + " == 1)",
		// Not limited to the scanned namespaces: it tells "nothing runs
		// there" apart from "the metrics are missing".
		"present": "count(kube_pod_container_info{" + selector + "})",
	}, nil
}

// workloadsFromMetrics maps kube-state-metrics series to the workloads list:
// the same rows the Kubernetes path builds from pods.
//
//   - kube_pod_container_info and kube_pod_init_container_info name each pod's
//     images. image_spec is the reference from the pod spec (the asset name);
//     image is what the runtime resolved it to, used only when an older
//     kube-state-metrics has no image_spec. image_id carries the digest.
//   - kube_pod_owner names the pod's controller, and kube_replicaset_owner the
//     Deployment behind a ReplicaSet.
//   - kube_pod_status_ready lists the pods that are ready, and
//     kube_pod_status_phase the finished ones, which are left out.
func workloadsFromMetrics(res promResults, excludeNamespaces []string) []Workload {
	excluded := map[string]bool{}
	for _, ns := range excludeNamespaces {
		if ns = strings.TrimSpace(ns); ns != "" {
			excluded[ns] = true
		}
	}
	type podKey struct{ namespace, pod string }
	type owner struct{ kind, name string }

	deployments := map[owner]string{} // (namespace, ReplicaSet) -> Deployment
	for _, s := range res.ReplicaSets {
		if m := s.Metric; m["owner_kind"] == "Deployment" && m["owner_name"] != "" {
			deployments[owner{m["namespace"], m["replicaset"]}] = m["owner_name"]
		}
	}
	owners := map[podKey]owner{}
	for _, s := range res.Owners {
		m := s.Metric
		if m["owner_is_controller"] != "true" {
			continue
		}
		switch kind := m["owner_kind"]; kind {
		case "ReplicaSet":
			if d, ok := deployments[owner{m["namespace"], m["owner_name"]}]; ok {
				owners[podKey{m["namespace"], m["pod"]}] = owner{"Deployment", d}
				continue
			}
			fallthrough
		case "StatefulSet", "DaemonSet", "Job":
			owners[podKey{m["namespace"], m["pod"]}] = owner{kind, m["owner_name"]}
		}
	}
	ready, finished := map[podKey]bool{}, map[podKey]bool{}
	for _, s := range res.Ready {
		ready[podKey{s.Metric["namespace"], s.Metric["pod"]}] = true
	}
	for _, s := range res.Finished {
		finished[podKey{s.Metric["namespace"], s.Metric["pod"]}] = true
	}

	// Pods in the order they first appear, so the grouping sees each once.
	images := map[podKey][]WorkloadImage{}
	var pods []podKey
	for _, s := range append(append([]promSample{}, res.InitContainers...), res.Containers...) {
		m := s.Metric
		k := podKey{m["namespace"], m["pod"]}
		if k.namespace == "" || k.pod == "" || excluded[k.namespace] || finished[k] {
			continue
		}
		if _, seen := images[k]; !seen {
			pods = append(pods, k)
			images[k] = nil
		}
		ref := m["image_spec"]
		if ref == "" {
			ref = m["image"]
		}
		if ref == "" {
			continue
		}
		images[k] = append(images[k], WorkloadImage{Image: ref, Digest: imageDigest(m["image_id"])})
	}

	set := newWorkloadSet()
	for _, k := range pods {
		o, ok := owners[k]
		if !ok {
			o = owner{"Pod", k.pod}
		}
		set.addPod(k.namespace, o.kind, o.name, ready[k], images[k])
	}
	return set.list()
}

// remoteExcludes is the namespace list for remote mode: the app's own setting
// if there is one, else what the scan agent read off the CronJob, else the
// scan job's default.
func (a *App) remoteExcludes() []string {
	if a.excludeNamespaces != nil {
		return a.excludeNamespaces
	}
	if a.scans != nil {
		if reported, ok := a.scans.excludes(); ok {
			return reported
		}
	}
	return defaultExcludedNamespaces
}

func (a *App) handlePrometheusWorkloads(w http.ResponseWriter, req *http.Request) {
	unavailable := func(reason string) {
		writeJSON(w, WorkloadsResponse{Source: "prometheus", Reason: reason, Workloads: []Workload{}})
	}
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use GET for the queries or POST with their results")
		return
	}
	if a.prometheusUID == "" {
		unavailable("No Prometheus data source is chosen. Pick the one that holds your kube-state-metrics series in the app's configuration")
		return
	}
	exclude := a.remoteExcludes()

	if req.Method == http.MethodGet {
		queries, err := workloadQueries(exclude, a.metricsSelector)
		if err != nil {
			unavailable(err.Error())
			return
		}
		writeJSON(w, WorkloadsResponse{
			Available:  true,
			Source:     "prometheus",
			Prometheus: &PrometheusQueries{DatasourceUID: a.prometheusUID, Queries: queries},
			Workloads:  []Workload{},
		})
		return
	}

	var res promResults
	if err := json.NewDecoder(io.LimitReader(req.Body, maxMetricsBytes)).Decode(&res); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(res.Present) == 0 && len(res.Containers) == 0 {
		unavailable("The Prometheus data source returned no kube_pod_container_info series. " +
			"It needs to scrape kube-state-metrics for this cluster; check the data source and the metrics selector")
		return
	}
	writeJSON(w, WorkloadsResponse{Available: true, Source: "prometheus", Workloads: workloadsFromMetrics(res, exclude)})
}
