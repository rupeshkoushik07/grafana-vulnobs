package plugin

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// The Assets page can show what is running in the cluster before any scan has
// happened: each workload, its pods and its images, so a new deployment shows
// up as "not scanned yet" instead of not at all.
//
// It reads pods, and only pods: the workload a pod belongs to is worked out
// from the pod's owner, so the app needs no access to Deployments,
// StatefulSets or anything else. That is the same single permission the scan
// job has (list pods), granted to the app only when the deployment opts in
// (showWorkloads: true).

// defaultExcludedNamespaces mirrors the scan job's default: system namespaces
// whose images the cluster operator doesn't manage as workloads.
var defaultExcludedNamespaces = []string{"kube-system", "kube-public", "kube-node-lease", "local-path-storage"}

// WorkloadImage is one container image a workload runs.
type WorkloadImage struct {
	// Image is the reference from the pod spec, which is also the asset name.
	Image string `json:"image"`
	// Digest is the "sha256:..." its containers actually run, when the kubelet
	// reports one. If a tag runs at several digests, the scan job stores each
	// as "<image>@<digest>".
	Digest string `json:"digest,omitempty"`
}

// Workload is a group of pods with the same owner.
type Workload struct {
	Namespace string          `json:"namespace"`
	Kind      string          `json:"kind"` // Deployment, StatefulSet, DaemonSet, Job, ReplicaSet or Pod
	Name      string          `json:"name"`
	Pods      int             `json:"pods"`
	Ready     int             `json:"ready"`
	Images    []WorkloadImage `json:"images"`
}

// WorkloadsResponse is the answer to GET /workloads.
type WorkloadsResponse struct {
	Available bool       `json:"available"`
	Reason    string     `json:"reason,omitempty"` // why not, when unavailable
	Workloads []Workload `json:"workloads"`
	// Source is "prometheus" when the list is built from kube-state-metrics
	// instead of the Kubernetes API (clusterMode "remote").
	Source string `json:"source,omitempty"`
	// Prometheus tells the page which queries to run, on a GET in that mode;
	// it posts the answers back to get the workloads.
	Prometheus *PrometheusQueries `json:"prometheus,omitempty"`
}

type kubePodList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []kubePod `json:"items"`
}

type kubePod struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		Containers     []kubeContainer `json:"containers"`
		InitContainers []kubeContainer `json:"initContainers"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		ContainerStatuses     []kubeContainerStatus `json:"containerStatuses"`
		InitContainerStatuses []kubeContainerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type kubeContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type kubeContainerStatus struct {
	Name    string `json:"name"`
	ImageID string `json:"imageID"`
}

// owner names the workload a pod belongs to. A Deployment's pods are owned by
// a ReplicaSet named "<deployment>-<pod-template-hash>", and the pod carries
// that hash as a label, so the Deployment's name can be read off without
// asking for the ReplicaSet.
func (p kubePod) owner() (kind, name string) {
	for _, o := range p.Metadata.OwnerReferences {
		if !o.Controller {
			continue
		}
		if o.Kind == "ReplicaSet" {
			if hash := p.Metadata.Labels["pod-template-hash"]; hash != "" && strings.HasSuffix(o.Name, "-"+hash) {
				return "Deployment", strings.TrimSuffix(o.Name, "-"+hash)
			}
		}
		switch o.Kind {
		case "ReplicaSet", "StatefulSet", "DaemonSet", "Job":
			return o.Kind, o.Name
		}
	}
	return "Pod", p.Metadata.Name
}

func (p kubePod) ready() bool {
	for _, c := range p.Status.Conditions {
		if c.Type == "Ready" {
			return c.Status == "True"
		}
	}
	return false
}

// imageDigest extracts "sha256:..." from a container status imageID such as
// "docker.io/library/python@sha256:..." (optionally "docker-pullable://"
// prefixed). A bare "sha256:..." is a local image id, not a registry digest.
func imageDigest(imageID string) string {
	repo, digest, ok := strings.Cut(strings.TrimPrefix(strings.TrimSpace(imageID), "docker-pullable://"), "@")
	if !ok || repo == "" || strings.Contains(repo, "://") {
		return ""
	}
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo != "sha256" || len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
		return ""
	}
	return digest
}

// workloads lists what runs in the cluster outside the excluded namespaces,
// grouped by owner. Finished pods are left out, as the scan job leaves them.
func (c *clusterScanner) workloads(ctx context.Context, excludeNamespaces []string) ([]Workload, error) {
	excluded := map[string]bool{}
	for _, ns := range excludeNamespaces {
		if ns = strings.TrimSpace(ns); ns != "" {
			excluded[ns] = true
		}
	}

	set := newWorkloadSet()
	next := ""
	for {
		path := "/api/v1/pods?limit=500"
		if next != "" {
			path += "&continue=" + url.QueryEscape(next)
		}
		var page kubePodList
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		for _, pod := range page.Items {
			ns := pod.Metadata.Namespace
			if excluded[ns] || pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
				continue
			}
			digests := map[string]string{}
			for _, st := range append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...) {
				digests[st.Name] = imageDigest(st.ImageID)
			}
			var images []WorkloadImage
			for _, ct := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
				if ct.Image == "" {
					continue
				}
				images = append(images, WorkloadImage{Image: ct.Image, Digest: digests[ct.Name]})
			}
			kind, name := pod.owner()
			set.addPod(ns, kind, name, pod.ready(), images)
		}
		if next = page.Metadata.Continue; next == "" {
			break
		}
	}
	return set.list(), nil
}

// workloadSet groups pods by owner. Both sources of the workloads list (the
// Kubernetes API and kube-state-metrics) feed it one pod at a time, so they
// produce the same rows.
type workloadSet struct {
	byKey     map[workloadKey]*Workload
	seenImage map[workloadKey]map[WorkloadImage]bool
}

type workloadKey struct{ namespace, kind, name string }

func newWorkloadSet() *workloadSet {
	return &workloadSet{byKey: map[workloadKey]*Workload{}, seenImage: map[workloadKey]map[WorkloadImage]bool{}}
}

// addPod counts one pod that hasn't finished towards its owner.
func (s *workloadSet) addPod(namespace, kind, name string, ready bool, images []WorkloadImage) {
	k := workloadKey{namespace, kind, name}
	w := s.byKey[k]
	if w == nil {
		w = &Workload{Namespace: namespace, Kind: kind, Name: name}
		s.byKey[k], s.seenImage[k] = w, map[WorkloadImage]bool{}
	}
	w.Pods++
	if ready {
		w.Ready++
	}
	for _, img := range images {
		s.seenImage[k][img] = true
	}
}

// list returns the workloads sorted by namespace, name and kind.
func (s *workloadSet) list() []Workload {
	out := make([]Workload, 0, len(s.byKey))
	for k, w := range s.byKey {
		// A replica that hasn't started yet reports no digest. If another
		// replica of the same image does, the digest-less entry is a duplicate.
		pinned := map[string]bool{}
		for img := range s.seenImage[k] {
			if img.Digest != "" {
				pinned[img.Image] = true
			}
		}
		for img := range s.seenImage[k] {
			if img.Digest == "" && pinned[img.Image] {
				continue
			}
			w.Images = append(w.Images, img)
		}
		sort.Slice(w.Images, func(i, j int) bool {
			if w.Images[i].Image != w.Images[j].Image {
				return w.Images[i].Image < w.Images[j].Image
			}
			return w.Images[i].Digest < w.Images[j].Digest
		})
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		case a.Name != b.Name:
			return a.Name < b.Name
		default:
			return a.Kind < b.Kind
		}
	})
	return out
}

// scanJobExcludes reads the namespaces the scan job skips from the CronJob
// itself (the discover step's -exclude-namespaces argument), so the page and
// the scan agree on what counts without the list being configured twice. ok is
// false when the CronJob can't be read or doesn't say.
func (c *clusterScanner) scanJobExcludes(ctx context.Context) (namespaces []string, ok bool) {
	var cron struct {
		Spec struct {
			JobTemplate struct {
				Spec struct {
					Template struct {
						Spec struct {
							InitContainers []kubeArgs `json:"initContainers"`
							Containers     []kubeArgs `json:"containers"`
						} `json:"spec"`
					} `json:"template"`
				} `json:"spec"`
			} `json:"jobTemplate"`
		} `json:"spec"`
	}
	if err := c.do(ctx, http.MethodGet, c.cronJobPath(), nil, &cron); err != nil {
		return nil, false
	}
	pod := cron.Spec.JobTemplate.Spec.Template.Spec
	for _, ct := range append(pod.InitContainers, pod.Containers...) {
		for i, arg := range ct.Args {
			if value, found := strings.CutPrefix(arg, "-exclude-namespaces="); found {
				return splitList(value), true
			}
			if (arg == "-exclude-namespaces" || arg == "--exclude-namespaces") && i+1 < len(ct.Args) {
				return splitList(ct.Args[i+1]), true
			}
		}
	}
	return nil, false
}

type kubeArgs struct {
	Args []string `json:"args"`
}

// handleWorkloads lists the workloads running in the cluster, for the Assets
// page to show next to their scan results: GET /resources/workloads
//
// In remote mode the app can't ask Kubernetes, so the list comes from
// kube-state-metrics in two steps (see promworkloads.go).
func (a *App) handleWorkloads(w http.ResponseWriter, req *http.Request) {
	if a.remote {
		a.handlePrometheusWorkloads(w, req)
		return
	}
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	if a.cluster == nil {
		reason := errNoServiceAccount.Error()
		if a.clusterErr != nil {
			reason = a.clusterErr.Error()
		}
		writeJSON(w, WorkloadsResponse{Available: false, Reason: reason, Workloads: []Workload{}})
		return
	}
	// Which namespaces to leave out: the app's own setting if there is one,
	// else whatever the scan job skips, else the scan job's default.
	exclude := a.excludeNamespaces
	if exclude == nil {
		var ok bool
		if exclude, ok = a.cluster.scanJobExcludes(req.Context()); !ok {
			exclude = defaultExcludedNamespaces
		}
	}
	workloads, err := a.cluster.workloads(req.Context(), exclude)
	if err != nil {
		// Not being allowed to list pods is the normal state when the
		// deployment didn't opt in, so it is an answer, not a failure.
		_, reason := a.cluster.explainKubeError(err)
		writeJSON(w, WorkloadsResponse{Available: false, Reason: reason, Workloads: []Workload{}})
		return
	}
	writeJSON(w, WorkloadsResponse{Available: true, Workloads: workloads})
}
