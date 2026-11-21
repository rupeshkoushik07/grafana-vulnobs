// Package discover finds the container images running in a Kubernetes cluster.
// It talks to the API server's REST interface directly, so the scan job needs
// neither kubectl nor client libraries, only a service account allowed to list
// pods.
package discover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Source is the ingest source recorded for images found in the cluster. The
// scan job prunes assets with this source that are no longer running.
const Source = "cluster"

// Image is one image reference and the namespaces where pods run it.
type Image struct {
	// Ref is the reference from the pod spec, e.g. "python:3.12". It names the
	// asset in Vulnobs.
	Ref string
	// ScanRef is what the scan job hands to the scanner. When the kubelet
	// reported the digest of the image a container is actually running, it is
	// that digest ("docker.io/library/python@sha256:..."), so the result
	// describes what is deployed even if the tag has moved since. Otherwise it
	// equals Ref.
	ScanRef    string
	Namespaces []string

	asset string // set by Images when Ref alone is ambiguous
}

// Asset is the name the image is stored under. It is Ref, unless pods run the
// same reference at different digests (a moved tag, pulled at different
// times): then each digest is its own asset, "python:3.12@sha256:...".
func (i Image) Asset() string {
	if i.asset != "" {
		return i.asset
	}
	return i.Ref
}

// Client lists pods through the Kubernetes API.
type Client struct {
	APIServer string
	Token     string
	HTTP      *http.Client
}

// InCluster builds a Client from the service account files mounted into a pod
// and the KUBERNETES_SERVICE_HOST/PORT environment variables.
func InCluster(tokenPath, caPath string) (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set (not running in a cluster?)")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("no certificates found in %s", caPath)
	}
	return &Client{
		APIServer: "https://" + net.JoinHostPort(host, port),
		Token:     strings.TrimSpace(string(token)),
		HTTP: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

type podList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Containers     []container `json:"containers"`
			InitContainers []container `json:"initContainers"`
		} `json:"spec"`
		Status struct {
			Phase                 string            `json:"phase"`
			ContainerStatuses     []containerStatus `json:"containerStatuses"`
			InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

type container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type containerStatus struct {
	Name    string `json:"name"`
	ImageID string `json:"imageID"`
}

// pinnedRef turns a container status imageID into a pullable digest reference,
// or "" when the runtime reported none. containerd reports
// "docker.io/library/python@sha256:..."; Docker prefixes it with
// "docker-pullable://". An image loaded straight into a node (kind load, a
// local build) has no registry digest: its imageID is a bare "sha256:..." or a
// tag, which no scanner can pull by.
func pinnedRef(imageID string) string {
	id := strings.TrimPrefix(strings.TrimSpace(imageID), "docker-pullable://")
	repo, digest, ok := strings.Cut(id, "@")
	if !ok || repo == "" || strings.Contains(repo, "://") {
		return ""
	}
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo != "sha256" || len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
		return ""
	}
	return id
}

// Images returns every image used by pods that haven't finished, outside the
// excluded namespaces, sorted by asset name. Each is pinned to the digest its
// containers run where the kubelet reports one.
func (c *Client) Images(ctx context.Context, excludeNamespaces []string) ([]Image, error) {
	excluded := map[string]bool{}
	for _, ns := range excludeNamespaces {
		if ns = strings.TrimSpace(ns); ns != "" {
			excluded[ns] = true
		}
	}

	type key struct{ ref, scanRef string }
	namespaces := map[key]map[string]bool{}
	next := ""
	for {
		page, err := c.listPods(ctx, next)
		if err != nil {
			return nil, err
		}
		for _, pod := range page.Items {
			ns := pod.Metadata.Namespace
			if excluded[ns] || pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
				continue
			}
			running := map[string]string{} // container name -> digest reference
			for _, st := range append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...) {
				running[st.Name] = pinnedRef(st.ImageID)
			}
			for _, ct := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
				if ct.Image == "" {
					continue
				}
				k := key{ref: ct.Image, scanRef: running[ct.Name]}
				if k.scanRef == "" {
					k.scanRef = ct.Image
				}
				if namespaces[k] == nil {
					namespaces[k] = map[string]bool{}
				}
				namespaces[k][ns] = true
			}
		}
		if next = page.Metadata.Continue; next == "" {
			break
		}
	}

	// A container that hasn't started yet has no digest, so its image shows up
	// under the bare reference next to the pinned one from a running replica.
	// That is the same image: fold it into the pinned entry.
	pinned := map[string][]key{}
	for k := range namespaces {
		if k.scanRef != k.ref {
			pinned[k.ref] = append(pinned[k.ref], k)
		}
	}
	for ref, keys := range pinned {
		unpinned := key{ref: ref, scanRef: ref}
		if set, ok := namespaces[unpinned]; ok && len(keys) == 1 {
			for ns := range set {
				namespaces[keys[0]][ns] = true
			}
			delete(namespaces, unpinned)
		}
	}
	variants := map[string]int{}
	for k := range namespaces {
		variants[k.ref]++
	}

	images := make([]Image, 0, len(namespaces))
	for k, set := range namespaces {
		img := Image{Ref: k.ref, ScanRef: k.scanRef}
		if variants[k.ref] > 1 && k.scanRef != k.ref {
			_, digest, _ := strings.Cut(k.scanRef, "@")
			img.asset = k.ref + "@" + digest
		}
		for ns := range set {
			img.Namespaces = append(img.Namespaces, ns)
		}
		sort.Strings(img.Namespaces)
		images = append(images, img)
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Asset() < images[j].Asset() })
	return images, nil
}

func (c *Client) listPods(ctx context.Context, continueToken string) (*podList, error) {
	u := c.APIServer + "/api/v1/pods?limit=500"
	if continueToken != "" {
		u += "&continue=" + url.QueryEscape(continueToken)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("list pods: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var page podList
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("decode pod list: %w", err)
	}
	return &page, nil
}

// IngestQuery is the query string the scan job appends to the app's /ingest
// endpoint for an image.
func IngestQuery(img Image) string {
	return url.Values{
		"asset":      {img.Asset()},
		"source":     {Source},
		"namespaces": {strings.Join(img.Namespaces, ",")},
	}.Encode()
}

// WriteTargets writes one "<reference to scan>\t<ingest query>" line per
// image, for the scan job's shell steps to read.
func WriteTargets(w io.Writer, images []Image) error {
	for _, img := range images {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", img.ScanRef, IngestQuery(img)); err != nil {
			return err
		}
	}
	return nil
}

// PruneRequest is the body for the app's /prune endpoint: remove cluster
// assets that are no longer running. Every discovered image is kept, including
// ones whose scan fails, so a transient failure doesn't delete earlier results.
func PruneRequest(images []Image) ([]byte, error) {
	keep := make([]string, 0, len(images))
	for _, img := range images {
		keep = append(keep, img.Asset())
	}
	return json.Marshal(map[string]any{"source": Source, "keep": keep})
}
