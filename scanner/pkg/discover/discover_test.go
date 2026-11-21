package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Two pages of a real-shaped pod list: the API server returns a continue token
// when there are more pods than the limit.
const page1 = `{
  "kind": "PodList", "apiVersion": "v1",
  "metadata": {"resourceVersion": "1234", "continue": "page-2-token"},
  "items": [
    {"metadata": {"name": "grafana-7d9f", "namespace": "vulnobs"},
     "spec": {"containers": [{"name": "grafana", "image": "ghcr.io/rupeshkoushik07/grafana-vulnobs:main"}]},
     "status": {"phase": "Running"}},
    {"metadata": {"name": "coredns-5d78", "namespace": "kube-system"},
     "spec": {"containers": [{"name": "coredns", "image": "registry.k8s.io/coredns/coredns:v1.11.1"}]},
     "status": {"phase": "Running"}},
    {"metadata": {"name": "api-6c4b", "namespace": "shop"},
     "spec": {"initContainers": [{"name": "migrate", "image": "flyway/flyway:10"}],
              "containers": [{"name": "api", "image": "python:3.12"}]},
     "status": {"phase": "Pending"}}
  ]
}`

const page2 = `{
  "kind": "PodList", "apiVersion": "v1",
  "metadata": {"resourceVersion": "1234"},
  "items": [
    {"metadata": {"name": "worker-8f2a", "namespace": "batch"},
     "spec": {"containers": [{"name": "worker", "image": "python:3.12"}]},
     "status": {"phase": "Running"}},
    {"metadata": {"name": "report-29x1", "namespace": "batch"},
     "spec": {"containers": [{"name": "report", "image": "busybox:1.36"}]},
     "status": {"phase": "Succeeded"}}
  ]
}`

func TestImages(t *testing.T) {
	var gotAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		if r.URL.Path != "/api/v1/pods" {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Query().Get("continue") {
		case "":
			_, _ = w.Write([]byte(page1))
		case "page-2-token":
			_, _ = w.Write([]byte(page2))
		default:
			http.Error(w, "bad continue token", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	c := &Client{APIServer: srv.URL, Token: "test-token", HTTP: srv.Client()}
	got, err := c.Images(context.Background(), []string{"kube-system", " "})
	if err != nil {
		t.Fatal(err)
	}

	want := []Image{
		{Ref: "flyway/flyway:10", ScanRef: "flyway/flyway:10", Namespaces: []string{"shop"}},
		{Ref: "ghcr.io/rupeshkoushik07/grafana-vulnobs:main", ScanRef: "ghcr.io/rupeshkoushik07/grafana-vulnobs:main", Namespaces: []string{"vulnobs"}},
		{Ref: "python:3.12", ScanRef: "python:3.12", Namespaces: []string{"batch", "shop"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("images:\n got %+v\nwant %+v", got, want)
	}
	if len(gotAuth) != 2 || gotAuth[0] != "Bearer test-token" {
		t.Errorf("expected two authenticated requests, got %q", gotAuth)
	}
}

func TestImagesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `pods is forbidden: User "system:serviceaccount:vulnobs:default" cannot list resource "pods"`, http.StatusForbidden)
	}))
	defer srv.Close()

	c := &Client{APIServer: srv.URL, Token: "t", HTTP: srv.Client()}
	_, err := c.Images(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("want a 403 error explaining the missing permission, got %v", err)
	}
}

func TestTargetsAndPrune(t *testing.T) {
	images := []Image{
		{Ref: "ghcr.io/org/app@sha256:abc", ScanRef: "ghcr.io/org/app@sha256:abc", Namespaces: []string{"a", "b"}},
		{Ref: "python:3.12", ScanRef: "docker.io/library/python@sha256:" + digestA, Namespaces: []string{"batch"}},
	}

	var buf bytes.Buffer
	if err := WriteTargets(&buf, images); err != nil {
		t.Fatal(err)
	}
	wantTargets := "ghcr.io/org/app@sha256:abc\tasset=ghcr.io%2Forg%2Fapp%40sha256%3Aabc&namespaces=a%2Cb&source=cluster\n" +
		"docker.io/library/python@sha256:" + digestA + "\tasset=python%3A3.12&namespaces=batch&source=cluster\n"
	if buf.String() != wantTargets {
		t.Errorf("targets:\n got %q\nwant %q", buf.String(), wantTargets)
	}

	body, err := PruneRequest(images)
	if err != nil {
		t.Fatal(err)
	}
	var req struct {
		Source string   `json:"source"`
		Keep   []string `json:"keep"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	if req.Source != Source || !reflect.DeepEqual(req.Keep, []string{"ghcr.io/org/app@sha256:abc", "python:3.12"}) {
		t.Errorf("prune request = %s", body)
	}
}

const (
	digestA = "1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "2222222222222222222222222222222222222222222222222222222222222222"
)

// What the kubelet reports once containers run: the digest of the image each
// one actually started from.
const pinnedPods = `{
  "kind": "PodList", "apiVersion": "v1", "metadata": {},
  "items": [
    {"metadata": {"name": "api-1", "namespace": "shop"},
     "spec": {"containers": [{"name": "api", "image": "python:3.12"}]},
     "status": {"phase": "Running", "containerStatuses": [
       {"name": "api", "imageID": "docker.io/library/python@sha256:` + digestA + `"}]}},
    {"metadata": {"name": "api-2", "namespace": "batch"},
     "spec": {"containers": [{"name": "api", "image": "python:3.12"}]},
     "status": {"phase": "Pending", "containerStatuses": [{"name": "api", "imageID": ""}]}},

    {"metadata": {"name": "web-old", "namespace": "shop"},
     "spec": {"containers": [{"name": "web", "image": "nginx:latest"}]},
     "status": {"phase": "Running", "containerStatuses": [
       {"name": "web", "imageID": "docker-pullable://nginx@sha256:` + digestA + `"}]}},
    {"metadata": {"name": "web-new", "namespace": "edge"},
     "spec": {"containers": [{"name": "web", "image": "nginx:latest"}]},
     "status": {"phase": "Running", "containerStatuses": [
       {"name": "web", "imageID": "docker-pullable://nginx@sha256:` + digestB + `"}]}},

    {"metadata": {"name": "local-1", "namespace": "dev"},
     "spec": {"containers": [{"name": "app", "image": "myapp:dev"}]},
     "status": {"phase": "Running", "containerStatuses": [
       {"name": "app", "imageID": "sha256:` + digestA + `"}]}}
  ]
}`

func TestImagesPinnedToRunningDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pinnedPods))
	}))
	defer srv.Close()

	c := &Client{APIServer: srv.URL, Token: "t", HTTP: srv.Client()}
	images, err := c.Images(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	type row struct {
		asset, scanRef string
		namespaces     []string
	}
	var got []row
	for _, img := range images {
		got = append(got, row{img.Asset(), img.ScanRef, img.Namespaces})
	}
	want := []row{
		// Loaded into the node without a registry digest: scanned by tag.
		{"myapp:dev", "myapp:dev", []string{"dev"}},
		// One tag running at two digests: one asset per digest.
		{"nginx:latest@sha256:" + digestA, "nginx@sha256:" + digestA, []string{"shop"}},
		{"nginx:latest@sha256:" + digestB, "nginx@sha256:" + digestB, []string{"edge"}},
		// A replica that hasn't started yet joins the pinned one.
		{"python:3.12", "docker.io/library/python@sha256:" + digestA, []string{"batch", "shop"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("images:\n got %+v\nwant %+v", got, want)
	}
}

func TestPinnedRef(t *testing.T) {
	for imageID, want := range map[string]string{
		"docker.io/library/python@sha256:" + digestA: "docker.io/library/python@sha256:" + digestA,
		"docker-pullable://nginx@sha256:" + digestA:  "nginx@sha256:" + digestA,
		"sha256:" + digestA:                          "",
		"docker://sha256:" + digestA:                 "",
		"docker.io/library/vulnobs:ci":               "",
		"python@sha256:abc":                          "",
		"python@md5:" + digestA:                      "",
		"":                                           "",
	} {
		if got := pinnedRef(imageID); got != want {
			t.Errorf("pinnedRef(%q) = %q, want %q", imageID, got, want)
		}
	}
}
