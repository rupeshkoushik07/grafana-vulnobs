package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// A scan with many packages must ask OSV which are affected in one batch, then
// fetch details only for those.
func TestScanPackagesUsesBatch(t *testing.T) {
	var mu sync.Mutex
	batches, queried := 0, map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/querybatch":
			batches++
			var body struct {
				Queries []struct {
					Package struct{ Name string } `json:"package"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			results := make([]map[string]any, len(body.Queries))
			for i, q := range body.Queries {
				results[i] = map[string]any{}
				if q.Package.Name == "pkg-7" || q.Package.Name == "pkg-1200" {
					results[i]["vulns"] = []map[string]string{{"id": "GHSA-test"}}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/query":
			var body struct {
				Package struct{ Name string } `json:"package"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			queried[body.Package.Name] = true
			_, _ = fmt.Fprintf(w, `{"vulns":[{"id":"GHSA-%s","aliases":["CVE-2026-0001"],"summary":"test"}]}`, body.Package.Name)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	app := &App{baseURL: srv.URL, httpClient: srv.Client()}
	var pkgs []pkgRef
	for i := 0; i < 1500; i++ {
		pkgs = append(pkgs, pkgRef{Ecosystem: "npm", Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"})
	}
	rows := app.scanPackages(context.Background(), pkgs)

	if batches != 2 {
		t.Errorf("batch requests = %d, want 2 (1000 + 500)", batches)
	}
	if len(queried) != 2 || !queried["pkg-7"] || !queried["pkg-1200"] {
		t.Errorf("detail queries = %v, want only the two affected packages", queried)
	}
	if len(rows) != 2 {
		t.Errorf("rows = %d, want 2", len(rows))
	}
}

// If the batch endpoint fails, nothing is dropped: every package is queried.
func TestScanPackagesBatchFailureFallsBack(t *testing.T) {
	var mu sync.Mutex
	queries := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		mu.Lock()
		queries++
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	app := &App{baseURL: srv.URL, httpClient: srv.Client()}
	var pkgs []pkgRef
	for i := 0; i < 20; i++ {
		pkgs = append(pkgs, pkgRef{Ecosystem: "npm", Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"})
	}
	app.scanPackages(context.Background(), pkgs)
	if queries != 20 {
		t.Errorf("detail queries = %d, want all 20", queries)
	}
}
