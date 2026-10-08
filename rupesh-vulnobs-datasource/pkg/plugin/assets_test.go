package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const storageFixture = `{"assets":[
 {"asset":"python:3.12","source":"cluster","namespaces":["batch","shop"],"format":"trivy",
  "lastScanned":"2026-09-15T01:00:00Z","counts":{"HIGH":2,"MODERATE":5},"kev":0,"total":7,
  "rows":[{"package":"setuptools","cve":"CVE-2024-6345","severity":"HIGH"}]},
 {"asset":"ghcr.io/org/api:1.0","source":"cluster","namespaces":["shop"],"format":"trivy",
  "lastScanned":"2026-09-15T01:00:00Z","counts":{"CRITICAL":2,"HIGH":1},"kev":2,"total":3}
]}`

func storageTestServer(status int, response string, token string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/assets" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
}

func TestAssetsFrameSingleMetric(t *testing.T) {
	token := "01234567890123456789012345678901"
	server := storageTestServer(http.StatusOK, storageFixture, token)
	defer server.Close()
	assets, err := loadIngestedAssets(t.Context(), server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	frame, err := assetsFrame(assets, "")
	if err != nil {
		t.Fatal(err)
	}

	numeric := 0
	for _, f := range frame.Fields {
		if f.Type().Numeric() {
			numeric++
		}
		if f.Type().Time() {
			t.Errorf("single-metric frame has a time field %q", f.Name)
		}
	}
	if numeric != 1 {
		t.Errorf("got %d numeric fields, want 1", numeric)
	}
	if frame.Rows() != 2 {
		t.Fatalf("rows = %d, want 2", frame.Rows())
	}
	if got := frame.Fields[0].At(0); got != "ghcr.io/org/api:1.0" {
		t.Errorf("first asset = %v", got)
	}
	if frame.Fields[3].Name != "kev" || frame.Fields[3].At(0) != int64(2) || frame.Fields[3].At(1) != int64(0) {
		t.Errorf("kev column = %s %v %v", frame.Fields[3].Name, frame.Fields[3].At(0), frame.Fields[3].At(1))
	}
	if got := frame.Fields[2].At(1); got != "batch,shop" {
		t.Errorf("namespaces = %v", got)
	}
}

func TestAssetsFrameMetrics(t *testing.T) {
	token := "01234567890123456789012345678901"
	server := storageTestServer(http.StatusOK, storageFixture, token)
	defer server.Close()
	assets, err := loadIngestedAssets(t.Context(), server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	frame, err := assetsFrame(assets, "critical")
	if err != nil {
		t.Fatal(err)
	}
	if f := frame.Fields[3]; f.Name != "critical" || f.At(0) != int64(2) || f.At(1) != int64(0) {
		t.Errorf("critical column = %s %v %v", f.Name, f.At(0), f.At(1))
	}

	all, err := assetsFrame(assets, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Fields) != 3+len(allMetrics)+1 {
		t.Errorf("'all' frame has %d fields", len(all.Fields))
	}
	if _, err := assetsFrame(assets, "bogus"); err == nil {
		t.Error("unknown metric should be an error")
	}
}

func TestLoadIngestedAssets(t *testing.T) {
	if _, err := loadIngestedAssets(context.Background(), "", "", nil); err != errAssetsNotConfigured {
		t.Errorf("empty settings: err = %v, want errAssetsNotConfigured", err)
	}

	frame, err := assetsFrame([]ingestedAsset{}, "kev")
	if err != nil || frame.Rows() != 0 || len(frame.Fields) != 4 {
		t.Errorf("empty frame: rows=%d fields=%d err=%v", frame.Rows(), len(frame.Fields), err)
	}

	token := "01234567890123456789012345678901"
	server := storageTestServer(http.StatusOK, "{broken", token)
	defer server.Close()
	if _, err := loadIngestedAssets(context.Background(), server.URL, token, server.Client()); err == nil {
		t.Error("malformed response should be an error")
	}

	server2 := storageTestServer(http.StatusServiceUnavailable, "unavailable", token)
	defer server2.Close()
	if _, err := loadIngestedAssets(context.Background(), server2.URL, token, server2.Client()); err == nil {
		t.Error("storage API failure should be an error")
	}
}
