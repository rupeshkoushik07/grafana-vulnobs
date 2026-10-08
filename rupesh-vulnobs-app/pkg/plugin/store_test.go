package plugin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
)

func TestAssetStoreRemoteOperations(t *testing.T) {
	assets := map[string]*AssetPosture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/assets":
			var p AssetPosture
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Errorf("decode put: %v", err)
			}
			assets[p.Asset] = &p
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/assets":
			list := make([]*AssetPosture, 0, len(assets))
			for _, p := range assets {
				list = append(list, p)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"assets": list})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/assets/get":
			var body struct {
				Asset string `json:"asset"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if p := assets[body.Asset]; p != nil {
				_ = json.NewEncoder(w).Encode(p)
				return
			}
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/assets/prune":
			var body struct {
				Source string   `json:"source"`
				Keep   []string `json:"keep"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			keep := make(map[string]bool, len(body.Keep))
			for _, name := range body.Keep {
				keep[name] = true
			}
			removed := []string{}
			for name, p := range assets {
				if p.Source == body.Source && !keep[name] {
					removed = append(removed, name)
					delete(assets, name)
				}
			}
			sort.Strings(removed)
			_ = json.NewEncoder(w).Encode(map[string]any{"removed": removed})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	s, err := newAssetStore(server.URL, "01234567890123456789012345678901", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	rows := []ScanRow{
		{Package: "log4j-core", CVE: "CVE-2021-44228", Severity: "CRITICAL", KEV: true},
		{Package: "lodash", CVE: "CVE-2021-23337", Severity: "HIGH"},
	}
	if _, err := s.put(t.Context(), "ghcr.io/org/api:1.0", "cluster", "trivy", []string{"shop"}, rows); err != nil {
		t.Fatal(err)
	}
	if _, err := s.put(t.Context(), "payments-api", "api", "cyclonedx", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.check(t.Context()); err != nil {
		t.Fatal(err)
	}

	got, found, err := s.get(t.Context(), "ghcr.io/org/api:1.0")
	if err != nil || !found {
		t.Fatalf("get asset: found=%v err=%v", found, err)
	}
	if got.Source != "cluster" || got.KEV != 1 || got.Total != 2 || got.Counts["CRITICAL"] != 1 ||
		!reflect.DeepEqual(got.Namespaces, []string{"shop"}) || len(got.Rows) != 2 {
		t.Errorf("posture = %+v", got)
	}

	list, err := s.list(t.Context())
	if err != nil || len(list) != 2 || list[0].Asset != "ghcr.io/org/api:1.0" {
		t.Fatalf("list = %v, err=%v", names(list), err)
	}
	if list[0].Rows != nil {
		t.Error("list should not include rows")
	}

	removed, err := s.prune(t.Context(), "cluster", []string{"not-present"})
	if err != nil || !reflect.DeepEqual(removed, []string{"ghcr.io/org/api:1.0"}) {
		t.Errorf("pruned = %v, err=%v", removed, err)
	}
}

func TestNewAssetStoreRequiresURLAndToken(t *testing.T) {
	for _, tc := range []struct{ url, token string }{
		{"", "01234567890123456789012345678901"},
		{"file:///tmp/store", "01234567890123456789012345678901"},
		{"http://storage.example", "short"},
	} {
		if _, err := newAssetStore(tc.url, tc.token, nil); err == nil {
			t.Errorf("newAssetStore(%q, %q) unexpectedly succeeded", tc.url, tc.token)
		}
	}
}

func names(list []*AssetPosture) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Asset)
	}
	return out
}
