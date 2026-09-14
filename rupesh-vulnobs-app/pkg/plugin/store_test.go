package plugin

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAssetStorePersists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vulnobs")
	s, err := newAssetStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	rows := []ScanRow{
		{Package: "log4j-core", CVE: "CVE-2021-44228", Severity: "CRITICAL", KEV: true},
		{Package: "lodash", CVE: "CVE-2021-23337", Severity: "HIGH"},
	}
	if _, err := s.put("ghcr.io/org/api:1.0", "cluster", "trivy", []string{"shop"}, rows); err != nil {
		t.Fatal(err)
	}
	if _, err := s.put("payments-api", "api", "cyclonedx", nil, rows[1:]); err != nil {
		t.Fatal(err)
	}

	// A new store on the same directory, as after a Grafana restart.
	reopened, err := newAssetStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.get("ghcr.io/org/api:1.0")
	if !ok {
		t.Fatal("asset not found after reopening the store")
	}
	if got.Source != "cluster" || got.KEV != 1 || got.Total != 2 || got.Counts["CRITICAL"] != 1 ||
		!reflect.DeepEqual(got.Namespaces, []string{"shop"}) || len(got.Rows) != 2 {
		t.Errorf("reloaded posture = %+v", got)
	}

	list := reopened.list()
	if len(list) != 2 || list[0].Asset != "ghcr.io/org/api:1.0" {
		t.Errorf("list order = %v, want the asset with a KEV finding first", names(list))
	}
	if list[0].Rows != nil {
		t.Error("list should not include rows")
	}
	if full, _ := reopened.get("ghcr.io/org/api:1.0"); len(full.Rows) != 2 {
		t.Error("list must not strip rows from the stored posture")
	}
}

func TestAssetStorePrune(t *testing.T) {
	dir := t.TempDir()
	s, _ := newAssetStore(dir)
	for _, a := range []struct{ name, source string }{
		{"python:3.12", "cluster"},
		{"old-image:1.0", "cluster"},
		{"payments-api", "api"},
	} {
		if _, err := s.put(a.name, a.source, "trivy", nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := s.prune("cluster", []string{"python:3.12", "never-scanned:2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{"old-image:1.0"}) {
		t.Errorf("removed = %v, want [old-image:1.0]", removed)
	}

	reopened, _ := newAssetStore(dir)
	if got := names(reopened.list()); !reflect.DeepEqual(got, []string{"payments-api", "python:3.12"}) {
		t.Errorf("assets after prune = %v", got)
	}
}

func TestAssetStoreInMemory(t *testing.T) {
	s, err := newAssetStore("")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.persistent(); ok {
		t.Error("store without a directory should not be persistent")
	}
	if _, err := s.put("a", "api", "trivy", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.get("a"); !ok {
		t.Error("in-memory store lost the asset")
	}
}

func TestAssetStoreCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, storeFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newAssetStore(dir)
	if err == nil {
		t.Fatal("expected an error for a corrupt store file")
	}
	// Still usable, and the next change replaces the corrupt file.
	if _, err := s.put("a", "api", "trivy", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := newAssetStore(dir); err != nil {
		t.Errorf("store file still unreadable after a write: %v", err)
	}
}

func names(list []*AssetPosture) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Asset)
	}
	return out
}
