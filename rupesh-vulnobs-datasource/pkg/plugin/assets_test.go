package plugin

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A store file as written by the Vulnobs app (version 1), including fields this
// data source ignores.
const storeFixture = `{"version":1,"assets":[
 {"asset":"python:3.12","source":"cluster","namespaces":["batch","shop"],"format":"trivy",
  "lastScanned":"2026-09-15T01:00:00Z","counts":{"HIGH":2,"MODERATE":5},"kev":0,"total":7,
  "rows":[{"package":"setuptools","cve":"CVE-2024-6345","severity":"HIGH"}]},
 {"asset":"ghcr.io/org/api:1.0","source":"cluster","namespaces":["shop"],"format":"trivy",
  "lastScanned":"2026-09-15T01:00:00Z","counts":{"CRITICAL":2,"HIGH":1},"kev":2,"total":3}
]}`

func writeStore(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, assetsFileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAssetsFrameSingleMetric(t *testing.T) {
	assets, err := loadIngestedAssets(writeStore(t, storeFixture))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := assetsFrame(assets, "")
	if err != nil {
		t.Fatal(err)
	}

	// Alert rules need exactly one numeric column; the rest become labels.
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
	// Sorted by asset name; the default metric is the KEV count.
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
	assets, _ := loadIngestedAssets(writeStore(t, storeFixture))

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
	if _, err := loadIngestedAssets(""); !errors.Is(err, errAssetsNotConfigured) {
		t.Errorf("empty dir: err = %v, want errAssetsNotConfigured", err)
	}

	// Nothing ingested yet: no file, no error, and still a valid empty frame.
	assets, err := loadIngestedAssets(t.TempDir())
	if err != nil || len(assets) != 0 {
		t.Fatalf("missing file: assets=%v err=%v", assets, err)
	}
	frame, err := assetsFrame(assets, "kev")
	if err != nil || frame.Rows() != 0 || len(frame.Fields) != 4 {
		t.Errorf("empty frame: rows=%d fields=%d err=%v", frame.Rows(), len(frame.Fields), err)
	}

	if _, err := loadIngestedAssets(writeStore(t, "{broken")); err == nil {
		t.Error("corrupt file should be an error")
	}
}
