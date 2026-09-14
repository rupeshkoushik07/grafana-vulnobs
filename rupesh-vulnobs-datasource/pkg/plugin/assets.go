package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// QueryTypeAssets selects the scans ingested by the Vulnobs app instead of an
// OSV lookup.
const QueryTypeAssets = "assets"

// assetsFileName is the Vulnobs app's store file inside its data directory
// (rupesh-vulnobs-app pkg/plugin/store.go).
const assetsFileName = "assets.json"

// ingestedAsset is the part of the app's stored posture this data source uses.
type ingestedAsset struct {
	Asset       string         `json:"asset"`
	Source      string         `json:"source"`
	Namespaces  []string       `json:"namespaces"`
	Counts      map[string]int `json:"counts"`
	KEV         int            `json:"kev"`
	Total       int            `json:"total"`
	LastScanned time.Time      `json:"lastScanned"`
}

// assetMetrics are the per-asset numbers an assets query can return. Alert rules
// need exactly one numeric column, so a query picks one; "all" returns every
// count, for tables.
var assetMetrics = map[string]func(ingestedAsset) int{
	"kev":      func(a ingestedAsset) int { return a.KEV },
	"critical": func(a ingestedAsset) int { return a.Counts["CRITICAL"] },
	"high":     func(a ingestedAsset) int { return a.Counts["HIGH"] },
	"moderate": func(a ingestedAsset) int { return a.Counts["MODERATE"] },
	"low":      func(a ingestedAsset) int { return a.Counts["LOW"] },
	"unknown":  func(a ingestedAsset) int { return a.Counts["UNKNOWN"] },
	"total":    func(a ingestedAsset) int { return a.Total },
}

var allMetrics = []string{"critical", "high", "moderate", "low", "unknown", "kev", "total"}

var errAssetsNotConfigured = errors.New(
	"set 'Assets data directory' in the data source settings to the Vulnobs app's data directory to query ingested assets")

// loadIngestedAssets reads the app's saved scans. A missing file means nothing
// has been ingested yet and returns no assets.
func loadIngestedAssets(dir string) ([]ingestedAsset, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errAssetsNotConfigured
	}
	raw, err := os.ReadFile(filepath.Join(dir, assetsFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ingested assets: %w", err)
	}
	var f struct {
		Assets []ingestedAsset `json:"assets"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse ingested assets: %w", err)
	}
	sort.Slice(f.Assets, func(i, j int) bool { return f.Assets[i].Asset < f.Assets[j].Asset })
	return f.Assets, nil
}

// assetsFrame builds a table with one row per asset: string columns, which
// alerting turns into labels, and the requested metric as the numeric column.
func assetsFrame(assets []ingestedAsset, metric string) (*data.Frame, error) {
	if metric == "" {
		metric = "kev"
	}
	metrics := []string{metric}
	if metric == "all" {
		metrics = allMetrics
	} else if _, ok := assetMetrics[metric]; !ok {
		return nil, fmt.Errorf("unknown metric %q (use one of kev, critical, high, moderate, low, unknown, total, all)", metric)
	}

	names := make([]string, 0, len(assets))
	sources := make([]string, 0, len(assets))
	namespaces := make([]string, 0, len(assets))
	values := make([][]int64, len(metrics))
	var scanned []time.Time
	for _, a := range assets {
		names = append(names, a.Asset)
		sources = append(sources, a.Source)
		namespaces = append(namespaces, strings.Join(a.Namespaces, ","))
		for i, m := range metrics {
			values[i] = append(values[i], int64(assetMetrics[m](a)))
		}
		scanned = append(scanned, a.LastScanned)
	}

	frame := data.NewFrame("assets",
		data.NewField("asset", nil, names),
		data.NewField("source", nil, sources),
		data.NewField("namespaces", nil, namespaces),
	)
	for i, m := range metrics {
		if values[i] == nil {
			values[i] = []int64{}
		}
		frame.Fields = append(frame.Fields, data.NewField(m, nil, values[i]))
	}
	// A time column is fine for tables but would stop alert rules from reading
	// the single numeric column, so only "all" includes it.
	if metric == "all" {
		if scanned == nil {
			scanned = []time.Time{}
		}
		frame.Fields = append(frame.Fields, data.NewField("last_scanned", nil, scanned))
	}
	frame.Meta = &data.FrameMeta{PreferredVisualization: data.VisTypeTable}
	return frame, nil
}
