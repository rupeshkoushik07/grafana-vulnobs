package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// QueryTypeAssets selects the scans ingested by the Vulnobs app instead of an
// OSV lookup.
const QueryTypeAssets = "assets"

type ingestedAsset struct {
	Asset       string         `json:"asset"`
	Source      string         `json:"source"`
	Namespaces  []string       `json:"namespaces"`
	Counts      map[string]int `json:"counts"`
	KEV         int            `json:"kev"`
	Total       int            `json:"total"`
	LastScanned time.Time      `json:"lastScanned"`
}

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

var errAssetsNotConfigured = errors.New("configure the authenticated storage API URL and token to query ingested assets")

func loadIngestedAssets(ctx context.Context, baseURL, token string, client *http.Client) ([]ingestedAsset, error) {
	if strings.TrimSpace(baseURL) == "" || len(strings.TrimSpace(token)) < 32 {
		return nil, errAssetsNotConfigured
	}
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("storage API URL must be an absolute HTTP or HTTPS URL without credentials, query, or fragment")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(parsed.String(), "/")+"/v1/assets", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query authenticated storage API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage API returned %s", resp.Status)
	}
	var result struct {
		Assets []ingestedAsset `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode ingested assets: %w", err)
	}
	sort.Slice(result.Assets, func(i, j int) bool { return result.Assets[i].Asset < result.Assets[j].Asset })
	return result.Assets, nil
}

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
	if metric == "all" {
		if scanned == nil {
			scanned = []time.Time{}
		}
		frame.Fields = append(frame.Fields, data.NewField("last_scanned", nil, scanned))
	}
	frame.Meta = &data.FrameMeta{PreferredVisualization: data.VisTypeTable}
	return frame, nil
}
