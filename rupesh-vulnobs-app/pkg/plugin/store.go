package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AssetPosture is the latest vulnerability posture for one scanned asset.
type AssetPosture struct {
	Asset       string         `json:"asset"`
	Source      string         `json:"source"`
	Namespaces  []string       `json:"namespaces,omitempty"`
	Format      string         `json:"format"`
	LastScanned time.Time      `json:"lastScanned"`
	Counts      map[string]int `json:"counts"`
	KEV         int            `json:"kev"`
	Total       int            `json:"total"`
	Rows        []ScanRow      `json:"rows,omitempty"`
}

type assetStore struct {
	baseURL string
	token   string
	client  *http.Client
}

type storageHTTPError struct {
	status int
}

func (e storageHTTPError) Error() string { return http.StatusText(e.status) }

func newAssetStore(baseURL, token string, client *http.Client) (*assetStore, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("storage API URL must be an absolute HTTP or HTTPS URL without credentials, query, or fragment")
	}
	if len(strings.TrimSpace(token)) < 32 {
		return nil, errors.New("storage API token must contain at least 32 characters")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &assetStore{baseURL: strings.TrimRight(parsed.String(), "/"), token: token, client: client}, nil
}

func (s *assetStore) request(ctx context.Context, method, path string, body any, target any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("create storage request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("storage API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return storageHTTPError{status: resp.StatusCode}
	}
	if target == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode storage API response: %w", err)
	}
	return nil
}

func (s *assetStore) check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/v1/health", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("storage API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("storage API returned %s", resp.Status)
	}
	return nil
}

func (s *assetStore) put(ctx context.Context, name, source, format string, namespaces []string, rows []ScanRow) (*AssetPosture, error) {
	counts := map[string]int{}
	kev := 0
	for _, row := range rows {
		counts[row.Severity]++
		if row.KEV {
			kev++
		}
	}
	p := &AssetPosture{
		Asset:       name,
		Source:      source,
		Namespaces:  namespaces,
		Format:      format,
		LastScanned: time.Now().UTC(),
		Counts:      counts,
		KEV:         kev,
		Total:       len(rows),
		Rows:        rows,
	}
	if err := s.request(ctx, http.MethodPut, "/v1/assets", p, nil); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *assetStore) prune(ctx context.Context, source string, keep []string) ([]string, error) {
	var result struct {
		Removed []string `json:"removed"`
	}
	if err := s.request(ctx, http.MethodPost, "/v1/assets/prune", map[string]any{"source": source, "keep": keep}, &result); err != nil {
		return nil, err
	}
	sort.Strings(result.Removed)
	return result.Removed, nil
}

func (s *assetStore) list(ctx context.Context) ([]*AssetPosture, error) {
	var result struct {
		Assets []*AssetPosture `json:"assets"`
	}
	if err := s.request(ctx, http.MethodGet, "/v1/assets", nil, &result); err != nil {
		return nil, err
	}
	for _, asset := range result.Assets {
		asset.Rows = nil
	}
	sort.Slice(result.Assets, func(i, j int) bool {
		a, b := result.Assets[i], result.Assets[j]
		switch {
		case a.KEV != b.KEV:
			return a.KEV > b.KEV
		case a.Counts["CRITICAL"] != b.Counts["CRITICAL"]:
			return a.Counts["CRITICAL"] > b.Counts["CRITICAL"]
		case a.Counts["HIGH"] != b.Counts["HIGH"]:
			return a.Counts["HIGH"] > b.Counts["HIGH"]
		case a.Total != b.Total:
			return a.Total > b.Total
		default:
			return a.Asset < b.Asset
		}
	})
	return result.Assets, nil
}

func (s *assetStore) get(ctx context.Context, name string) (*AssetPosture, bool, error) {
	var p AssetPosture
	err := s.request(ctx, http.MethodPost, "/v1/assets/get", map[string]string{"asset": name}, &p)
	if err != nil {
		var statusError storageHTTPError
		if errors.As(err, &statusError) && statusError.status == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &p, true, nil
}
