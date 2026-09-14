package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// AssetPosture is the latest vulnerability posture for one scanned asset
// (an image, deployment, or repo).
type AssetPosture struct {
	Asset       string         `json:"asset"`
	Source      string         `json:"source"`               // who pushed it, e.g. "cluster" for the scan CronJob
	Namespaces  []string       `json:"namespaces,omitempty"` // where the image runs, for cluster scans
	Format      string         `json:"format"`
	LastScanned time.Time      `json:"lastScanned"`
	Counts      map[string]int `json:"counts"` // severity -> count
	KEV         int            `json:"kev"`    // actively exploited (CISA KEV) findings
	Total       int            `json:"total"`
	Rows        []ScanRow      `json:"rows,omitempty"`
}

// storeFileName is the asset store's file inside the data directory. The
// Vulnobs data source reads the same file (rupesh-vulnobs-datasource
// pkg/plugin/assets.go) to serve dashboards and alert rules, so keep the format
// compatible.
const storeFileName = "assets.json"

type storeFile struct {
	Version int             `json:"version"`
	Assets  []*AssetPosture `json:"assets"`
}

// assetStore keeps the most recent posture per asset. With a data directory it
// also writes every change to disk, so postures survive restarts; without one
// it only keeps them in memory.
//
// Grafana creates one app instance per organization, and instances configured
// with the same directory share one file. Give each organization its own
// directory if more than one ingests scans.
type assetStore struct {
	mu     sync.RWMutex
	assets map[string]*AssetPosture
	path   string // "" keeps assets in memory only
}

// newAssetStore opens the store in dir, loading any saved postures. An empty
// dir gives a memory-only store. On error the store is still usable: it falls
// back to memory if dir can't be created, and starts empty (and overwrites the
// file on the next change) if the saved file can't be read.
func newAssetStore(dir string) (*assetStore, error) {
	s := &assetStore{assets: map[string]*AssetPosture{}}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return s, fmt.Errorf("create data directory: %w", err)
	}
	s.path = filepath.Join(dir, storeFileName)

	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("read %s: %w", s.path, err)
	}
	var f storeFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return s, fmt.Errorf("parse %s: %w", s.path, err)
	}
	for _, a := range f.Assets {
		if a != nil && a.Asset != "" {
			s.assets[a.Asset] = a
		}
	}
	return s, nil
}

// persistent reports whether changes are written to disk, and where.
func (s *assetStore) persistent() (bool, string) {
	return s.path != "", filepath.Dir(s.path)
}

// put replaces the stored posture for an asset with the latest scan. The
// posture is stored even if saving it to disk fails; the error says so.
func (s *assetStore) put(name, source, format string, namespaces []string, rows []ScanRow) (*AssetPosture, error) {
	counts := map[string]int{}
	kev := 0
	for _, r := range rows {
		counts[r.Severity]++
		if r.KEV {
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

	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets[name] = p
	return p, s.saveLocked()
}

// prune removes assets pushed by source that are not in keep, and returns
// their names. Assets from other sources are left alone.
func (s *assetStore) prune(source string, keep []string) ([]string, error) {
	keepSet := make(map[string]bool, len(keep))
	for _, k := range keep {
		keepSet[k] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	removed := []string{}
	for name, a := range s.assets {
		if a.Source == source && !keepSet[name] {
			delete(s.assets, name)
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	if len(removed) == 0 {
		return removed, nil
	}
	return removed, s.saveLocked()
}

// saveLocked writes all assets to disk atomically: a temporary file in the
// same directory, renamed over the old one. The caller holds s.mu.
func (s *assetStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	f := storeFile{Version: 1, Assets: make([]*AssetPosture, 0, len(s.assets))}
	for _, a := range s.assets {
		f.Assets = append(f.Assets, a)
	}
	sort.Slice(f.Assets, func(i, j int) bool { return f.Assets[i].Asset < f.Assets[j].Asset })
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".assets-*.json")
	if err != nil {
		return fmt.Errorf("save assets: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save assets: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save assets: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("save assets: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("save assets: %w", err)
	}
	return nil
}

// list returns all assets without their per-row detail, most urgent first:
// actively exploited findings, then critical, then high, then total.
func (s *assetStore) list() []*AssetPosture {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*AssetPosture, 0, len(s.assets))
	for _, a := range s.assets {
		summary := *a
		summary.Rows = nil
		out = append(out, &summary)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
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
	return out
}

// get returns the full posture (with rows) for one asset.
func (s *assetStore) get(name string) (*AssetPosture, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[name]
	return a, ok
}
