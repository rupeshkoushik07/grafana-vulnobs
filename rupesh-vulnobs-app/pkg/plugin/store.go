package plugin

import (
	"sort"
	"sync"
	"time"
)

// AssetPosture is the latest vulnerability posture for one scanned asset
// (a deployment, image, or repo).
type AssetPosture struct {
	Asset       string         `json:"asset"`
	Format      string         `json:"format"`
	LastScanned time.Time      `json:"lastScanned"`
	Counts      map[string]int `json:"counts"` // severity -> count
	Total       int            `json:"total"`
	Rows        []ScanRow      `json:"rows,omitempty"`
}

// assetStore keeps the most recent posture per asset in memory. It is reset when
// the plugin restarts; durable storage (Loki) is a later phase.
type assetStore struct {
	mu     sync.RWMutex
	assets map[string]*AssetPosture
}

func newAssetStore() *assetStore {
	return &assetStore{assets: map[string]*AssetPosture{}}
}

// put replaces the stored posture for an asset with the latest scan.
func (s *assetStore) put(name, format string, rows []ScanRow) *AssetPosture {
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Severity]++
	}
	p := &AssetPosture{
		Asset:       name,
		Format:      format,
		LastScanned: time.Now().UTC(),
		Counts:      counts,
		Total:       len(rows),
		Rows:        rows,
	}
	s.mu.Lock()
	s.assets[name] = p
	s.mu.Unlock()
	return p
}

// list returns all assets (without their per-row detail), most-critical first.
func (s *assetStore) list() []*AssetPosture {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*AssetPosture, 0, len(s.assets))
	for _, a := range s.assets {
		out = append(out, &AssetPosture{
			Asset:       a.Asset,
			Format:      a.Format,
			LastScanned: a.LastScanned,
			Counts:      a.Counts,
			Total:       a.Total,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Counts["CRITICAL"] != out[j].Counts["CRITICAL"] {
			return out[i].Counts["CRITICAL"] > out[j].Counts["CRITICAL"]
		}
		if out[i].Counts["HIGH"] != out[j].Counts["HIGH"] {
			return out[i].Counts["HIGH"] > out[j].Counts["HIGH"]
		}
		return out[i].Total > out[j].Total
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
