package plugin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	epssAPI    = "https://api.first.org/data/v1/epss"
	kevFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevTTL     = 6 * time.Hour
	epssChunk  = 100
)

// CVEIntel is the exploit-context enrichment for a single CVE.
type CVEIntel struct {
	CVE      string  `json:"cve"`
	EPSS     float64 `json:"epss"`     // probability of exploitation in the next 30 days (0..1)
	KEV      bool    `json:"kev"`      // listed in CISA Known Exploited Vulnerabilities
	Priority int     `json:"priority"` // higher = fix sooner
	Action   string  `json:"action"`   // now | urgent | soon | backlog
}

// kevCache holds the CISA KEV id set with a TTL.
type kevCache struct {
	mu      sync.RWMutex
	set     map[string]bool
	fetched time.Time
}

func newKevCache() *kevCache { return &kevCache{set: map[string]bool{}} }

// contains reports whether a CVE is on the KEV list, refreshing the feed if stale.
// A refresh failure is non-fatal: we keep serving whatever we last had.
func (k *kevCache) ensure(ctx context.Context, client *http.Client) {
	k.mu.RLock()
	fresh := time.Since(k.fetched) < kevTTL && len(k.set) > 0
	k.mu.RUnlock()
	if fresh {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevFeedURL, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var feed struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return
	}
	set := make(map[string]bool, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		set[v.CveID] = true
	}
	k.mu.Lock()
	k.set = set
	k.fetched = time.Now()
	k.mu.Unlock()
}

func (k *kevCache) has(cve string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.set[cve]
}

// enrichCVEs returns exploit intel (EPSS + KEV + priority) for a set of CVE ids.
func (a *App) enrichCVEs(ctx context.Context, cves []string) map[string]CVEIntel {
	out := map[string]CVEIntel{}

	// Dedupe, keeping only real CVE ids.
	uniq := make([]string, 0, len(cves))
	seen := map[string]bool{}
	for _, c := range cves {
		c = strings.TrimSpace(c)
		if !strings.HasPrefix(c, "CVE-") || seen[c] {
			continue
		}
		seen[c] = true
		uniq = append(uniq, c)
	}
	if len(uniq) == 0 {
		return out
	}

	a.kev.ensure(ctx, a.httpClient)

	// EPSS scores, fetched in chunks to keep URLs sane.
	epss := map[string]float64{}
	for i := 0; i < len(uniq); i += epssChunk {
		end := i + epssChunk
		if end > len(uniq) {
			end = len(uniq)
		}
		for k, v := range a.fetchEPSS(ctx, uniq[i:end]) {
			epss[k] = v
		}
	}

	for _, c := range uniq {
		e := epss[c]
		k := a.kev.has(c)
		out[c] = CVEIntel{
			CVE:      c,
			EPSS:     e,
			KEV:      k,
			Priority: priorityScore(0, e, k),
			Action:   actionLabel(e, k),
		}
	}
	return out
}

func (a *App) fetchEPSS(ctx context.Context, cves []string) map[string]float64 {
	out := map[string]float64{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssAPI+"?cve="+strings.Join(cves, ","), nil)
	if err != nil {
		return out
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	raw, _ := io.ReadAll(resp.Body)
	var body struct {
		Data []struct {
			CVE  string `json:"cve"`
			EPSS string `json:"epss"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return out
	}
	for _, d := range body.Data {
		out[d.CVE] = parseFloat(d.EPSS)
	}
	return out
}

// priorityScore ranks a finding: KEV (actively exploited) dominates, then EPSS,
// then the CVSS severity bucket as a tie-breaker.
func priorityScore(severityScore int, epss float64, kev bool) int {
	s := severityScore * 10 // 0..40 from the severity bucket
	s += int(epss * 100)    // 0..100 from exploit probability
	if kev {
		s += 1000 // actively exploited outranks everything
	}
	return s
}

func actionLabel(epss float64, kev bool) string {
	switch {
	case kev:
		return "now"
	case epss > 0.5:
		return "urgent"
	case epss > 0.1:
		return "soon"
	default:
		return "backlog"
	}
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}
