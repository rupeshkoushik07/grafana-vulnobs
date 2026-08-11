package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DefaultOsvBaseURL is the public OSV.dev API. https://osv.dev
const DefaultOsvBaseURL = "https://api.osv.dev"

// osvVuln is a subset of an OSV vulnerability record.
// See https://ossf.github.io/osv-schema/
type osvVuln struct {
	ID        string          `json:"id"`
	Summary   string          `json:"summary"`
	Details   string          `json:"details"`
	Aliases   []string        `json:"aliases"`
	Published string          `json:"published"`
	Modified  string          `json:"modified"`
	Severity  []osvSeverity   `json:"severity"`
	Affected  []osvAffected   `json:"affected"`
	Refs      []osvReference  `json:"references"`
	DBSpec    json.RawMessage `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Ranges  []osvRange      `json:"ranges"`
	DBSpec  json.RawMessage `json:"database_specific"`
	EcoSpec json.RawMessage `json:"ecosystem_specific"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// VulnRow is the flat, JSON-friendly shape returned to the app frontend.
type VulnRow struct {
	ID            string `json:"id"`
	CVE           string `json:"cve"`
	Severity      string `json:"severity"`
	SeverityScore int    `json:"severityScore"`
	CVSS          string `json:"cvss"`
	Summary       string `json:"summary"`
	FixedVersion  string `json:"fixedVersion"`
	Published     string `json:"published"`
	Modified      string `json:"modified"`
	URL           string `json:"url"`
}

// osvQueryPackage POSTs to /v1/query and returns all vulnerabilities affecting a
// package (optionally constrained to a specific version).
func (a *App) osvQueryPackage(ctx context.Context, ecosystem, pkg, version string) ([]osvVuln, error) {
	body := map[string]any{
		"package": map[string]string{"name": pkg, "ecosystem": ecosystem},
	}
	if version != "" {
		body["version"] = version
	}

	raw, err := a.osvPost(ctx, "/v1/query", body)
	if err != nil {
		return nil, err
	}

	var out struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}
	return out.Vulns, nil
}

// osvGetVuln fetches a single vulnerability by its id (OSV, GHSA or CVE id).
func (a *App) osvGetVuln(ctx context.Context, id string) (*osvVuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned %s for id %q", resp.Status, id)
	}

	var v osvVuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}
	return &v, nil
}

func (a *App) osvPost(ctx context.Context, path string, body any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned %s", resp.Status)
	}
	return raw, nil
}

// toRows flattens OSV vulnerabilities into VulnRows for the frontend.
func toRows(vulns []osvVuln) []VulnRow {
	rows := make([]VulnRow, 0, len(vulns))
	for _, v := range vulns {
		label := severityLabel(v)
		rows = append(rows, VulnRow{
			ID:            v.ID,
			CVE:           cveOf(v),
			Severity:      label,
			SeverityScore: severityScore(label),
			CVSS:          firstCVSS(v),
			Summary:       summaryOf(v),
			FixedVersion:  fixedVersion(v),
			Published:     v.Published,
			Modified:      v.Modified,
			URL:           primaryURL(v),
		})
	}
	return rows
}

// --- helpers ---

func cveOf(v osvVuln) string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}

func severityLabel(v osvVuln) string {
	if s := severityFromRaw(v.DBSpec); s != "" {
		return s
	}
	for _, a := range v.Affected {
		if s := severityFromRaw(a.DBSpec); s != "" {
			return s
		}
		if s := severityFromRaw(a.EcoSpec); s != "" {
			return s
		}
	}
	return "UNKNOWN"
}

func severityFromRaw(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	return normalizeSeverity(m.Severity)
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MODERATE", "MEDIUM":
		return "MODERATE"
	case "LOW":
		return "LOW"
	default:
		return ""
	}
}

func severityScore(label string) int {
	switch label {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MODERATE":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func summaryOf(v osvVuln) string {
	if v.Summary != "" {
		return v.Summary
	}
	if v.Details != "" {
		if i := strings.IndexByte(v.Details, '\n'); i > 0 {
			return v.Details[:i]
		}
		return v.Details
	}
	return ""
}

func fixedVersion(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func firstCVSS(v osvVuln) string {
	if len(v.Severity) > 0 {
		return v.Severity[0].Score
	}
	return ""
}

func primaryURL(v osvVuln) string {
	for _, r := range v.Refs {
		if r.Type == "ADVISORY" && r.URL != "" {
			return r.URL
		}
	}
	if len(v.Refs) > 0 {
		return v.Refs[0].URL
	}
	if v.ID != "" {
		return "https://osv.dev/vulnerability/" + v.ID
	}
	return ""
}
