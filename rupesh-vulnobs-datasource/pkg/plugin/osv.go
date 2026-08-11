package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

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
	Type  string `json:"type"`  // e.g. CVSS_V3
	Score string `json:"score"` // a CVSS vector string, not a number
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

// osvQueryPackage POSTs to /v1/query and returns all vulnerabilities affecting a
// package (optionally constrained to a specific version).
func (d *Datasource) osvQueryPackage(ctx context.Context, ecosystem, pkg, version string) ([]osvVuln, error) {
	body := map[string]any{
		"package": map[string]string{"name": pkg, "ecosystem": ecosystem},
	}
	if version != "" {
		body["version"] = version
	}

	raw, err := d.osvPost(ctx, "/v1/query", body)
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

// osvGetVuln fetches a single vulnerability by its id (OSV, GHSA or CVE id) via
// GET /v1/vulns/{id}.
func (d *Datasource) osvGetVuln(ctx context.Context, id string) (*osvVuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
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

func (d *Datasource) osvPost(ctx context.Context, path string, body any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
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

// vulnsToFrame turns OSV vulnerabilities into a Grafana table data frame.
func vulnsToFrame(name string, vulns []osvVuln) *data.Frame {
	var (
		ids        []string
		cves       []string
		severities []string
		scores     []int64
		summaries  []string
		fixed      []string
		cvss       []string
		published  []*time.Time
		modified   []*time.Time
		urls       []string
	)

	for _, v := range vulns {
		label := severityLabel(v)
		ids = append(ids, v.ID)
		cves = append(cves, cveOf(v))
		severities = append(severities, label)
		scores = append(scores, severityScore(label))
		summaries = append(summaries, summaryOf(v))
		fixed = append(fixed, fixedVersion(v))
		cvss = append(cvss, firstCVSS(v))
		published = append(published, parseTime(v.Published))
		modified = append(modified, parseTime(v.Modified))
		urls = append(urls, primaryURL(v))
	}

	frame := data.NewFrame(name,
		data.NewField("id", nil, ids),
		data.NewField("cve", nil, cves),
		data.NewField("severity", nil, severities),
		data.NewField("severity_score", nil, scores),
		data.NewField("cvss", nil, cvss),
		data.NewField("summary", nil, summaries),
		data.NewField("fixed_version", nil, fixed),
		data.NewField("published", nil, published),
		data.NewField("modified", nil, modified),
		data.NewField("url", nil, urls),
	)
	frame.Meta = &data.FrameMeta{PreferredVisualization: data.VisTypeTable}
	return frame
}

// --- helpers ---

// cveOf returns the CVE identifier for a record: its own id when it is a CVE
// record, otherwise the first CVE found among its aliases.
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

// severityLabel best-effort extracts a qualitative severity (CRITICAL/HIGH/...)
// from the record- or affected-level database_specific.severity fields.
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

// severityScore maps a label to a numeric rank so alert rules can threshold it.
func severityScore(label string) int64 {
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
	// Fall back to the first line of details.
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

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
