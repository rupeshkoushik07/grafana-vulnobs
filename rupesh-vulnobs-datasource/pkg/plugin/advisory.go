package plugin

import (
	"math"
	"strings"
)

// This file is identical in rupesh-vulnobs-app and rupesh-vulnobs-datasource,
// which are separate Go modules. Change both copies together.

// advisory is one vulnerability as shown to users: OSV records describing the
// same CVE merged into one, with a severity and a fixed version that make sense
// for the package being looked at.
type advisory struct {
	ID        string
	CVE       string
	Severity  string // CRITICAL, HIGH, MODERATE, LOW or UNKNOWN
	CVSS      string // a CVSS vector string, if any record has one
	Summary   string
	Fixed     string
	Published string
	Modified  string
	URL       string
}

// normalizeVulns turns raw OSV records into advisories.
//
// OSV aggregates several databases, so one CVE often arrives as several records
// (GHSA-... from GitHub and PYSEC-... or GO-... from the ecosystem's own
// database), and not all of them carry a severity. Records that share a CVE are
// merged into one advisory; records without a CVE are kept as they are.
// Withdrawn records are dropped.
//
// pkg and version describe what was queried and may be empty, as in a lookup by
// id. They select the affected ranges that apply, so the fixed version is one
// the package can actually upgrade to.
func normalizeVulns(vulns []osvVuln, pkg, version string) []advisory {
	var order []string
	groups := map[string][]osvVuln{}
	for _, v := range vulns {
		if v.Withdrawn != "" {
			continue
		}
		key := cveOf(v)
		if key == "" {
			key = v.ID
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], v)
	}

	out := make([]advisory, 0, len(order))
	for _, key := range order {
		out = append(out, mergeRecords(groups[key], pkg, version))
	}
	return out
}

// mergeRecords combines records for one CVE. The record with the most reliable
// severity represents the group; the fixed version is the highest any record
// needs, so upgrading to it fixes every one of them.
func mergeRecords(records []osvVuln, pkg, version string) advisory {
	best, bestRank := 0, -1
	for i, r := range records {
		if rank := recordRank(r); rank > bestRank {
			best, bestRank = i, rank
		}
	}
	rep := records[best]
	severity, vector := severityOf(rep)

	a := advisory{
		ID:        rep.ID,
		CVE:       cveOf(rep),
		Severity:  severity,
		CVSS:      vector,
		Summary:   summaryOf(rep),
		Published: rep.Published,
		Modified:  rep.Modified,
		URL:       primaryURL(rep),
	}
	for _, r := range records {
		if a.Summary == "" {
			a.Summary = summaryOf(r)
		}
		if a.CVSS == "" {
			a.CVSS = firstCVSS(r)
		}
		if f := fixedVersionFor(r, pkg, version); f != "" && (a.Fixed == "" || compareVersions(f, a.Fixed) > 0) {
			a.Fixed = f
		}
	}
	return a
}

// recordRank prefers a curated severity label over one computed from CVSS, a
// higher severity over a lower one, and GitHub advisories on ties.
func recordRank(v osvVuln) int {
	rank := 0
	if labelSeverity(v) != "" {
		rank = 200
	} else if computedSeverity(v) != "" {
		rank = 100
	}
	severity, _ := severityOf(v)
	rank += 10 * severityRank(severity)
	if strings.HasPrefix(v.ID, "GHSA-") {
		rank++
	}
	return rank
}

func severityRank(label string) int {
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

// severityOf returns a record's severity label and the CVSS vector alongside it.
func severityOf(v osvVuln) (string, string) {
	if s := labelSeverity(v); s != "" {
		return s, firstCVSS(v)
	}
	for _, s := range v.Severity {
		if s.Type != "CVSS_V3" {
			continue
		}
		if score, ok := cvss3BaseScore(s.Score); ok {
			if label := cvssSeverity(score); label != "" {
				return label, s.Score
			}
		}
	}
	return "UNKNOWN", firstCVSS(v)
}

// labelSeverity reads a qualitative severity (CRITICAL/HIGH/...) from the
// record- or affected-level database_specific or ecosystem_specific fields.
func labelSeverity(v osvVuln) string {
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
	return ""
}

func computedSeverity(v osvVuln) string {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if score, ok := cvss3BaseScore(s.Score); ok {
				return cvssSeverity(score)
			}
		}
	}
	return ""
}

// fixedVersionFor returns the release that fixes a record for the queried
// package. Only ECOSYSTEM and SEMVER ranges count: GIT ranges name a commit,
// which is not something a user can upgrade to. With a version, it is the fix
// for the release line that version is on; without one, the highest fix.
func fixedVersionFor(v osvVuln, pkg, version string) string {
	affected := v.Affected
	if pkg != "" {
		var matching []osvAffected
		for _, a := range v.Affected {
			if samePackage(a.Package.Name, pkg) {
				matching = append(matching, a)
			}
		}
		if len(matching) > 0 {
			affected = matching
		}
	}

	var containing, above, highest string
	for _, a := range affected {
		for _, r := range a.Ranges {
			if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
				continue
			}
			introduced := ""
			for _, e := range r.Events {
				if e.Introduced != "" {
					introduced = e.Introduced
					continue
				}
				if e.Fixed == "" {
					continue
				}
				highest = maxVersion(highest, e.Fixed)
				if version != "" && compareVersions(e.Fixed, version) > 0 {
					above = minVersion(above, e.Fixed)
					if introduced == "" || introduced == "0" || compareVersions(version, introduced) >= 0 {
						containing = minVersion(containing, e.Fixed)
					}
				}
				introduced = ""
			}
		}
	}

	switch {
	case version == "":
		return highest
	case containing != "":
		return containing
	default:
		return above
	}
}

// samePackage compares package names, treating case and the separators PyPI
// considers equivalent (PEP 503) as insignificant.
func samePackage(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		return strings.NewReplacer("_", "-", ".", "-").Replace(s)
	}
	return norm(a) == norm(b)
}

// cvss3BaseScore computes the base score of a CVSS v3.0 or v3.1 vector, per the
// CVSS v3.1 specification. Temporal and environmental metrics are ignored.
func cvss3BaseScore(vector string) (float64, bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1") {
		return 0, false
	}
	metrics := map[string]string{}
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, ":")
		if !ok {
			return 0, false
		}
		metrics[k] = val
	}

	scope := metrics["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}
	privileges := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		privileges = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	impactWeights := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	weights := []struct {
		metric string
		values map[string]float64
	}{
		{"AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}},
		{"AC", map[string]float64{"L": 0.77, "H": 0.44}},
		{"PR", privileges},
		{"UI", map[string]float64{"N": 0.85, "R": 0.62}},
		{"C", impactWeights},
		{"I", impactWeights},
		{"A", impactWeights},
	}
	w := make([]float64, len(weights))
	for i, m := range weights {
		value, ok := m.values[metrics[m.metric]]
		if !ok {
			return 0, false
		}
		w[i] = value
	}
	av, ac, pr, ui, c, integrity, avail := w[0], w[1], w[2], w[3], w[4], w[5], w[6]

	iss := 1 - (1-c)*(1-integrity)*(1-avail)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	if scope == "U" {
		return roundUp(math.Min(impact+exploitability, 10)), true
	}
	return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
}

// roundUp is the CVSS v3.1 Roundup function: the smallest one-decimal number
// greater than or equal to x, computed without floating-point drift.
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// cvssSeverity maps a CVSS v3 base score to its qualitative rating. OSV and
// GitHub call MEDIUM "MODERATE", so this does too.
func cvssSeverity(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MODERATE"
	case score > 0:
		return "LOW"
	default:
		return ""
	}
}

// compareVersions orders two version strings, returning -1, 0 or 1. It is a
// best-effort comparison that works across ecosystems: numeric parts compare as
// numbers, a leading "v" is ignored, missing trailing zeros are equal ("2.15"
// equals "2.15.0"), and a pre-release suffix sorts before its release
// ("2.0-beta9" is before "2.0").
func compareVersions(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		switch {
		case i >= len(ta):
			if isDigit(tb[i][0]) {
				if strings.TrimLeft(tb[i], "0") == "" {
					continue
				}
				return -1
			}
			return 1
		case i >= len(tb):
			if isDigit(ta[i][0]) {
				if strings.TrimLeft(ta[i], "0") == "" {
					continue
				}
				return 1
			}
			return -1
		}
		if c := compareTokens(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	return 0
}

func versionTokens(v string) []string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && isDigit(v[1]) {
		v = v[1:]
	}
	var tokens []string
	start := -1
	for i := 0; i <= len(v); i++ {
		boundary := i == len(v) || !isAlnum(v[i]) || (start >= 0 && isDigit(v[i]) != isDigit(v[start]))
		if boundary && start >= 0 {
			tokens = append(tokens, strings.ToLower(v[start:i]))
			start = -1
		}
		if i < len(v) && isAlnum(v[i]) && start < 0 {
			start = i
		}
	}
	return tokens
}

func compareTokens(x, y string) int {
	xNum, yNum := isDigit(x[0]), isDigit(y[0])
	switch {
	case xNum && yNum:
		x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
		if len(x) != len(y) {
			if len(x) < len(y) {
				return -1
			}
			return 1
		}
		return strings.Compare(x, y)
	case xNum:
		return 1
	case yNum:
		return -1
	default:
		return strings.Compare(x, y)
	}
}

func maxVersion(current, candidate string) string {
	if current == "" || compareVersions(candidate, current) > 0 {
		return candidate
	}
	return current
}

func minVersion(current, candidate string) string {
	if current == "" || compareVersions(candidate, current) < 0 {
		return candidate
	}
	return current
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
