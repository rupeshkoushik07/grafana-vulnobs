package plugin

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// This file is identical in rupesh-vulnobs-app and rupesh-vulnobs-datasource.
// The fixtures in testdata/osv are real OSV responses; see the README there.

func loadVulns(t *testing.T, name string) []osvVuln {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "osv", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Vulns
}

var commitHash = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestNormalizeVulns(t *testing.T) {
	type want struct{ severity, fixed string }
	cases := []struct {
		fixture, pkg, version string
		records               int // raw OSV records before merging
		want                  map[string]want
	}{
		{
			// Every CVE is reported by GitHub (GHSA) and by the PyPA database
			// (PYSEC). PYSEC-2018-28 and PYSEC-2023-74 have no severity at all
			// and fix at a git commit as well as a release.
			fixture: "requests", pkg: "requests", version: "2.19.0", records: 10,
			want: map[string]want{
				"CVE-2018-18074": {"HIGH", "2.20.0"},
				"CVE-2023-32681": {"MODERATE", "2.31.0"},
				"CVE-2024-35195": {"MODERATE", "2.32.0"},
				"CVE-2024-47081": {"MODERATE", "2.32.4"},
				"CVE-2026-25645": {"MODERATE", "2.33.0"},
			},
		},
		{
			// GO-2021-0052 and GO-2023-1737 duplicate GitHub advisories without
			// a severity.
			fixture: "gin", pkg: "github.com/gin-gonic/gin", version: "v1.6.0", records: 5,
			want: map[string]want{
				"CVE-2020-28483": {"HIGH", "1.7.7"},
				"CVE-2023-26125": {"MODERATE", "1.9.0"},
				"CVE-2023-29401": {"MODERATE", "1.9.1"},
			},
		},
		{
			// Two GitHub advisories each for CVE-2021-23337 and CVE-2025-13465,
			// fixed in different releases: the merged fix must cover both.
			fixture: "lodash", pkg: "lodash", version: "4.17.11", records: 7,
			want: map[string]want{
				"CVE-2019-10744": {"CRITICAL", "4.17.12"},
				"CVE-2020-28500": {"MODERATE", "4.17.21"},
				"CVE-2020-8203":  {"HIGH", "4.17.19"},
				"CVE-2021-23337": {"HIGH", "4.18.0"},
				"CVE-2025-13465": {"MODERATE", "4.18.0"},
			},
		},
		{
			// Fixed on several release lines: 2.14.1 needs the fix on the 2.13+
			// line, not the first "fixed" event in the record (2.3.2 for
			// CVE-2021-44832).
			fixture: "log4j", pkg: "org.apache.logging.log4j:log4j-core", version: "2.14.1", records: 7,
			want: map[string]want{
				"CVE-2021-44228": {"CRITICAL", "2.15.0"},
				"CVE-2021-45046": {"CRITICAL", "2.16.0"},
				"CVE-2021-45105": {"HIGH", "2.17.0"},
				"CVE-2021-44832": {"MODERATE", "2.17.1"},
				"CVE-2025-68161": {"MODERATE", "2.25.3"},
				"CVE-2026-34477": {"MODERATE", "2.25.4"},
				"CVE-2026-34480": {"MODERATE", "2.25.4"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			vulns := loadVulns(t, c.fixture)
			if len(vulns) != c.records {
				t.Fatalf("fixture has %d records, want %d", len(vulns), c.records)
			}
			got := normalizeVulns(vulns, c.pkg, c.version)
			if len(got) != len(c.want) {
				t.Errorf("got %d advisories, want %d (one per CVE)", len(got), len(c.want))
			}
			seen := map[string]bool{}
			for _, a := range got {
				if seen[a.CVE] {
					t.Errorf("%s appears more than once", a.CVE)
				}
				seen[a.CVE] = true
				w, ok := c.want[a.CVE]
				if !ok {
					t.Errorf("unexpected advisory %s (%s)", a.CVE, a.ID)
					continue
				}
				if a.Severity != w.severity {
					t.Errorf("%s severity = %s, want %s", a.CVE, a.Severity, w.severity)
				}
				if a.Fixed != w.fixed {
					t.Errorf("%s fixed = %q, want %q", a.CVE, a.Fixed, w.fixed)
				}
				if commitHash.MatchString(a.Fixed) {
					t.Errorf("%s fixed version is a commit hash: %s", a.CVE, a.Fixed)
				}
			}
		})
	}
}

func TestLookupByCVEUsesCVSS(t *testing.T) {
	// OSV's own CVE record has a CVSS vector but no severity label.
	got := normalizeVulns(loadVulns(t, "cve-2021-44228"), "", "")
	if len(got) != 1 {
		t.Fatalf("got %d advisories, want 1", len(got))
	}
	if got[0].Severity != "CRITICAL" {
		t.Errorf("severity = %s, want CRITICAL (CVSS 10.0)", got[0].Severity)
	}
	if got[0].CVSS == "" {
		t.Error("CVSS vector should be kept")
	}
}

func TestWithdrawnRecordsAreDropped(t *testing.T) {
	vulns := []osvVuln{
		{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2020-0001"}, Withdrawn: "2024-01-01T00:00:00Z"},
		{ID: "GHSA-dddd-eeee-ffff", Aliases: []string{"CVE-2020-0002"}},
	}
	got := normalizeVulns(vulns, "", "")
	if len(got) != 1 || got[0].CVE != "CVE-2020-0002" {
		t.Errorf("got %+v, want only CVE-2020-0002", got)
	}
}

func TestCVSS3BaseScore(t *testing.T) {
	// Expected scores from the reference Python implementation
	// (https://github.com/RedHatProductSecurity/cvss) for every CVSS v3 vector
	// in the fixtures.
	cases := []struct {
		vector   string
		score    float64
		severity string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3, "MODERATE"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.6, "MODERATE"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", 7.1, "HIGH"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, "MODERATE"},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "HIGH"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L", 6.5, "MODERATE"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1, "CRITICAL"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4, "HIGH"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "HIGH"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H", 9.0, "CRITICAL"},
		{"CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.6, "MODERATE"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H", 10.0, "CRITICAL"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H", 8.6, "HIGH"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3, "MODERATE"},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N", 5.6, "MODERATE"},
		{"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N", 4.4, "MODERATE"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.1, "MODERATE"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "HIGH"},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 5.5, "MODERATE"},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, ""},
	}
	for _, c := range cases {
		score, ok := cvss3BaseScore(c.vector)
		if !ok {
			t.Errorf("%s: not parsed", c.vector)
			continue
		}
		if math.Abs(score-c.score) > 1e-9 {
			t.Errorf("%s: score %.1f, want %.1f", c.vector, score, c.score)
		}
		if got := cvssSeverity(score); got != c.severity {
			t.Errorf("%s: severity %q, want %q", c.vector, got, c.severity)
		}
	}

	for _, bad := range []string{
		"",
		"CVSS:3.1/AV:N",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H",
	} {
		if _, ok := cvss3BaseScore(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.17.1", "2.3.2", 1},
		{"1.10.0", "1.9.9", 1},
		{"v1.7.7", "1.7.7", 0},
		{"2.15", "2.15.0", 0},
		{"2.0-beta9", "2.0", -1},
		{"2.0", "2.0-beta9", 1},
		{"4.17.23", "4.18.0", -1},
		{"2.14.1", "2.13.0", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
