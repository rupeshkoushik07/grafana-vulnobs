package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// maxPackages caps how many packages we query per scan, to keep the request
// responsive and gentle on the OSV API.
const maxPackages = 200

// scanConcurrency bounds parallel OSV requests.
const scanConcurrency = 8

// pkgRef is a package extracted from a scan, mapped to an OSV ecosystem.
type pkgRef struct {
	Ecosystem string
	Name      string
	Version   string
}

// ScanRow is one (package, vulnerability) pairing returned to the frontend.
type ScanRow struct {
	Package       string `json:"package"`
	Ecosystem     string `json:"ecosystem"`
	Version       string `json:"version"`
	ID            string `json:"id"`
	CVE           string `json:"cve"`
	Severity      string `json:"severity"`
	SeverityScore int    `json:"severityScore"`
	FixedVersion  string `json:"fixedVersion"`
	Summary       string `json:"summary"`
	URL           string `json:"url"`
}

// mapEcosystem maps a scanner's package type/ecosystem string to an OSV
// ecosystem. It returns "" for types OSV language feeds don't cover (e.g. OS
// packages, which need a release-qualified ecosystem).
func mapEcosystem(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "npm", "node-pkg", "node":
		return "npm"
	case "pip", "python-pkg", "python", "poetry", "conda":
		return "PyPI"
	case "gobinary", "gomod", "go-module", "go":
		return "Go"
	case "jar", "pom", "gradle", "java-archive", "maven", "java":
		return "Maven"
	case "gem", "gemspec", "ruby":
		return "RubyGems"
	case "cargo", "rust-crate", "rust":
		return "crates.io"
	case "nuget", "dotnet":
		return "NuGet"
	case "composer", "php-composer", "php":
		return "Packagist"
	case "pub", "dart":
		return "Pub"
	case "hex", "erlang", "elixir":
		return "Hex"
	default:
		return ""
	}
}

// --- Trivy ---

type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Type     string `json:"Type"`
		Packages []struct {
			Name    string `json:"Name"`
			Version string `json:"Version"`
		} `json:"Packages"`
		Vulnerabilities []struct {
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// --- Grype ---

type grypeReport struct {
	Matches []struct {
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	} `json:"matches"`
	Source struct {
		Target json.RawMessage `json:"target"`
	} `json:"source"`
}

// parseScan detects the scan format and extracts a deduplicated package list.
// skippedOS counts packages dropped because their ecosystem isn't an OSV
// language feed we can query.
func parseScan(raw []byte) (format, image string, pkgs []pkgRef, skippedOS int, err error) {
	// Sniff the format from top-level keys.
	var probe map[string]json.RawMessage
	if err = json.Unmarshal(raw, &probe); err != nil {
		return "", "", nil, 0, fmt.Errorf("not valid JSON: %w", err)
	}

	seen := map[string]bool{}
	add := func(eco, name, version string) {
		if eco == "" {
			skippedOS++
			return
		}
		if name == "" {
			return
		}
		key := eco + "\x00" + name + "\x00" + version
		if seen[key] {
			return
		}
		seen[key] = true
		pkgs = append(pkgs, pkgRef{Ecosystem: eco, Name: name, Version: version})
	}

	switch {
	case probe["matches"] != nil:
		format = "grype"
		var g grypeReport
		if err = json.Unmarshal(raw, &g); err != nil {
			return "", "", nil, 0, fmt.Errorf("parse grype report: %w", err)
		}
		image = grypeTarget(g.Source.Target)
		for _, m := range g.Matches {
			add(mapEcosystem(m.Artifact.Type), m.Artifact.Name, m.Artifact.Version)
		}
	case probe["Results"] != nil || probe["ArtifactName"] != nil:
		format = "trivy"
		var tv trivyReport
		if err = json.Unmarshal(raw, &tv); err != nil {
			return "", "", nil, 0, fmt.Errorf("parse trivy report: %w", err)
		}
		image = tv.ArtifactName
		for _, r := range tv.Results {
			eco := mapEcosystem(r.Type)
			// Prefer the full package list when present; otherwise fall back to
			// the packages named in the vulnerability findings.
			if len(r.Packages) > 0 {
				for _, p := range r.Packages {
					add(eco, p.Name, p.Version)
				}
			} else {
				for _, v := range r.Vulnerabilities {
					add(eco, v.PkgName, v.InstalledVersion)
				}
			}
		}
	default:
		return "", "", nil, 0, fmt.Errorf("unrecognized scan format (expected Trivy or Grype JSON)")
	}

	return format, image, pkgs, skippedOS, nil
}

func grypeTarget(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// target may be a plain string or an object with userInput.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		UserInput string `json:"userInput"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.UserInput
	}
	return ""
}

// scanPackages queries OSV for each package concurrently and returns all
// matching vulnerabilities as ScanRows, sorted highest-severity first.
func (a *App) scanPackages(ctx context.Context, pkgs []pkgRef) []ScanRow {
	sem := make(chan struct{}, scanConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rows []ScanRow

	for _, p := range pkgs {
		wg.Add(1)
		sem <- struct{}{}
		go func(p pkgRef) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns, err := a.osvQueryPackage(ctx, p.Ecosystem, p.Name, p.Version)
			if err != nil || len(vulns) == 0 {
				return
			}
			local := make([]ScanRow, 0, len(vulns))
			for _, v := range vulns {
				label := severityLabel(v)
				local = append(local, ScanRow{
					Package:       p.Name,
					Ecosystem:     p.Ecosystem,
					Version:       p.Version,
					ID:            v.ID,
					CVE:           cveOf(v),
					Severity:      label,
					SeverityScore: severityScore(label),
					FixedVersion:  fixedVersion(v),
					Summary:       summaryOf(v),
					URL:           primaryURL(v),
				})
			}
			mu.Lock()
			rows = append(rows, local...)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].SeverityScore != rows[j].SeverityScore {
			return rows[i].SeverityScore > rows[j].SeverityScore
		}
		return rows[i].Package < rows[j].Package
	})
	return rows
}
