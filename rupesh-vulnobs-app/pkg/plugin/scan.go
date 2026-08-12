package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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

	// Exploit-context enrichment (EPSS + CISA KEV), filled by enrichRows.
	EPSS     float64 `json:"epss"`
	KEV      bool    `json:"kev"`
	Priority int     `json:"priority"`
	Action   string  `json:"action"`
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

// parsePurl parses a Package URL (purl) into an OSV-mapped pkgRef.
// e.g. "pkg:npm/%40angular/core@12.0.0" -> {npm, @angular/core, 12.0.0}.
// Returns ok=false for types OSV can't resolve.
// Spec: https://github.com/package-url/purl-spec
func parsePurl(purl string) (pkgRef, bool) {
	s := strings.TrimSpace(purl)
	if !strings.HasPrefix(s, "pkg:") {
		return pkgRef{}, false
	}
	s = strings.TrimPrefix(s, "pkg:")

	// Strip subpath (#...) then split off qualifiers (?...).
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	var qualifiers string
	if i := strings.IndexByte(s, '?'); i >= 0 {
		qualifiers = s[i+1:]
		s = s[:i]
	}

	// Split version off the end (last '@').
	version := ""
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		version = s[i+1:]
		s = s[:i]
	}

	// s is now "type/namespace.../name".
	typ, rest, ok := strings.Cut(s, "/")
	if !ok {
		return pkgRef{}, false
	}
	namespace, name := "", rest
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		namespace, name = rest[:i], rest[i+1:]
	}

	namespace = urlDecode(namespace)
	name = urlDecode(name)
	version = urlDecode(version)

	eco := purlEcosystem(typ, qualifiers)
	if eco == "" {
		return pkgRef{}, false
	}

	// Construct the OSV package name per ecosystem naming rules.
	full := name
	switch strings.ToLower(typ) {
	case "golang", "composer", "npm":
		if namespace != "" {
			full = namespace + "/" + name
		}
	case "maven":
		if namespace != "" {
			full = namespace + ":" + name
		}
	}
	return pkgRef{Ecosystem: eco, Name: full, Version: version}, true
}

// purlEcosystem maps a purl type (plus qualifiers, for OS packages) to an OSV
// ecosystem, or "" if unsupported.
func purlEcosystem(typ, qualifiers string) string {
	t := strings.ToLower(typ)
	switch t {
	case "deb":
		if d := distroVersion(qualifiers, "debian-"); d != "" {
			return "Debian:" + d
		}
		return ""
	case "apk":
		if d := distroVersion(qualifiers, "alpine-"); d != "" {
			return "Alpine:v" + d
		}
		return ""
	case "golang":
		t = "go"
	case "pypi":
		t = "python"
	}
	// Language types resolve through the shared scanner-ecosystem table.
	return mapEcosystem(t)
}

// distroVersion pulls e.g. "11" from "distro=debian-11" or "3.18" from
// "distro=alpine-3.18.4" (major.minor) in a purl qualifier string.
func distroVersion(qualifiers, prefix string) string {
	for _, kv := range strings.Split(qualifiers, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k != "distro" {
			continue
		}
		if !strings.HasPrefix(v, prefix) {
			return ""
		}
		ver := strings.TrimPrefix(v, prefix)
		if prefix == "alpine-" {
			parts := strings.Split(ver, ".")
			if len(parts) >= 2 {
				return parts[0] + "." + parts[1]
			}
		}
		return ver
	}
	return ""
}

func urlDecode(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
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

// --- CycloneDX SBOM ---

type cyclonedxBOM struct {
	Metadata struct {
		Component struct {
			Name string `json:"name"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"components"`
}

// --- SPDX SBOM ---

type spdxDoc struct {
	Name     string `json:"name"`
	Packages []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
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
	// addPurl adds a package from a purl, or counts it as skipped when the purl
	// is absent or its ecosystem isn't one OSV can resolve.
	addPurl := func(purl string) {
		if p, ok := parsePurl(purl); ok {
			add(p.Ecosystem, p.Name, p.Version)
			return
		}
		skippedOS++
	}

	switch {
	case probe["bomFormat"] != nil || probe["components"] != nil:
		format = "cyclonedx"
		var b cyclonedxBOM
		if err = json.Unmarshal(raw, &b); err != nil {
			return "", "", nil, 0, fmt.Errorf("parse CycloneDX SBOM: %w", err)
		}
		image = b.Metadata.Component.Name
		for _, c := range b.Components {
			addPurl(c.PURL)
		}
	case probe["spdxVersion"] != nil || probe["SPDXID"] != nil:
		format = "spdx"
		var doc spdxDoc
		if err = json.Unmarshal(raw, &doc); err != nil {
			return "", "", nil, 0, fmt.Errorf("parse SPDX SBOM: %w", err)
		}
		image = doc.Name
		for _, p := range doc.Packages {
			purl := ""
			for _, ref := range p.ExternalRefs {
				if strings.EqualFold(ref.ReferenceType, "purl") {
					purl = ref.ReferenceLocator
					break
				}
			}
			addPurl(purl)
		}
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
		return "", "", nil, 0, fmt.Errorf("unrecognized format (expected Trivy, Grype, CycloneDX, or SPDX JSON)")
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

// enrichRows adds EPSS + KEV exploit intel to each row, sets a priority, and
// re-sorts the rows so the ones that actually matter float to the top.
func (a *App) enrichRows(ctx context.Context, rows []ScanRow) {
	cves := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.CVE != "" {
			cves = append(cves, r.CVE)
		}
	}
	intel := a.enrichCVEs(ctx, cves)
	for i := range rows {
		it := intel[rows[i].CVE]
		rows[i].EPSS = it.EPSS
		rows[i].KEV = it.KEV
		rows[i].Priority = priorityScore(rows[i].SeverityScore, it.EPSS, it.KEV)
		rows[i].Action = actionLabel(it.EPSS, it.KEV)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return rows[i].Priority > rows[j].Priority
		}
		return rows[i].Package < rows[j].Package
	})
}
