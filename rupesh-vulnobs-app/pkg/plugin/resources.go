package plugin

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// maxScanBytes caps the size of an uploaded scan report (25 MiB).
const maxScanBytes = 25 << 20

// handleSearch queries the OSV feed and returns matching vulnerabilities.
//
// Query params:
//   - vulnId:    look up a single CVE / GHSA / OSV id directly (takes precedence)
//   - ecosystem: package ecosystem, e.g. npm, Go, PyPI (used with package)
//   - package:   package name, e.g. lodash
//   - version:   optional; limit to vulns affecting this version
func (a *App) handleSearch(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	vulnID := strings.TrimSpace(q.Get("vulnId"))
	ecosystem := strings.TrimSpace(q.Get("ecosystem"))
	pkg := strings.TrimSpace(q.Get("package"))
	version := strings.TrimSpace(q.Get("version"))

	ctx := req.Context()

	// Mode 1: direct lookup by id.
	if vulnID != "" {
		v, err := a.osvGetVuln(ctx, vulnID)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, map[string]any{"vulns": toRows([]osvVuln{*v})})
		return
	}

	// Mode 2: package query.
	if pkg == "" {
		writeError(w, http.StatusBadRequest, "provide a package name (with ecosystem) or a vulnId")
		return
	}

	vulns, err := a.osvQueryPackage(ctx, ecosystem, pkg, version)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{"vulns": toRows(vulns)})
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// handleScan ingests a Trivy or Grype JSON report, extracts its package
// inventory, and matches every package against live OSV data. Because it
// re-queries OSV rather than trusting the scan's embedded findings, the result
// reflects vulnerabilities known *right now* — including ones published after
// the scan was taken.
func (a *App) handleScan(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST with a Trivy or Grype JSON body")
		return
	}

	raw, err := io.ReadAll(io.LimitReader(req.Body, maxScanBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}

	format, image, pkgs, skippedOS, err := parseScan(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	truncated := false
	queried := pkgs
	if len(queried) > maxPackages {
		queried = queried[:maxPackages]
		truncated = true
	}

	rows := a.scanPackages(req.Context(), queried)

	// Count distinct vulnerable packages.
	vulnPkgs := map[string]bool{}
	for _, r := range rows {
		vulnPkgs[r.Ecosystem+"\x00"+r.Package+"\x00"+r.Version] = true
	}

	writeJSON(w, map[string]any{
		"format":             format,
		"image":              image,
		"packagesScanned":    len(pkgs),
		"packagesQueried":    len(queried),
		"vulnerablePackages": len(vulnPkgs),
		"skippedOsPackages":  skippedOS,
		"truncated":          truncated,
		"rows":               rows,
	})
}

// registerRoutes maps HTTP handlers onto the app's resource mux.
func (a *App) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/search", a.handleSearch)
	mux.HandleFunc("/scan", a.handleScan)
}
