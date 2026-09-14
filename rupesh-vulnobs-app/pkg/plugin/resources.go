package plugin

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
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
		writeJSON(w, map[string]any{"vulns": toRows([]osvVuln{*v}, "", "")})
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
	writeJSON(w, map[string]any{"vulns": toRows(vulns, pkg, version)})
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
	a.enrichRows(req.Context(), rows)

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

// handleIngest accepts a scan/SBOM pushed by an external scanner (a CronJob or CI
// step), matches it against live OSV, and stores it as the latest posture for the
// named asset. This is what turns manual uploads into continuous monitoring.
//
//	POST /resources/ingest?asset=<name>[&source=<who>][&namespaces=<a,b>]
//
// source records who pushed the scan ("cluster" for the scan CronJob, "api" by
// default) so /prune can remove stale assets of one source only. namespaces
// lists where the image runs.
func (a *App) handleIngest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST with a scan/SBOM body")
		return
	}
	q := req.URL.Query()
	asset := strings.TrimSpace(q.Get("asset"))
	if asset == "" {
		writeError(w, http.StatusBadRequest, "missing required 'asset' query parameter")
		return
	}
	source := strings.TrimSpace(q.Get("source"))
	if source == "" {
		source = "api"
	}

	raw, err := io.ReadAll(io.LimitReader(req.Body, maxScanBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}

	format, _, pkgs, _, err := parseScan(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(pkgs) > maxPackages {
		pkgs = pkgs[:maxPackages]
	}

	rows := a.scanPackages(req.Context(), pkgs)
	a.enrichRows(req.Context(), rows)
	posture, err := a.store.put(asset, source, format, splitList(q.Get("namespaces")), rows)

	resp := map[string]any{
		"asset":       posture.Asset,
		"source":      posture.Source,
		"format":      posture.Format,
		"total":       posture.Total,
		"kev":         posture.KEV,
		"counts":      posture.Counts,
		"lastScanned": posture.LastScanned,
	}
	if err != nil {
		backend.Logger.Warn("Ingested scan kept in memory but not saved to disk", "asset", asset, "error", err)
		resp["warning"] = "kept in memory but not saved to disk: " + err.Error()
	}
	writeJSON(w, resp)
}

// handleAssets returns the current posture of every ingested asset (summary only).
func (a *App) handleAssets(w http.ResponseWriter, _ *http.Request) {
	persistent, dir := a.store.persistent()
	storage := map[string]any{"persistent": persistent}
	if persistent {
		storage["dataDir"] = dir
	}
	writeJSON(w, map[string]any{"assets": a.store.list(), "storage": storage})
}

// handleAsset returns the full posture (including per-vulnerability rows) for one
// asset: GET /resources/asset?name=<name>
func (a *App) handleAsset(w http.ResponseWriter, req *http.Request) {
	name := strings.TrimSpace(req.URL.Query().Get("name"))
	p, ok := a.store.get(name)
	if !ok {
		writeError(w, http.StatusNotFound, "no posture stored for that asset")
		return
	}
	writeJSON(w, p)
}

// handlePrune removes assets from one source that are no longer present, e.g.
// images the scan CronJob no longer finds running in the cluster.
//
//	POST /resources/prune   body: {"source": "cluster", "keep": ["python:3.12", ...]}
func (a *App) handlePrune(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST with {\"source\": ..., \"keep\": [...]}")
		return
	}
	var body struct {
		Source string   `json:"source"`
		Keep   []string `json:"keep"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(body.Source) == "" {
		writeError(w, http.StatusBadRequest, "'source' is required, so only that source's assets are pruned")
		return
	}
	removed, err := a.store.prune(body.Source, body.Keep)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"removed": removed})
}

// handleEnrich adds exploit context (EPSS + CISA KEV + a priority) to a list of
// CVE ids. This is the engine other surfaces (and the panel plugin) call to turn
// a flat CVE list into a ranked "fix these first" order.
//
//	POST /resources/enrich   body: {"cves": ["CVE-2021-44228", ...]}
func (a *App) handleEnrich(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST with {\"cves\": [...]}")
		return
	}
	var body struct {
		CVEs []string `json:"cves"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	intel := a.enrichCVEs(req.Context(), body.CVEs)
	writeJSON(w, map[string]any{"intel": intel})
}

// splitList splits a comma-separated list, dropping empty items.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// registerRoutes maps HTTP handlers onto the app's resource mux.
func (a *App) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/search", a.handleSearch)
	mux.HandleFunc("/scan", a.handleScan)
	mux.HandleFunc("/ingest", a.handleIngest)
	mux.HandleFunc("/assets", a.handleAssets)
	mux.HandleFunc("/asset", a.handleAsset)
	mux.HandleFunc("/prune", a.handlePrune)
	mux.HandleFunc("/enrich", a.handleEnrich)
}
