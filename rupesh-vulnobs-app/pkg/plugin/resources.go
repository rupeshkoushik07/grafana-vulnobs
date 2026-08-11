package plugin

import (
	"encoding/json"
	"net/http"
	"strings"
)

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

// registerRoutes maps HTTP handlers onto the app's resource mux.
func (a *App) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/search", a.handleSearch)
}
