package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/instancemgmt"
	"github.com/grafana/grafana-plugin-sdk-go/backend/resource/httpadapter"
)

// Make sure App implements required interfaces. This is important to do
// since otherwise we will only get a not implemented error response from plugin in
// runtime. Plugin should not implement all these interfaces - only those which are
// required for a particular task.
var (
	_ backend.CallResourceHandler   = (*App)(nil)
	_ instancemgmt.InstanceDisposer = (*App)(nil)
	_ backend.CheckHealthHandler    = (*App)(nil)
)

// App is the Vulnobs app backend. It exposes resources the app pages call to
// browse and search public vulnerability feeds (OSV).
type App struct {
	backend.CallResourceHandler
	baseURL    string
	httpClient *http.Client
	store      *assetStore
	storeErr   error // why the store couldn't open its data directory, if it couldn't
	kev        *kevCache
}

// appSettings is the app's jsonData.
type appSettings struct {
	// OsvBaseURL overrides the OSV API base URL.
	OsvBaseURL string `json:"osvBaseUrl"`
	// DataDir is where ingested scans are saved so they survive restarts. Grafana
	// doesn't tell plugins its data path, so this must be set; when it isn't,
	// scans are kept in memory only.
	DataDir string `json:"dataDir"`
}

// NewApp creates a new *App instance.
func NewApp(_ context.Context, settings backend.AppInstanceSettings) (instancemgmt.Instance, error) {
	var cfg appSettings
	if len(settings.JSONData) > 0 {
		if err := json.Unmarshal(settings.JSONData, &cfg); err != nil {
			backend.Logger.Warn("Ignoring invalid app jsonData", "error", err)
		}
	}

	app := App{
		baseURL:    DefaultOsvBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		kev:        newKevCache(),
	}
	if cfg.OsvBaseURL != "" {
		app.baseURL = strings.TrimRight(cfg.OsvBaseURL, "/")
	}

	app.store, app.storeErr = newAssetStore(strings.TrimSpace(cfg.DataDir))
	if app.storeErr != nil {
		backend.Logger.Error("Could not open the ingested scan store", "dataDir", cfg.DataDir, "error", app.storeErr)
	}

	// Use a httpadapter (provided by the SDK) for resource calls. This allows us
	// to use a *http.ServeMux for resource calls, so we can map multiple routes
	// to CallResource without having to implement extra logic.
	mux := http.NewServeMux()
	app.registerRoutes(mux)
	app.CallResourceHandler = httpadapter.New(mux)

	return &app, nil
}

// Dispose here tells plugin SDK that plugin wants to clean up resources when a new instance
// created.
func (a *App) Dispose() {
	// cleanup
}

// CheckHealth reports whether ingested scans are being saved to disk.
func (a *App) CheckHealth(_ context.Context, _ *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if a.storeErr != nil {
		return &backend.CheckHealthResult{
			Status:  backend.HealthStatusError,
			Message: fmt.Sprintf("Ingested scan store: %v", a.storeErr),
		}, nil
	}
	if persistent, dir := a.store.persistent(); persistent {
		return &backend.CheckHealthResult{
			Status:  backend.HealthStatusOk,
			Message: fmt.Sprintf("Ingested scans are saved in %s", dir),
		}, nil
	}
	return &backend.CheckHealthResult{
		Status:  backend.HealthStatusOk,
		Message: "Ingested scans are kept in memory only; set dataDir in the app's jsonData to keep them across restarts",
	}, nil
}
