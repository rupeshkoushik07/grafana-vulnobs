package plugin

import (
	"context"
	"encoding/json"
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
	kev        *kevCache
}

// NewApp creates a new *App instance.
func NewApp(_ context.Context, settings backend.AppInstanceSettings) (instancemgmt.Instance, error) {
	app := App{
		baseURL:    DefaultOsvBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		store:      newAssetStore(),
		kev:        newKevCache(),
	}

	// Optional override of the OSV base URL via the app's jsonData.
	if len(settings.JSONData) > 0 {
		var cfg struct {
			OsvBaseURL string `json:"osvBaseUrl"`
		}
		if err := json.Unmarshal(settings.JSONData, &cfg); err == nil && cfg.OsvBaseURL != "" {
			app.baseURL = strings.TrimRight(cfg.OsvBaseURL, "/")
		}
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

// CheckHealth handles health checks sent from Grafana to the plugin.
func (a *App) CheckHealth(_ context.Context, _ *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	return &backend.CheckHealthResult{
		Status:  backend.HealthStatusOk,
		Message: "ok",
	}, nil
}
