package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	storeErr   error
	kev        *kevCache
}

// appSettings is the app's jsonData.
type appSettings struct {
	StorageURL string `json:"storageUrl"`
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
		baseURL: DefaultOsvBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		kev: newKevCache(),
	}
	app.store, app.storeErr = newAssetStore(cfg.StorageURL, settings.DecryptedSecureJSONData["storageToken"], app.httpClient)

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

// CheckHealth reports whether the authenticated storage service is reachable.
func (a *App) CheckHealth(ctx context.Context, _ *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if a.storeErr != nil {
		return &backend.CheckHealthResult{
			Status:  backend.HealthStatusError,
			Message: fmt.Sprintf("Ingested scan store: %v", a.storeErr),
		}, nil
	}
	if err := a.store.check(ctx); err != nil {
		return &backend.CheckHealthResult{
			Status:  backend.HealthStatusError,
			Message: fmt.Sprintf("Authenticated storage API unavailable: %v", err),
		}, nil
	}
	return &backend.CheckHealthResult{
		Status:  backend.HealthStatusOk,
		Message: "Connected to the authenticated storage API",
	}, nil
}
