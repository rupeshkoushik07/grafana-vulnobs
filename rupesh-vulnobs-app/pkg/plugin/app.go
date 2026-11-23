package plugin

import (
	"context"
	"encoding/json"
	"errors"
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
	storeErr   error
	kev        *kevCache
	// cluster starts the scan CronJob on demand; nil when Grafana has no
	// Kubernetes service account, with clusterErr saying why if it's a fault.
	cluster    *clusterScanner
	clusterErr error
	// excludeNamespaces are left out of the workloads list; nil means "what
	// the scan job skips".
	excludeNamespaces []string

	// Remote mode (clusterMode "remote"): Grafana runs anywhere and never
	// talks to Kubernetes. Workloads come from kube-state-metrics through a
	// Prometheus data source, and "Scan now" is a request the in-cluster scan
	// agent picks up.
	remote          bool
	prometheusUID   string
	metricsSelector string
	scannerToken    string
	scans           *scanQueue
}

// appSettings is the app's jsonData.
type appSettings struct {
	StorageURL string `json:"storageUrl"`

	// "Scan now". All optional: the defaults fit the Tanka deployment.
	ScanCronJob         string `json:"scanCronJob"`         // default "vulnobs-scan"
	KubernetesNamespace string `json:"kubernetesNamespace"` // default: the service account's
	KubernetesAPIServer string `json:"kubernetesApiServer"` // default: the in-cluster address

	// Namespaces left out of the workloads list. Default: the ones the scan
	// CronJob skips, read from the CronJob when the app may read it; set this
	// only to make the page differ from the scan.
	ExcludeNamespaces []string `json:"excludeNamespaces"`

	// ClusterMode says how the app learns about the cluster. "" or
	// "in-cluster" (the default): through the Kubernetes API, with the pod's
	// service account. "remote": without any Kubernetes access.
	ClusterMode string `json:"clusterMode"`
	// Remote mode: UID of the Prometheus data source holding
	// kube-state-metrics series, and an optional label matcher list added to
	// every query, e.g. `cluster="prod"`.
	PrometheusDatasourceUID string `json:"prometheusDatasourceUid"`
	MetricsSelector         string `json:"metricsSelector"`
}

// clusterModeRemote is the clusterMode in which Grafana needs no access to
// the Kubernetes API.
const clusterModeRemote = "remote"

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
	if strings.TrimSpace(cfg.ClusterMode) == clusterModeRemote {
		app.remote = true
		app.prometheusUID = strings.TrimSpace(cfg.PrometheusDatasourceUID)
		app.metricsSelector = strings.TrimSpace(cfg.MetricsSelector)
		app.scannerToken = strings.TrimSpace(settings.DecryptedSecureJSONData["scannerToken"])
		app.scans = sharedScanQueue(app.scannerToken)
	} else if cluster, err := newClusterScanner(cfg, defaultServiceAccountDir); err == nil {
		app.cluster = cluster
	} else if !errors.Is(err, errNoServiceAccount) {
		backend.Logger.Warn("Scan now is unavailable", "error", err)
		app.clusterErr = err
	}
	app.excludeNamespaces = cfg.ExcludeNamespaces
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
