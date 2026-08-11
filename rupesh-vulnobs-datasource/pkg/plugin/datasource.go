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
	"github.com/rupesh/vulnobs/pkg/models"
)

// Make sure Datasource implements required interfaces. This is important to do
// since otherwise we will only get a not implemented error response from plugin in
// runtime. In this example datasource instance implements backend.QueryDataHandler,
// backend.CheckHealthHandler interfaces. Plugin should not implement all these
// interfaces - only those which are required for a particular task.
var (
	_ backend.QueryDataHandler      = (*Datasource)(nil)
	_ backend.CheckHealthHandler    = (*Datasource)(nil)
	_ instancemgmt.InstanceDisposer = (*Datasource)(nil)
)

// NewDatasource creates a new datasource instance.
func NewDatasource(_ context.Context, s backend.DataSourceInstanceSettings) (instancemgmt.Instance, error) {
	settings, err := models.LoadPluginSettings(s)
	if err != nil {
		return nil, err
	}
	return &Datasource{
		baseURL:    strings.TrimRight(settings.OsvBaseURL, "/"),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Datasource queries public vulnerability feeds (OSV) and returns the results as
// Grafana data frames.
type Datasource struct {
	baseURL    string
	httpClient *http.Client
}

// Dispose here tells plugin SDK that plugin wants to clean up resources when a new instance
// created. As soon as datasource settings change detected by SDK old datasource instance will
// be disposed and a new one will be created using NewSampleDatasource factory function.
func (d *Datasource) Dispose() {
	// Clean up datasource instance resources.
}

// QueryData handles multiple queries and returns multiple responses.
// req contains the queries []DataQuery (where each query contains RefID as a unique identifier).
// The QueryDataResponse contains a map of RefID to the response for each query, and each response
// contains Frames ([]*Frame).
func (d *Datasource) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	// create response struct
	response := backend.NewQueryDataResponse()

	// loop over queries and execute them individually.
	for _, q := range req.Queries {
		res := d.query(ctx, req.PluginContext, q)

		// save the response in a hashmap
		// based on with RefID as identifier
		response.Responses[q.RefID] = res
	}

	return response, nil
}

type queryModel struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
	VulnID    string `json:"vulnId"`
}

func (d *Datasource) query(ctx context.Context, _ backend.PluginContext, query backend.DataQuery) backend.DataResponse {
	var response backend.DataResponse

	var qm queryModel
	if len(query.JSON) > 0 {
		if err := json.Unmarshal(query.JSON, &qm); err != nil {
			return backend.ErrDataResponse(backend.StatusBadRequest, fmt.Sprintf("json unmarshal: %v", err.Error()))
		}
	}

	qm.Ecosystem = strings.TrimSpace(qm.Ecosystem)
	qm.Package = strings.TrimSpace(qm.Package)
	qm.Version = strings.TrimSpace(qm.Version)
	qm.VulnID = strings.TrimSpace(qm.VulnID)

	// Mode 1: direct lookup of a single vulnerability by id (CVE / GHSA / OSV id).
	if qm.VulnID != "" {
		v, err := d.osvGetVuln(ctx, qm.VulnID)
		if err != nil {
			return backend.ErrDataResponse(backend.StatusInternal, fmt.Sprintf("OSV lookup failed: %v", err))
		}
		response.Frames = append(response.Frames, vulnsToFrame("vulnerabilities", []osvVuln{*v}))
		return response
	}

	// Mode 2: all vulnerabilities affecting a package (optionally a version).
	if qm.Package == "" {
		return backend.ErrDataResponse(backend.StatusBadRequest, "provide a package name (with ecosystem) or a vulnerability id")
	}

	vulns, err := d.osvQueryPackage(ctx, qm.Ecosystem, qm.Package, qm.Version)
	if err != nil {
		return backend.ErrDataResponse(backend.StatusInternal, fmt.Sprintf("OSV query failed: %v", err))
	}

	response.Frames = append(response.Frames, vulnsToFrame("vulnerabilities", vulns))
	return response
}

// CheckHealth handles health checks sent from Grafana to the plugin.
// The main use case for these health checks is the test button on the
// datasource configuration page which allows users to verify that
// a datasource is working as expected.
func (d *Datasource) CheckHealth(ctx context.Context, _ *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	// A lightweight live query confirms we can reach and parse the OSV API.
	if _, err := d.osvQueryPackage(ctx, "npm", "lodash", ""); err != nil {
		return &backend.CheckHealthResult{
			Status:  backend.HealthStatusError,
			Message: fmt.Sprintf("Could not reach OSV at %s: %v", d.baseURL, err),
		}, nil
	}

	return &backend.CheckHealthResult{
		Status:  backend.HealthStatusOk,
		Message: fmt.Sprintf("Connected to OSV at %s", d.baseURL),
	}, nil
}
