package models

import (
	"encoding/json"
	"fmt"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

// DefaultOsvBaseURL is the public OSV.dev API. https://osv.dev
const DefaultOsvBaseURL = "https://api.osv.dev"

type PluginSettings struct {
	// OsvBaseURL is the base URL of the OSV API. Defaults to DefaultOsvBaseURL.
	OsvBaseURL string                `json:"osvBaseUrl"`
	Secrets    *SecretPluginSettings `json:"-"`
}

type SecretPluginSettings struct {
	// ApiKey is reserved for enrichment feeds (NVD / GitHub Advisory) in a later
	// phase. OSV itself requires no authentication.
	ApiKey string `json:"apiKey"`
}

func LoadPluginSettings(source backend.DataSourceInstanceSettings) (*PluginSettings, error) {
	settings := PluginSettings{}
	err := json.Unmarshal(source.JSONData, &settings)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal PluginSettings json: %w", err)
	}

	if settings.OsvBaseURL == "" {
		settings.OsvBaseURL = DefaultOsvBaseURL
	}

	settings.Secrets = loadSecretPluginSettings(source.DecryptedSecureJSONData)

	return &settings, nil
}

func loadSecretPluginSettings(source map[string]string) *SecretPluginSettings {
	return &SecretPluginSettings{
		ApiKey: source["apiKey"],
	}
}
