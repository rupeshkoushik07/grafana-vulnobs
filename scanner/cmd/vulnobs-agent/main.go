// Command vulnobs-agent lets the Vulnobs app's "Scan now" button work when
// Grafana runs outside the cluster. It polls the app for scan requests, starts
// the scan CronJob for each, and reports the CronJob's runs back, so Grafana
// never needs to reach the Kubernetes API.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rupeshkoushik07/grafana-vulnobs/scanner/pkg/agent"
)

func main() {
	api := flag.String("api", os.Getenv("VULNOBS_API"),
		"the app's resource API: <grafana>/api/plugins/rupeshkoushik07-vulnobs-app/resources (env VULNOBS_API)")
	cronJob := flag.String("cronjob", "vulnobs-scan", "name of the scan CronJob")
	namespace := flag.String("namespace", "", "namespace of the scan CronJob (default: the service account's)")
	interval := flag.Duration("interval", 10*time.Second, "how often to poll the app")
	saDir := flag.String("serviceaccount-dir", "/var/run/secrets/kubernetes.io/serviceaccount",
		"directory holding the service account token and ca.crt")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	// Secrets come from the environment only, so they don't show up in the
	// pod spec or the process list.
	scannerToken := strings.TrimSpace(os.Getenv("VULNOBS_SCANNER_TOKEN"))
	if scannerToken == "" {
		log.Fatal("vulnobs-agent: VULNOBS_SCANNER_TOKEN is not set; it must match the scanner token in the app's configuration")
	}
	if u, err := url.Parse(*api); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		log.Fatalf("vulnobs-agent: -api (or VULNOBS_API) must be the app's resource URL, got %q", *api)
	}
	if *interval < time.Second {
		log.Fatal("vulnobs-agent: -interval must be at least 1s")
	}
	if *namespace == "" {
		raw, err := os.ReadFile(filepath.Join(*saDir, "namespace"))
		if err != nil {
			log.Fatalf("vulnobs-agent: no -namespace given and none mounted: %v", err)
		}
		*namespace = strings.TrimSpace(string(raw))
	}

	kube, err := agent.InCluster(filepath.Join(*saDir, "token"), filepath.Join(*saDir, "ca.crt"), *namespace, *cronJob)
	if err != nil {
		log.Fatalf("vulnobs-agent: %v", err)
	}
	a := &agent.Agent{
		Kube: kube,
		App: &agent.App{
			BaseURL:      *api,
			ScannerToken: scannerToken,
			GrafanaToken: strings.TrimSpace(os.Getenv("VULNOBS_GRAFANA_TOKEN")),
			HTTP: &http.Client{
				Timeout: 15 * time.Second,
				// A redirect (to a login page, say) is a failure, not an answer.
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			},
		},
		Interval: *interval,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("vulnobs-agent: polling %s every %s for CronJob %s/%s", *api, *interval, *namespace, *cronJob)
	a.Run(ctx)
}
