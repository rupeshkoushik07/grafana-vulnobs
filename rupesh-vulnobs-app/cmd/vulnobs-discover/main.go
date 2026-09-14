// Command vulnobs-discover lists the container images running in the cluster
// and writes the inputs for the Vulnobs scan CronJob: the images to scan with
// their /ingest query strings, and the /prune request that drops assets no
// longer running. It runs in the scan job with a service account that can list
// pods.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rupesh/vulnobs/pkg/discover"
)

func main() {
	exclude := flag.String("exclude-namespaces", "kube-system,kube-public,kube-node-lease",
		"comma-separated namespaces whose pods are not scanned")
	targetsPath := flag.String("targets", "/work/targets.tsv", "file to write image and ingest query lines to")
	prunePath := flag.String("prune", "/work/prune.json", "file to write the /prune request body to")
	saDir := flag.String("serviceaccount-dir", "/var/run/secrets/kubernetes.io/serviceaccount",
		"directory holding the service account token and ca.crt")
	flag.Parse()

	if err := run(*exclude, *targetsPath, *prunePath, *saDir); err != nil {
		log.Fatalf("vulnobs-discover: %v", err)
	}
}

func run(exclude, targetsPath, prunePath, saDir string) error {
	client, err := discover.InCluster(filepath.Join(saDir, "token"), filepath.Join(saDir, "ca.crt"))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	images, err := client.Images(ctx, strings.Split(exclude, ","))
	if err != nil {
		return err
	}

	targets, err := os.Create(targetsPath)
	if err != nil {
		return err
	}
	if err := discover.WriteTargets(targets, images); err != nil {
		_ = targets.Close()
		return err
	}
	if err := targets.Close(); err != nil {
		return err
	}

	body, err := discover.PruneRequest(images)
	if err != nil {
		return err
	}
	if err := os.WriteFile(prunePath, body, 0o644); err != nil {
		return err
	}

	fmt.Printf("found %d images outside namespaces [%s]\n", len(images), exclude)
	for _, img := range images {
		fmt.Printf("  %s (%s)\n", img.Ref, strings.Join(img.Namespaces, ", "))
	}
	return nil
}
