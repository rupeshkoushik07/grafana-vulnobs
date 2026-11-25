# Changelog

## Unreleased

### Features

- **The scan job's pod on the Assets page** — while a cluster scan runs, the workloads view
  shows the scan job's own pod in a *Scanning now* box: its name, its namespace, the step
  it is on (finding the images, building the SBOMs, sending them) and the images it runs.
  It comes from the pod list the view already reads, so it needs no new permission; in
  remote mode the box is not shown.
- **Remote mode: Grafana outside the cluster** — with `clusterMode: remote` the app needs
  no access to the Kubernetes API. The workloads view is built from kube-state-metrics
  series, queried through a Prometheus data source chosen in the app's configuration, and
  **Scan now** records a request that the new in-cluster scan agent (`vulnobs-agent`) picks
  up, authenticated with a scanner token. The default mode is unchanged.
- **Workloads view** — with the deployment's opt-in `showWorkloads` setting, the Assets page
  lists what is running in the cluster (workload, namespace, pods, image) next to its
  findings, and marks what has not been scanned yet. `GET /resources/workloads` is the API
  behind it; it needs to list pods and nothing else.
- **Scan now** — a button on the Assets page starts the cluster scan CronJob on demand,
  shows the run, and refreshes the list when it finishes. Needs the deployment's opt-in
  `scanNow` setting; `GET`/`POST /resources/cluster-scan` is the API behind it.
- **CycloneDX from the cluster scan** — the scan job now pushes a CycloneDX SBOM of each
  image instead of a Trivy vulnerability report, so every finding comes from the app's own
  matching against OSV.
- **Pinned to what runs** — the scan job reads each image by the digest its containers are
  running, not by a tag that may have moved.

### Fixes

- Update `golang.org/x/net` to 0.62.0 (CVE-2026-78661, CVE-2026-78669).
- Scans are no longer cut off at 200 packages. Up to 5,000 are checked, using OSV's batch
  endpoint to find the affected ones first, so large images cost a few requests instead of
  one per package.

## 0.5.2

### Security and reliability

- Replace plugin-local JSON persistence with the authenticated VulnObs Storage API.
- Enforce tenant-scoped asset access and configurable finding retention.
- Update Jest tooling and remove the webpack-only ESLint hook to drop the vulnerable `braces` dependency.
- Keep linting enforced through `npm run lint` and CI.
- Upgrade the Storage API's `golang.org/x/text` dependency to a patched release.

## 0.2.0

### Features

- **Risk-based prioritization** — every CVE is enriched with **EPSS** (exploit probability)
  and **CISA KEV** (actively exploited) and given a priority score (`KEV > EPSS > severity`),
  so findings are ranked by real risk rather than severity alone.
- Scan results now show a Priority column (🔥 actively exploited, now/urgent/soon/backlog),
  EPSS %, and an "actively exploited" callout.
- **SBOM support** — Scan accepts CycloneDX and SPDX in addition to Trivy and Grype.
- **Continuous ingest** — `POST /resources/ingest?asset=<name>` stores the latest prioritized
  posture per asset (for scanners pushing on a schedule).
- `/resources/enrich` exposes the EPSS + KEV engine on its own.

## 0.1.0

First release.

### Features

- **Search page** — query [OSV](https://osv.dev) live by ecosystem + package (npm, Go,
  PyPI, Maven, and more) or by CVE / GHSA id, with a severity summary and click-to-filter.
- **Scan page** — upload a Trivy or Grype JSON report; the backend extracts the package
  inventory and matches every package against live OSV, so results reflect the
  vulnerabilities known now rather than the scan's snapshot.
- Go backend resource endpoints (`/search`, `/scan`) that call OSV directly with bounded
  concurrency and OS-package filtering.
