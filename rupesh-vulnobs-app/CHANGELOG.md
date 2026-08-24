# Changelog

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
