# Changelog

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
