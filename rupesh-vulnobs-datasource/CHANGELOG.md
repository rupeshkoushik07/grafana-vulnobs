# Changelog

## 0.1.0

First release.

### Features

- Backend data source that queries [OSV](https://osv.dev) live for vulnerabilities affecting
  a package (ecosystem + name + optional version) or a single CVE / GHSA / OSV id.
- Returns a vulnerabilities table (id, cve, severity, severity_score, cvss, summary,
  fixed_version, published, modified, url) usable in dashboards, Explore, and — because it has
  a backend — Grafana alert rules.
- Config editor for the OSV base URL (optional API key reserved for future NVD / GitHub
  Advisory enrichment) and a health check that pings OSV live.
