# OSV fixtures

Real responses from the OSV API, captured on 2026-09-15 and trimmed to the fields
the plugin reads. They cover the cases `advisory.go` handles: one CVE reported by
several databases (GHSA plus PYSEC or GO records), records with a CVSS vector but
no severity label, git-commit fix events, and advisories fixed on several release
lines.

| File | Request |
| --- | --- |
| `requests.json` | `POST /v1/query` PyPI `requests` 2.19.0 |
| `gin.json` | `POST /v1/query` Go `github.com/gin-gonic/gin` 1.6.0 |
| `lodash.json` | `POST /v1/query` npm `lodash` 4.17.11 |
| `log4j.json` | `POST /v1/query` Maven `org.apache.logging.log4j:log4j-core` 2.14.1 |
| `cve-2021-44228.json` | `GET /v1/vulns/CVE-2021-44228` |
