# Example scan reports

Sample files you can upload on the app's **Scan** page (More apps → Vulnobs → Scan).

| File | Format | What it contains |
| --- | --- | --- |
| [`cyclonedx-payments-api.json`](./cyclonedx-payments-api.json) | CycloneDX SBOM | log4j-core 2.14.1 (Log4Shell), lodash, requests, gin |
| [`trivy-myapp.json`](./trivy-myapp.json) | Trivy | lodash, minimist, express, gin, and a Debian OS package (skipped) |

Each package is matched against **live OSV**, so results reflect vulnerabilities known
right now — including CVEs published after the report was generated.

## Generate your own

```bash
# Trivy — scan an image to JSON
trivy image --format json --output myimage.json python:3.9

# Grype — scan an image to JSON
grype python:3.9 -o json > myimage.json

# Syft — produce a CycloneDX SBOM
syft python:3.9 -o cyclonedx-json > myimage.sbom.json
```
