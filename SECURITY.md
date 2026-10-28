# Security policy

## Supported versions

Vulnobs is in early development. Security fixes go into the latest release and `main`
only.

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it privately instead:

- Through GitHub: **Security → Report a vulnerability** on this repository, or
- By email to koushik.rupesh07@gmail.com with "Vulnobs security" in the subject.

Include what you found, the affected component (App, data source, storage API, scanner or
deployment), steps to reproduce, and the impact you expect.

## What happens next

1. You get an acknowledgement, and we confirm whether the issue is valid.
2. We agree on a fix and a disclosure date with you, and keep you updated until it ships.
3. The fix is released and a GitHub security advisory is published, crediting you unless
   you prefer otherwise.

## Scope

In scope: the Vulnobs App and data source plugins, the storage API (including tenant
isolation and token handling), the scanner, the container image and the deployment
manifests in this repository.

Out of scope: vulnerabilities in Grafana itself or in third-party dependencies (report
those upstream), and findings that only affect the local development setup with default
credentials.
