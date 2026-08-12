# Deploy Vulnobs with Tanka

A [Grafana Tanka](https://tanka.dev) environment that deploys the Vulnobs stack to
Kubernetes: **Grafana** (with the Vulnobs plugins), and a **Trivy CronJob** that
continuously scans a target image and pushes the report to the app's `/ingest`
endpoint for live, prioritized posture.

It's written in plain [Jsonnet](https://jsonnet.org) with no external libraries, so
it renders with nothing but `tk` installed.

## Layout

```
deploy/tanka/
├── environments/default/
│   ├── main.jsonnet     # the environment — imports the lib and sets parameters
│   └── spec.json        # Tanka env spec (target apiServer + namespace)
└── lib/vulnobs/
    └── main.libsonnet   # the stack: Namespace, Grafana Deployment/Service, scan CronJob
```

## What it renders

Four Kubernetes objects:

| Kind | Name | Purpose |
| --- | --- | --- |
| Namespace | `vulnobs` | isolates the stack |
| Deployment | `grafana` | Grafana; an init container downloads the plugin release zips into a shared volume |
| Service | `grafana` | exposes Grafana on `:3000` |
| CronJob | `vulnobs-scan` | Trivy scans `targetImage` → curl pushes the report to `/ingest` |

## Render it (no cluster needed)

```bash
cd deploy/tanka
tk eval environments/default      # Jsonnet -> JSON
tk show environments/default      # applyable Kubernetes YAML
```

## Apply to a cluster

```bash
# point the environment at your cluster
tk env set environments/default --server=https://your-api-server:6443

tk apply environments/default     # shows a diff, then applies

kubectl -n vulnobs port-forward svc/grafana 3000:3000
# open http://localhost:3000 -> More apps -> Vulnobs
```

## Configure

Edit `environments/default/main.jsonnet`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `targetImage` | `python:3.12` | image the CronJob scans |
| `scanSchedule` | `0 * * * *` | scan cadence (cron) |
| `pluginVersion` | `v0.1.0` | plugin release to install |
| `grafanaImage` | `grafana/grafana:11.2.0` | Grafana image |

## Notes

- The plugins load **unsigned** (`GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS`) — fine for
  internal use; sign them for a hardened deployment.
- The CronJob demonstrates the continuous **scan → ingest** loop. In a real cluster you'd
  more likely run [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) for
  cluster-wide scanning and point the ingest at its reports.
