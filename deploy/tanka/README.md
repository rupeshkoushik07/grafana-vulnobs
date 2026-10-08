# Deploy Vulnobs with Tanka

A [Grafana Tanka](https://tanka.dev) environment that deploys the Vulnobs stack to
Kubernetes:

- **Grafana**, running the Vulnobs image (the bundled app and nested OSV data source, a demo
  dashboard and an alert rule baked in) on a persistent volume.
- **Vulnobs storage API**, which authenticates requests and stores tenant-isolated asset postures
  in PostgreSQL. It verifies signed, expiring tenant credentials and purges records older than
  the configured retention period. PostgreSQL can be self-managed or managed externally.
- A **scan CronJob** that finds every image running in the cluster, scans each one with
  Trivy, and pushes the reports to the app's `/ingest` endpoint. The results show up on the
  app's **Assets** page, ranked by exploit risk, and feed an alert rule that fires for any
  image with an actively exploited (CISA KEV) vulnerability.
- Optionally, a **Kyverno policy** that refuses to run the Vulnobs image unless its signature
  and SBOM attestation verify.

It's written in plain [Jsonnet](https://jsonnet.org) with no external libraries, so
it renders with nothing but `tk` installed.

## Tested on every change

The [`kubernetes.yml`](../../.github/workflows/kubernetes.yml) workflow deploys this
environment to a throwaway [kind](https://kind.sigs.k8s.io) cluster on every pull request
and push to `main`, using an image built from that commit. It checks that:

- Grafana becomes ready with the bundled app and datasource loaded, the app enabled with its
  Assets page, and the authenticated storage API reachable;
- the provisioned data source reaches OSV and the demo dashboard exists;
- a scan finds a demo workload's image in its namespace, skips excluded namespaces, and
  ingests the report;
- the ingested scan survives a Grafana restart;
- an "Ingested assets" data source query returns it, and the provisioned alert rule
  evaluates without errors; and
- once the workload is deleted, the next scan prunes its image.

## Layout

```
deploy/tanka/
├── environments/default/
│   ├── main.jsonnet     # the environment — imports the lib and sets parameters
│   └── spec.json        # Tanka env spec (target apiServer + namespace)
└── lib/vulnobs/
    └── main.libsonnet   # the stack: Grafana, scan CronJob and its RBAC, image policy
```

## What it renders

| Kind | Name | Purpose |
| --- | --- | --- |
| Namespace | `vulnobs` | isolates the stack |
| PersistentVolumeClaim | `grafana-data` | Grafana's database and plugin state |
| Deployment | `grafana` | runs `ghcr.io/rupeshkoushik07/grafana-vulnobs`, built by [`image.yml`](../../.github/workflows/image.yml) |
| Service | `grafana` | exposes Grafana on `:3000` |
| Deployment, Service | `vulnobs-storage` | authenticated API in front of the PostgreSQL asset store |
| ServiceAccount | `vulnobs-scanner` | identity of the scan job |
| ClusterRole, ClusterRoleBinding | `vulnobs-scanner` | lets the scan job **list pods**, nothing else |
| CronJob | `vulnobs-scan` | discover images → Trivy scan → push to `/ingest` → prune (see below) |
| ClusterPolicy | `vulnobs-verify-image` | only with `verifyImageSignatures: true` — see below |

## How the cluster scan works

Each run of `vulnobs-scan` is one pod with three steps sharing a scratch volume:

1. **discover** runs `vulnobs-discover` from the Vulnobs image. It lists the pods in every
   namespace except `excludeNamespaces`, collects the images of pods that haven't finished,
   and notes which namespaces run each one. It is the only step that gets the service
   account token, and that token can only list pods.
2. **trivy** scans each image. An image it can't pull (for example from a private registry
   it has no credentials for) is logged and skipped.
3. **push** sends each report to the app's `/ingest`, labelled with the image's namespaces
   and `source=cluster`, then calls `/prune` to remove cluster assets that are no longer
   running. Images that were found but failed to scan are kept, so a transient failure
   doesn't delete earlier results. Assets pushed by anything else are never pruned.

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

# Create/provision PostgreSQL and issue a signed tenant token.
kubectl create namespace vulnobs
export VULNOBS_TOKEN_SIGNING_KEY="$(openssl rand -hex 32)"
export VULNOBS_STORAGE_TOKEN="$(VULNOBS_TOKEN_SIGNING_KEY="$VULNOBS_TOKEN_SIGNING_KEY" python3 ../../tools/create-storage-token.py --tenant-id production-grafana)"
kubectl -n vulnobs create secret generic vulnobs-storage \
  --from-literal=database-url='postgres://USER:PASSWORD@DB_HOST:5432/vulnobs?sslmode=require' \
  --from-literal=token-signing-key="$VULNOBS_TOKEN_SIGNING_KEY" \
  --from-literal=storage-token="$VULNOBS_STORAGE_TOKEN"

tk apply environments/default     # shows a diff, then applies

kubectl -n vulnobs port-forward svc/grafana 3000:3000
# open http://localhost:3000, log in as admin / admin -> More apps -> Vulnobs -> Assets
```

Grafana provisions the signed token independently into the App and datasource.
The API verifies its HMAC signature and expiry, then takes the tenant ID from the
verified claims—not from a request parameter. Keep the signing key private,
rotate it to revoke credentials, keep PostgreSQL private, and require TLS for
connections outside the cluster. Retention defaults to 90 days; set
`storageRetentionDays` in `environments/default/main.jsonnet` to a value from 1
to 3650.

To migrate an existing installation's JSON store, first back up the old file,
then copy it out of the Grafana pod and import it with the signed token configured
in the Kubernetes Secret:

```bash
kubectl -n vulnobs cp grafana-DEPLOYMENT_POD:/var/lib/grafana/vulnobs/assets.json ./assets.json
kubectl -n vulnobs port-forward svc/vulnobs-storage 8080:8080
VULNOBS_STORAGE_TOKEN='your-existing-storage-token' \
  python3 ../../tools/migrate-assets.py ./assets.json http://127.0.0.1:8080
```

Keep the backup until the Assets page and dashboards show the imported records.

The first scan runs at the top of the next hour. To run one now:

```bash
kubectl -n vulnobs create job scan-now --from=cronjob/vulnobs-scan
kubectl -n vulnobs logs -f job/scan-now --all-containers --prefix
```

The alert rule is in **Alerting → Alert rules → Vulnobs**. It sends notifications to
Grafana's default contact point; point that at Slack, email, PagerDuty or wherever you want
them.

## Configure

These are top-level arguments, so you can override them on the command line without
editing any file, for example `tk apply environments/default --tla-str imageTag=0.3.0`:

| Argument | Default | Meaning |
| --- | --- | --- |
| `imageRepository` | `ghcr.io/rupeshkoushik07/grafana-vulnobs` | Vulnobs image |
| `imageTag` | `main` | image tag (`main`, a release version like `0.3.0`, or `sha-<commit>`) |

Set these in `environments/default/main.jsonnet`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `excludeNamespaces` | `kube-system`, `kube-public`, `kube-node-lease`, `local-path-storage` | namespaces whose pods are not scanned |
| `scanSchedule` | `0 * * * *` | scan cadence (cron) |
| `trivyImage` | `ghcr.io/aquasecurity/trivy:0.74.0` | scanner image |
| `storageSize` | `1Gi` | size of Grafana's data volume |
| `storageClassName` | `null` | StorageClass for the volume; `null` uses the cluster default |
| `storageRetentionDays` | `90` | age in days before stored scan postures are deleted (1–3650) |
| `repo` | `rupeshkoushik07/grafana-vulnobs` | GitHub repo whose `image.yml` must have signed the image |
| `verifyImageSignatures` | `false` | render the Kyverno policy |

## Enforce signed images (Kyverno)

With `verifyImageSignatures: true`, the environment also renders a Kyverno
`ClusterPolicy`. Every Pod that uses `imageRepository` is admitted only if the image has:

- a keyless cosign signature whose certificate was issued to
  `https://github.com/<repo>/.github/workflows/image.yml` on `main` or a `v*` tag, logged in
  Rekor, and
- a signed CycloneDX SBOM attestation from that same identity.

Kyverno also rewrites the tag to the digest it verified (`mutateDigest`), so the Pod runs
exactly what was checked, even if the tag moves later. The pipeline produces the
signature; the cluster refuses anything without it. This covers the scan job's discover
step too, since it runs the Vulnobs image.

Requirements:

- [Kyverno](https://kyverno.io/docs/installation/) installed in the cluster. The policy uses
  `type: SigstoreBundle`, because cosign v3 stores signatures as Sigstore bundles; it was
  written against the Kyverno v1.19 API.
- Kyverno must be able to pull the image's signatures: make the GHCR package public, or
  configure registry credentials for Kyverno.

The policy only covers the Vulnobs image; other images in the cluster (such as the Trivy and
curl images the CronJob uses) are not affected. The CI deployment above uses an unsigned
image built from the pull request, so it runs with the policy off.

## Notes

- Grafana loads the Vulnobs plugins as **unsigned Grafana plugins**
  (`GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS`, set in the image). The cosign signature
  covers the whole image, plugins included; Grafana's own plugin signing is separate.
- The deployment enables anonymous access with the Editor role, which is what lets the scan
  job push without credentials. Anyone who can reach Grafana can therefore push or prune
  assets. Keep the Service internal, or put authentication in front of it, in a shared
  cluster.
- The app matches each image's language packages (npm, PyPI, Go, Maven, …) against OSV. OS
  packages such as Debian or Alpine ones are counted but not matched.
- Scan postures contain normalized metadata and findings, not the original uploaded report.
  Records older than the configured retention window are deleted automatically, independently
  of Grafana's data volume.
