# Deploy Vulnobs with Tanka

A [Grafana Tanka](https://tanka.dev) environment that deploys the Vulnobs stack to
Kubernetes: **Grafana** (the signed Vulnobs image, with both plugins, the OSV data source
and a demo dashboard baked in), and a **Trivy CronJob** that continuously scans a target
image and pushes the report to the app's `/ingest` endpoint for live, prioritized posture.
Optionally, a **Kyverno policy** refuses to run the Vulnobs image unless its signature and
SBOM attestation verify.

It's written in plain [Jsonnet](https://jsonnet.org) with no external libraries, so
it renders with nothing but `tk` installed.

## Tested on every change

The [`kubernetes.yml`](../../.github/workflows/kubernetes.yml) workflow deploys this
environment to a throwaway [kind](https://kind.sigs.k8s.io) cluster on every pull request
and push to `main`, using an image built from that commit. It checks that:

- Grafana becomes ready with both plugins loaded and the app enabled,
- the provisioned data source reaches OSV and the demo dashboard exists, and
- one run of the scheduled Trivy scan completes and its report shows up in the app's
  ingested assets.

## Layout

```
deploy/tanka/
├── environments/default/
│   ├── main.jsonnet     # the environment — imports the lib and sets parameters
│   └── spec.json        # Tanka env spec (target apiServer + namespace)
└── lib/vulnobs/
    └── main.libsonnet   # the stack: Namespace, Grafana, scan CronJob, image policy
```

## What it renders

| Kind | Name | Purpose |
| --- | --- | --- |
| Namespace | `vulnobs` | isolates the stack |
| Deployment | `grafana` | runs `ghcr.io/rupeshkoushik07/grafana-vulnobs`, built by [`image.yml`](../../.github/workflows/image.yml) |
| Service | `grafana` | exposes Grafana on `:3000` |
| CronJob | `vulnobs-scan` | Trivy scans `targetImage` → curl pushes the report to `/ingest` |
| ClusterPolicy | `vulnobs-verify-image` | only with `verifyImageSignatures: true` — see below |

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
# open http://localhost:3000, log in as admin / admin -> More apps -> Vulnobs
```

To run a scan now instead of waiting for the schedule:

```bash
kubectl -n vulnobs create job scan-now --from=cronjob/vulnobs-scan
```

## Configure

These are top-level arguments, so you can override them on the command line without
editing any file, for example `tk apply environments/default --tla-str imageTag=0.3.0`:

| Argument | Default | Meaning |
| --- | --- | --- |
| `imageRepository` | `ghcr.io/rupeshkoushik07/grafana-vulnobs` | Vulnobs image |
| `imageTag` | `main` | image tag (`main`, a release version like `0.3.0`, or `sha-<commit>`) |
| `targetImage` | `python:3.12` | image the CronJob scans |

Set these in `environments/default/main.jsonnet`:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `repo` | `rupeshkoushik07/grafana-vulnobs` | GitHub repo whose `image.yml` must have signed the image |
| `verifyImageSignatures` | `false` | render the Kyverno policy |
| `scanSchedule` | `0 * * * *` | scan cadence (cron) |
| `trivyImage` | `ghcr.io/aquasecurity/trivy:0.74.0` | scanner image |

## Enforce signed images (Kyverno)

With `verifyImageSignatures: true`, the environment also renders a Kyverno
`ClusterPolicy`. Every Pod that uses `imageRepository` is admitted only if the image has:

- a keyless cosign signature whose certificate was issued to
  `https://github.com/<repo>/.github/workflows/image.yml` on `main` or a `v*` tag, logged in
  Rekor, and
- a signed CycloneDX SBOM attestation from that same identity.

Kyverno also rewrites the tag to the digest it verified (`mutateDigest`), so the Pod runs
exactly what was checked, even if the tag moves later. The pipeline produces the
signature; the cluster refuses anything without it.

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
- The CronJob demonstrates the continuous **scan → ingest** loop. In a real cluster you'd
  more likely run [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) for
  cluster-wide scanning and point the ingest at its reports.
- Ingested scans are held in memory by the app, so they reset when the Grafana pod restarts.
