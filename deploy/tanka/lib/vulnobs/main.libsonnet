// Vulnobs stack as plain Jsonnet — no external libraries required.
// Deploys Grafana (the Vulnobs image, with both plugins baked in), and a Trivy
// CronJob that continuously scans an image and pushes the result to the app's
// /ingest. Optionally adds a Kyverno policy that refuses to run the Vulnobs
// image unless it is signed, with an SBOM attestation, by this repo's image
// workflow.
{
  new(params):: {
    local ns = params.namespace,
    local appID = 'rupesh-vulnobs-app',
    local grafanaURL = 'http://grafana.%s.svc:3000' % ns,

    namespace: {
      apiVersion: 'v1',
      kind: 'Namespace',
      metadata: { name: ns },
    },

    grafana: {
      deployment: {
        apiVersion: 'apps/v1',
        kind: 'Deployment',
        metadata: { name: 'grafana', namespace: ns, labels: { app: 'grafana' } },
        spec: {
          replicas: 1,
          selector: { matchLabels: { app: 'grafana' } },
          template: {
            metadata: { labels: { app: 'grafana' } },
            spec: {
              containers: [{
                name: 'grafana',
                image: '%s:%s' % [params.imageRepository, params.imageTag],
                ports: [{ containerPort: 3000, name: 'http' }],
                env: [
                  { name: 'GF_AUTH_ANONYMOUS_ENABLED', value: 'true' },
                  { name: 'GF_AUTH_ANONYMOUS_ORG_ROLE', value: 'Editor' },
                  { name: 'GF_SECURITY_ADMIN_PASSWORD', value: params.adminPassword },
                ],
                readinessProbe: { httpGet: { path: '/api/health', port: 3000 }, initialDelaySeconds: 10 },
              }],
            },
          },
        },
      },

      service: {
        apiVersion: 'v1',
        kind: 'Service',
        metadata: { name: 'grafana', namespace: ns, labels: { app: 'grafana' } },
        spec: {
          selector: { app: 'grafana' },
          ports: [{ name: 'http', port: 3000, targetPort: 3000 }],
        },
      },
    },

    // Admission control: only admit the Vulnobs image if it carries a valid
    // keyless cosign signature and CycloneDX SBOM attestation made by
    // .github/workflows/image.yml on main or a v* tag of params.repo.
    [if params.verifyImageSignatures then 'imagePolicy']: {
      local attestors = [{
        entries: [{
          keyless: {
            issuer: 'https://token.actions.githubusercontent.com',
            subjectRegExp: '^https://github\\.com/%s/\\.github/workflows/image\\.yml@refs/(heads/main|tags/v.+)$' % params.repo,
            rekor: { url: 'https://rekor.sigstore.dev' },
          },
        }],
      }],

      clusterPolicy: {
        apiVersion: 'kyverno.io/v1',
        kind: 'ClusterPolicy',
        metadata: { name: 'vulnobs-verify-image' },
        spec: {
          background: false,
          rules: [{
            name: 'require-signature-and-sbom',
            match: { any: [{ resources: { kinds: ['Pod'] } }] },
            verifyImages: [{
              imageReferences: [params.imageRepository + ':*', params.imageRepository + '@*'],
              // cosign v3 stores signatures as Sigstore bundles (OCI referrers).
              // Kyverno's default `Cosign` type only looks for legacy .sig tags.
              type: 'SigstoreBundle',
              failureAction: 'Enforce',
              required: true,
              // Rewrite the tag to the verified digest so the pod runs exactly
              // what was checked, even if the tag moves later.
              mutateDigest: true,
              verifyDigest: true,
              attestors: attestors,
              attestations: [{
                type: 'https://cyclonedx.org/bom',
                attestors: attestors,
              }],
            }],
          }],
        },
      },
    },

    // Continuous scanner: Trivy scans the target image on a schedule; a second
    // container pushes the report to the app's /ingest endpoint (asset = image).
    scanner: {
      cronjob: {
        apiVersion: 'batch/v1',
        kind: 'CronJob',
        metadata: { name: 'vulnobs-scan', namespace: ns },
        spec: {
          schedule: params.scanSchedule,
          concurrencyPolicy: 'Forbid',
          jobTemplate: {
            spec: {
              backoffLimit: 1,
              template: {
                spec: {
                  restartPolicy: 'Never',
                  initContainers: [{
                    name: 'trivy',
                    image: params.trivyImage,
                    command: ['trivy'],
                    args: [
                      'image',
                      '--scanners', 'vuln',
                      '--format', 'json',
                      '--output', '/work/scan.json',
                      params.targetImage,
                    ],
                    volumeMounts: [{ name: 'work', mountPath: '/work' }],
                  }],
                  containers: [{
                    name: 'push',
                    image: 'curlimages/curl:8.10.1',
                    command: ['/bin/sh', '-c'],
                    args: [
                      'curl -sS -X POST "%s/api/plugins/%s/resources/ingest?asset=%s" -H "Content-Type: application/json" --data-binary @/work/scan.json'
                      % [grafanaURL, appID, std.strReplace(params.targetImage, '/', '_')],
                    ],
                    volumeMounts: [{ name: 'work', mountPath: '/work' }],
                  }],
                  volumes: [{ name: 'work', emptyDir: {} }],
                },
              },
            },
          },
        },
      },
    },
  },
}
