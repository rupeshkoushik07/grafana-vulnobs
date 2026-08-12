// Vulnobs stack as plain Jsonnet — no external libraries required.
// Deploys Grafana (with the Vulnobs plugins), and a Trivy CronJob that
// continuously scans an image and pushes the result to the app's /ingest.
{
  new(params):: {
    local ns = params.namespace,
    local appID = 'rupesh-vulnobs-app',
    local dsID = 'rupesh-vulnobs-datasource',
    local releaseBase = 'https://github.com/%s/releases/download/%s' % [params.repo, params.pluginVersion],
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
              // Download and unpack the (unsigned) Vulnobs plugins from the GitHub
              // release into a shared volume before Grafana starts.
              initContainers: [{
                name: 'install-plugins',
                image: 'alpine:3.20',
                command: ['/bin/sh', '-c'],
                args: [|||
                  set -eu
                  apk add --no-cache curl unzip >/dev/null
                  for p in %s %s; do
                    curl -sSL "%s/${p}-%s.zip" -o "/tmp/${p}.zip"
                    unzip -qo "/tmp/${p}.zip" -d /var/lib/grafana/plugins
                  done
                ||| % [appID, dsID, releaseBase, params.pluginVersion]],
                volumeMounts: [{ name: 'plugins', mountPath: '/var/lib/grafana/plugins' }],
              }],
              containers: [{
                name: 'grafana',
                image: params.grafanaImage,
                ports: [{ containerPort: 3000, name: 'http' }],
                env: [
                  { name: 'GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS', value: '%s,%s' % [appID, dsID] },
                  { name: 'GF_AUTH_ANONYMOUS_ENABLED', value: 'true' },
                  { name: 'GF_AUTH_ANONYMOUS_ORG_ROLE', value: 'Editor' },
                  { name: 'GF_SECURITY_ADMIN_PASSWORD', value: params.adminPassword },
                ],
                volumeMounts: [{ name: 'plugins', mountPath: '/var/lib/grafana/plugins' }],
                readinessProbe: { httpGet: { path: '/api/health', port: 3000 }, initialDelaySeconds: 10 },
              }],
              volumes: [{ name: 'plugins', emptyDir: {} }],
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
