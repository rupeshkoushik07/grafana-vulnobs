// Vulnobs stack as plain Jsonnet — no external libraries required.
// Deploys Grafana (the Vulnobs image, with both plugins baked in) on a
// persistent volume, and a CronJob that scans every image running in the
// cluster with Trivy and pushes the reports to the app's /ingest. Optionally
// adds a Kyverno policy that refuses to run the Vulnobs image unless it is
// signed, with an SBOM attestation, by this repo's image workflow.
{
  new(params):: {
    local ns = params.namespace,
    local appID = 'rupesh-vulnobs-app',
    local image = '%s:%s' % [params.imageRepository, params.imageTag],
    local appAPI = 'http://grafana.%s.svc:3000/api/plugins/%s/resources' % [ns, appID],

    namespace: {
      apiVersion: 'v1',
      kind: 'Namespace',
      metadata: { name: ns },
    },

    grafana: {
      // Grafana's data directory: its database, and the scans the app ingests.
      pvc: {
        apiVersion: 'v1',
        kind: 'PersistentVolumeClaim',
        metadata: { name: 'grafana-data', namespace: ns },
        spec: {
          accessModes: ['ReadWriteOnce'],
          resources: { requests: { storage: params.storageSize } },
        } + (if params.storageClassName != null then { storageClassName: params.storageClassName } else {}),
      },

      deployment: {
        apiVersion: 'apps/v1',
        kind: 'Deployment',
        metadata: { name: 'grafana', namespace: ns, labels: { app: 'grafana' } },
        spec: {
          replicas: 1,
          // The data volume can only be mounted by one pod at a time.
          strategy: { type: 'Recreate' },
          selector: { matchLabels: { app: 'grafana' } },
          template: {
            metadata: { labels: { app: 'grafana' } },
            spec: {
              // Let the grafana user (uid/gid 472 in the image) write the volume.
              securityContext: { fsGroup: 472 },
              containers: [{
                name: 'grafana',
                image: image,
                ports: [{ containerPort: 3000, name: 'http' }],
                env: [
                  { name: 'GF_AUTH_ANONYMOUS_ENABLED', value: 'true' },
                  { name: 'GF_AUTH_ANONYMOUS_ORG_ROLE', value: 'Editor' },
                  { name: 'GF_SECURITY_ADMIN_PASSWORD', value: params.adminPassword },
                ],
                volumeMounts: [{ name: 'data', mountPath: '/var/lib/grafana' }],
                readinessProbe: { httpGet: { path: '/api/health', port: 3000 }, initialDelaySeconds: 10 },
              }],
              volumes: [{ name: 'data', persistentVolumeClaim: { claimName: 'grafana-data' } }],
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

    // Scheduled cluster scan. Three steps share a scratch volume:
    //  1. discover (Vulnobs image): list the images of every pod outside the
    //     excluded namespaces, using a read-only service account token that
    //     only this container gets.
    //  2. trivy: scan each image; one that can't be pulled is skipped.
    //  3. push (curl): send each report to the app's /ingest, labelled with the
    //     namespaces that run it, then /prune assets no longer running.
    scanner: {
      serviceAccount: {
        apiVersion: 'v1',
        kind: 'ServiceAccount',
        metadata: { name: 'vulnobs-scanner', namespace: ns },
        automountServiceAccountToken: false,
      },

      clusterRole: {
        apiVersion: 'rbac.authorization.k8s.io/v1',
        kind: 'ClusterRole',
        metadata: { name: 'vulnobs-scanner' },
        rules: [{ apiGroups: [''], resources: ['pods'], verbs: ['list'] }],
      },

      clusterRoleBinding: {
        apiVersion: 'rbac.authorization.k8s.io/v1',
        kind: 'ClusterRoleBinding',
        metadata: { name: 'vulnobs-scanner' },
        roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'vulnobs-scanner' },
        subjects: [{ kind: 'ServiceAccount', name: 'vulnobs-scanner', namespace: ns }],
      },

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
              activeDeadlineSeconds: 3600,
              template: {
                metadata: { labels: { app: 'vulnobs-scan' } },
                spec: {
                  restartPolicy: 'Never',
                  serviceAccountName: 'vulnobs-scanner',
                  automountServiceAccountToken: false,
                  initContainers: [
                    {
                      name: 'discover',
                      image: image,
                      command: ['vulnobs-discover'],
                      args: [
                        '-exclude-namespaces', std.join(',', params.excludeNamespaces),
                        '-targets', '/work/targets.tsv',
                        '-prune', '/work/prune.json',
                      ],
                      volumeMounts: [
                        { name: 'work', mountPath: '/work' },
                        { name: 'kube-api', mountPath: '/var/run/secrets/kubernetes.io/serviceaccount', readOnly: true },
                      ],
                    },
                    {
                      name: 'trivy',
                      image: params.trivyImage,
                      command: ['/bin/sh', '-c'],
                      args: [|||
                        set -u
                        mkdir -p /work/reports
                        tab="$(printf '\t')"
                        n=0; ok=0; failed=0
                        while IFS="$tab" read -r image query; do
                          [ -n "$image" ] || continue
                          n=$((n + 1))
                          echo "scanning $image"
                          if trivy image --quiet --scanners vuln --format json --timeout 15m \
                              --cache-dir /work/cache --output "/work/reports/$n.json" "$image"; then
                            printf '%s\n' "$query" > "/work/reports/$n.query"
                            ok=$((ok + 1))
                          else
                            echo "could not scan $image; skipping it" >&2
                            rm -f "/work/reports/$n.json"
                            failed=$((failed + 1))
                          fi
                        done < /work/targets.tsv
                        echo "scanned $ok of $n images ($failed failed)"
                      |||],
                      volumeMounts: [{ name: 'work', mountPath: '/work' }],
                    },
                  ],
                  containers: [{
                    name: 'push',
                    image: 'curlimages/curl:8.22.0',
                    command: ['/bin/sh', '-c'],
                    env: [{ name: 'VULNOBS_API', value: appAPI }],
                    args: [|||
                      set -eu
                      pushed=0
                      for q in /work/reports/*.query; do
                        [ -e "$q" ] || continue
                        report="${q%.query}.json"
                        curl -fsS -X POST "$VULNOBS_API/ingest?$(cat "$q")" \
                          -H 'Content-Type: application/json' --data-binary @"$report" > /dev/null
                        pushed=$((pushed + 1))
                      done
                      echo "pushed $pushed scans"
                      curl -fsS -X POST "$VULNOBS_API/prune" \
                        -H 'Content-Type: application/json' --data-binary @/work/prune.json
                      echo
                    |||],
                    volumeMounts: [{ name: 'work', mountPath: '/work' }],
                  }],
                  volumes: [
                    { name: 'work', emptyDir: {} },
                    {
                      name: 'kube-api',
                      projected: {
                        sources: [
                          { serviceAccountToken: { path: 'token', expirationSeconds: 3600 } },
                          { configMap: { name: 'kube-root-ca.crt', items: [{ key: 'ca.crt', path: 'ca.crt' }] } },
                        ],
                      },
                    },
                  ],
                },
              },
            },
          },
        },
      },
    },
  },
}
