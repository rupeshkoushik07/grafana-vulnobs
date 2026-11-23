// Vulnobs stack as plain Jsonnet — no external libraries required.
// Deploys Grafana (the Vulnobs image, with the app and nested datasource baked in) on a
// persistent volume, and a CronJob that builds a CycloneDX SBOM of every image
// running in the cluster with Trivy and pushes them to the app's /ingest, which
// matches the packages against OSV. Optionally lets the app start that scan on
// demand ("Scan now"), or runs without Grafana having any access to the
// Kubernetes API (grafanaURL, scanAgent), and adds a Kyverno policy that refuses to run the Vulnobs image unless it is
// signed, with an SBOM attestation, by this repo's image workflow.
{
  new(params):: {
    local ns = params.namespace,
    local appID = 'rupeshkoushik07-vulnobs-app',
    local image = '%s:%s' % [params.imageRepository, params.imageTag],
    // Remote mode: Grafana needs no access to the Kubernetes API, so it can
    // run anywhere. Two independent switches:
    //  - grafanaURL: Grafana lives elsewhere, at this address. Grafana and the
    //    storage API are not deployed here; only the scan job (and the agent)
    //    are, and they talk to that Grafana.
    //  - scanAgent: deploy the scan agent, which polls the app for "Scan now"
    //    requests and starts the scan CronJob for them. It holds the
    //    permission to create jobs that scanNow would otherwise give Grafana.
    local grafanaURL = std.get(params, 'grafanaURL', null),
    local externalGrafana = grafanaURL != null,
    local scanAgent = std.get(params, 'scanAgent', false),
    local remote = externalGrafana || scanAgent,
    local appAPI = (
      if externalGrafana then std.stripChars(grafanaURL, '/')
      else 'http://grafana.%s.svc:3000' % ns
    ) + '/api/plugins/%s/resources' % appID,
    // Secret holding what the scan job and the agent send to the app:
    // scanner-token (the app's scanner token) and, for a Grafana that requires
    // login, grafana-token (a Grafana service account token).
    local scannerSecret = 'vulnobs-scanner',
    local scannerEnv = [
      {
        name: 'VULNOBS_SCANNER_TOKEN',
        valueFrom: { secretKeyRef: { name: scannerSecret, key: 'scanner-token' } },
      },
      {
        name: 'VULNOBS_GRAFANA_TOKEN',
        valueFrom: { secretKeyRef: { name: scannerSecret, key: 'grafana-token', optional: true } },
      },
    ],

    // Pod hardening (CIS Kubernetes Benchmark section 5, Pod Security
    // Standards). Every container drops all capabilities and can't gain
    // privileges; every pod uses the container runtime's default seccomp
    // profile. Containers whose image runs as a non-root user also say so, so
    // the kubelet refuses to start them as root.
    local podSecurity = { seccompProfile: { type: 'RuntimeDefault' } },
    local containerSecurity = {
      allowPrivilegeEscalation: false,
      capabilities: { drop: ['ALL'] },
    },
    // The Vulnobs image runs as Grafana's numeric user 472.
    local nonRoot = containerSecurity { runAsNonRoot: true },

    // "Scan now": the app asks Kubernetes to run the scan CronJob early. Off
    // unless params.scanNow is set, because it needs what Grafana otherwise
    // never has: a service account token.
    local scanNow = std.get(params, 'scanNow', false),
    // Workloads view: the app lists pods, so the Assets page can show what
    // runs in the cluster before it has been scanned. Also opt-in, for the
    // same reason.
    local showWorkloads = std.get(params, 'showWorkloads', false),
    // Either one means Grafana gets a service account token.
    local kubeAccess = scanNow || showWorkloads,
    local scanCronJob = 'vulnobs-scan',
    local serviceAccountDir = '/var/run/secrets/kubernetes.io/serviceaccount',

    assert !(remote && kubeAccess) :
           'scanNow and showWorkloads give Grafana access to the Kubernetes API; grafanaURL and scanAgent are for running without it. Pick one of the two modes.',

    namespace: {
      apiVersion: 'v1',
      kind: 'Namespace',
      metadata: {
        name: ns,
        // Pod Security Admission: refuse pods that break the baseline
        // standard, and warn about (and audit) anything short of restricted.
        // The Trivy scan step runs as root (the upstream image's default
        // user), which baseline allows but restricted doesn't.
        labels: {
          'pod-security.kubernetes.io/enforce': 'baseline',
          'pod-security.kubernetes.io/warn': 'restricted',
          'pod-security.kubernetes.io/audit': 'restricted',
        },
      },
    },

    [if std.get(params, 'grafanaURL', null) == null then 'grafana']: {
      // Grafana's database and plugin state; scan posture lives in PostgreSQL.
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
              // Grafana doesn't talk to the Kubernetes API, unless "Scan now"
              // or the workloads view is on: then it gets a short-lived token
              // for an account that can only do what those need (see
              // kubeAccess, scanNow and showWorkloads below).
              automountServiceAccountToken: false,
              [if kubeAccess then 'serviceAccountName']: 'vulnobs-grafana',
              // Let the grafana user (uid/gid 472 in the image) write the volume.
              securityContext: podSecurity { fsGroup: 472 },
              containers: [{
                name: 'grafana',
                image: image,
                ports: [{ containerPort: 3000, name: 'http' }],
                env: [
                  { name: 'GF_AUTH_ANONYMOUS_ENABLED', value: 'true' },
                  { name: 'GF_AUTH_ANONYMOUS_ORG_ROLE', value: 'Editor' },
                  { name: 'GF_SECURITY_ADMIN_PASSWORD', value: params.adminPassword },
                  {
                    name: 'VULNOBS_STORAGE_TOKEN',
                    valueFrom: { secretKeyRef: { name: 'vulnobs-storage', key: 'storage-token' } },
                  },
                ] + (
                  // Remote mode with Grafana still in the cluster: the image's
                  // provisioning passes these on to the app's settings.
                  if scanAgent then [
                    { name: 'VULNOBS_CLUSTER_MODE', value: 'remote' },
                    { name: 'VULNOBS_PROMETHEUS_DATASOURCE_UID', value: std.get(params, 'prometheusDatasourceUid', '') },
                    scannerEnv[0],
                  ] else []
                ),
                volumeMounts: [{ name: 'data', mountPath: '/var/lib/grafana' }] + (
                  if kubeAccess then [{ name: 'kube-api', mountPath: serviceAccountDir, readOnly: true }] else []
                ),
                readinessProbe: { httpGet: { path: '/api/health', port: 3000 }, initialDelaySeconds: 10 },
                // Grafana also writes outside its data volume (logs, plugin
                // and temp files), so its root filesystem stays writable.
                securityContext: nonRoot,
                resources: {
                  requests: { cpu: '100m', memory: '256Mi' },
                  limits: { memory: '1Gi' },
                },
              }],
              volumes: [{ name: 'data', persistentVolumeClaim: { claimName: 'grafana-data' } }] + (
                if kubeAccess then [{
                  name: 'kube-api',
                  projected: {
                    sources: [
                      { serviceAccountToken: { path: 'token', expirationSeconds: 3600 } },
                      { configMap: { name: 'kube-root-ca.crt', items: [{ key: 'ca.crt', path: 'ca.crt' }] } },
                      { downwardAPI: { items: [{ path: 'namespace', fieldRef: { fieldPath: 'metadata.namespace' } }] } },
                    ],
                  },
                }] else []
              ),
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

    // "Scan now": what the app's button needs to start the scan CronJob, in
    // this namespace only. It can read that one CronJob, and list and create
    // jobs.
    //
    // Know what you are granting. Kubernetes has no "run this CronJob" verb,
    // so the permission is "create jobs", and whoever can create a job in a
    // namespace can run any pod there: one that mounts the namespace's secrets
    // (the storage credentials) or uses the scanner's service account. With
    // this on, someone who takes over Grafana gets that far. Without it, they
    // get nothing from Kubernetes. Leave it off where Grafana is exposed to
    // people you wouldn't give that to.
    // The app's identity in Kubernetes, when it has one at all.
    [if std.get(params, 'scanNow', false) || std.get(params, 'showWorkloads', false) then 'kubeAccess']: {
      serviceAccount: {
        apiVersion: 'v1',
        kind: 'ServiceAccount',
        metadata: { name: 'vulnobs-grafana', namespace: ns },
        automountServiceAccountToken: false,
      },
    },

    // Workloads view: the app may list pods, cluster-wide, and nothing else:
    // the same ClusterRole the scan job uses. Read-only, but it does let
    // whoever controls Grafana see every pod's name, image and environment
    // variables set inline in the pod spec.
    [if std.get(params, 'showWorkloads', false) then 'showWorkloads']: {
      clusterRoleBinding: {
        apiVersion: 'rbac.authorization.k8s.io/v1',
        kind: 'ClusterRoleBinding',
        metadata: { name: 'vulnobs-grafana-workloads' },
        roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'vulnobs-scanner' },
        subjects: [{ kind: 'ServiceAccount', name: 'vulnobs-grafana', namespace: ns }],
      },
    },

    [if std.get(params, 'scanNow', false) then 'scanNow']: {
      role: {
        apiVersion: 'rbac.authorization.k8s.io/v1',
        kind: 'Role',
        metadata: { name: 'vulnobs-scan-now', namespace: ns },
        rules: [
          { apiGroups: ['batch'], resources: ['cronjobs'], resourceNames: [scanCronJob], verbs: ['get'] },
          { apiGroups: ['batch'], resources: ['jobs'], verbs: ['create', 'list'] },
        ],
      },

      roleBinding: {
        apiVersion: 'rbac.authorization.k8s.io/v1',
        kind: 'RoleBinding',
        metadata: { name: 'vulnobs-scan-now', namespace: ns },
        roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'vulnobs-scan-now' },
        subjects: [{ kind: 'ServiceAccount', name: 'vulnobs-grafana', namespace: ns }],
      },
    },

    // The scan agent: the only piece that talks to the Kubernetes API on
    // behalf of "Scan now" in remote mode. It polls the app, and for each
    // request creates a job from the scan CronJob, in this namespace only.
    //
    // The permission is the one scanNow grants ("create jobs" lets its holder
    // run any pod in the namespace), but here it stays inside the cluster:
    // someone who takes over Grafana can ask for a scan and nothing more.
    [if std.get(params, 'scanAgent', false) then 'scanAgent']: {
      serviceAccount: {
        apiVersion: 'v1',
        kind: 'ServiceAccount',
        metadata: { name: 'vulnobs-scan-agent', namespace: ns },
        automountServiceAccountToken: false,
      },

      role: {
        apiVersion: 'rbac.authorization.k8s.io/v1',
        kind: 'Role',
        metadata: { name: 'vulnobs-scan-agent', namespace: ns },
        rules: [
          { apiGroups: ['batch'], resources: ['cronjobs'], resourceNames: [scanCronJob], verbs: ['get'] },
          { apiGroups: ['batch'], resources: ['jobs'], verbs: ['create', 'list'] },
        ],
      },

      roleBinding: {
        apiVersion: 'rbac.authorization.k8s.io/v1',
        kind: 'RoleBinding',
        metadata: { name: 'vulnobs-scan-agent', namespace: ns },
        roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'vulnobs-scan-agent' },
        subjects: [{ kind: 'ServiceAccount', name: 'vulnobs-scan-agent', namespace: ns }],
      },

      deployment: {
        apiVersion: 'apps/v1',
        kind: 'Deployment',
        metadata: { name: 'vulnobs-scan-agent', namespace: ns, labels: { app: 'vulnobs-scan-agent' } },
        spec: {
          replicas: 1,
          // Two agents would both answer the same request.
          strategy: { type: 'Recreate' },
          selector: { matchLabels: { app: 'vulnobs-scan-agent' } },
          template: {
            metadata: { labels: { app: 'vulnobs-scan-agent' } },
            spec: {
              serviceAccountName: 'vulnobs-scan-agent',
              automountServiceAccountToken: false,
              securityContext: podSecurity,
              containers: [{
                name: 'agent',
                image: image,
                command: ['vulnobs-agent'],
                args: ['-namespace', ns, '-cronjob', scanCronJob],
                env: [{ name: 'VULNOBS_API', value: appAPI }] + scannerEnv,
                volumeMounts: [{ name: 'kube-api', mountPath: serviceAccountDir, readOnly: true }],
                // A single Go binary that writes no files.
                securityContext: nonRoot { readOnlyRootFilesystem: true },
                resources: {
                  requests: { cpu: '10m', memory: '16Mi' },
                  limits: { memory: '64Mi' },
                },
              }],
              volumes: [{
                name: 'kube-api',
                projected: {
                  sources: [
                    { serviceAccountToken: { path: 'token', expirationSeconds: 3600 } },
                    { configMap: { name: 'kube-root-ca.crt', items: [{ key: 'ca.crt', path: 'ca.crt' }] } },
                  ],
                },
              }],
            },
          },
        },
      },
    },

    [if std.get(params, 'grafanaURL', null) == null then 'storageAPI']: {
      deployment: {
        apiVersion: 'apps/v1',
        kind: 'Deployment',
        metadata: { name: 'vulnobs-storage', namespace: ns, labels: { app: 'vulnobs-storage' } },
        spec: {
          replicas: 1,
          selector: { matchLabels: { app: 'vulnobs-storage' } },
          template: {
            metadata: { labels: { app: 'vulnobs-storage' } },
            spec: {
              // The storage API doesn't talk to the Kubernetes API.
              automountServiceAccountToken: false,
              securityContext: podSecurity,
              containers: [{
                name: 'storage-api',
                image: image,
                command: ['/usr/local/bin/vulnobs-storage'],
                ports: [{ containerPort: 8080, name: 'http' }],
                env: [{
                  name: 'DATABASE_URL',
                  valueFrom: { secretKeyRef: { name: 'vulnobs-storage', key: 'database-url' } },
                }, {
                  name: 'VULNOBS_TOKEN_SIGNING_KEY',
                  valueFrom: { secretKeyRef: { name: 'vulnobs-storage', key: 'token-signing-key' } },
                }, {
                  name: 'VULNOBS_RETENTION_DAYS',
                  value: std.toString(params.storageRetentionDays),
                }],
                readinessProbe: { httpGet: { path: '/healthz', port: 8080 }, initialDelaySeconds: 5 },
                // A single Go binary that only talks to PostgreSQL over the
                // network and writes no files.
                securityContext: nonRoot { readOnlyRootFilesystem: true },
                resources: {
                  requests: { cpu: '50m', memory: '64Mi' },
                  limits: { memory: '256Mi' },
                },
              }],
            },
          },
        },
      },

      service: {
        apiVersion: 'v1',
        kind: 'Service',
        metadata: { name: 'vulnobs-storage', namespace: ns },
        spec: {
          selector: { app: 'vulnobs-storage' },
          ports: [{ name: 'http', port: 8080, targetPort: 8080 }],
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
    //     only this container gets. Each image is pinned to the digest its
    //     containers actually run, where the kubelet reports one.
    //  2. trivy: write a CycloneDX SBOM (the package inventory, no findings) of
    //     each image; one that can't be pulled is skipped. Trivy doesn't match
    //     vulnerabilities here, so it downloads no vulnerability database.
    //  3. push (curl): send each SBOM to the app's /ingest, labelled with the
    //     namespaces that run it, then /prune assets no longer running. The
    //     app matches the packages against OSV as they are known at that
    //     moment.
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
        metadata: { name: scanCronJob, namespace: ns },
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
                  securityContext: podSecurity,
                  initContainers: [
                    {
                      name: 'discover',
                      image: image,
                      command: ['vulnobs-discover'],
                      args: [
                        '-exclude-namespaces',
                        std.join(',', params.excludeNamespaces),
                        '-targets',
                        '/work/targets.tsv',
                        '-prune',
                        '/work/prune.json',
                      ],
                      volumeMounts: [
                        { name: 'work', mountPath: '/work' },
                        { name: 'kube-api', mountPath: '/var/run/secrets/kubernetes.io/serviceaccount', readOnly: true },
                      ],
                      // Writes only to the scratch volume.
                      securityContext: nonRoot { readOnlyRootFilesystem: true },
                      resources: {
                        requests: { cpu: '50m', memory: '64Mi' },
                        limits: { memory: '256Mi' },
                      },
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
                          echo "writing an SBOM of $image"
                          if trivy image --quiet --format cyclonedx --timeout 15m \
                              --cache-dir /work/cache --output "/work/reports/$n.json" "$image"; then
                            printf '%s\n' "$query" > "/work/reports/$n.query"
                            ok=$((ok + 1))
                          else
                            echo "could not read $image; skipping it" >&2
                            rm -f "/work/reports/$n.json"
                            failed=$((failed + 1))
                          fi
                        done < /work/targets.tsv
                        echo "wrote SBOMs for $ok of $n images ($failed failed)"
                      |||],
                      volumeMounts: [{ name: 'work', mountPath: '/work' }],
                      // The upstream Trivy image runs as root and Trivy writes
                      // temporary files outside its cache dir, so neither
                      // runAsNonRoot nor a read-only root filesystem is set.
                      // Root without capabilities can still write the scratch
                      // volume (an emptyDir, mode 0777).
                      securityContext: containerSecurity,
                      // Large images need memory to scan.
                      resources: {
                        requests: { cpu: '250m', memory: '512Mi' },
                        limits: { memory: '2Gi' },
                      },
                    },
                  ],
                  containers: [{
                    name: 'push',
                    image: 'curlimages/curl:8.22.0',
                    command: ['/bin/sh', '-c'],
                    env: [{ name: 'VULNOBS_API', value: appAPI }] + (if remote then scannerEnv else []),
                    local pushScript = |||
                      set -eu
                      pushed=0
                      for q in /work/reports/*.query; do
                        [ -e "$q" ] || continue
                        report="${q%.query}.json"
                        curl -fsS -X POST "$VULNOBS_API/ingest?$(cat "$q")" \
                          -H 'Content-Type: application/json' --data-binary @"$report" > /dev/null
                        pushed=$((pushed + 1))
                      done
                      echo "pushed $pushed SBOMs"
                      curl -fsS -X POST "$VULNOBS_API/prune" \
                        -H 'Content-Type: application/json' --data-binary @/work/prune.json
                      echo
                    |||,
                    // Remote mode: the pushes carry the scanner token and, if
                    // Grafana requires login, a Grafana service account token.
                    local authSetup = |||
                      set -eu
                      set --
                      if [ -n "${VULNOBS_SCANNER_TOKEN:-}" ]; then
                        set -- "$@" -H "X-Vulnobs-Scanner-Token: $VULNOBS_SCANNER_TOKEN"
                      fi
                      if [ -n "${VULNOBS_GRAFANA_TOKEN:-}" ]; then
                        set -- "$@" -H "Authorization: Bearer $VULNOBS_GRAFANA_TOKEN"
                      fi
                    |||,
                    args: [
                      if remote then
                        std.strReplace(
                          std.strReplace(pushScript, 'set -eu\n', authSetup),
                          'curl -fsS -X POST',
                          'curl -fsS "$@" -X POST'
                        )
                      else pushScript,
                    ],
                    volumeMounts: [{ name: 'work', mountPath: '/work' }],
                    // curlimages/curl names its user (curl_user, uid 100)
                    // rather than its uid, so the kubelet needs the uid to
                    // verify it isn't root. It only reads the scratch volume.
                    securityContext: containerSecurity {
                      runAsNonRoot: true,
                      runAsUser: 100,
                      readOnlyRootFilesystem: true,
                    },
                    resources: {
                      requests: { cpu: '10m', memory: '16Mi' },
                      limits: { memory: '64Mi' },
                    },
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
