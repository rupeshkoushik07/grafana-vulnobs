local vulnobs = import 'vulnobs/main.libsonnet';

// Top-level arguments override the image without editing this file, e.g. to
// deploy a locally built image:
//   tk apply environments/default --tla-str imageRepository=vulnobs --tla-str imageTag=dev
function(
  // Grafana with the Vulnobs plugins baked in, built, signed and SBOM-attested
  // by .github/workflows/image.yml in this repo.
  imageRepository='ghcr.io/rupeshkoushik07/grafana-vulnobs',
  imageTag='main',
  // Give the app's "Scan now" button what it needs to start the cluster scan.
  // Off by default: read the note at scanNow in lib/vulnobs/main.libsonnet.
  //   tk apply environments/default --tla-code scanNow=true
  scanNow=false,
  // Let the app list pods, so the Assets page shows what runs in the cluster
  // before it has been scanned. Off by default: see showWorkloads in the lib.
  //   tk apply environments/default --tla-code showWorkloads=true
  showWorkloads=false,
  // Scan every image running in the cluster, except in these namespaces. The
  // workloads view skips the same ones.
  excludeNamespaces=['kube-system', 'kube-public', 'kube-node-lease', 'local-path-storage'],
)
  vulnobs.new({
    namespace: 'vulnobs',

    repo: 'rupeshkoushik07/grafana-vulnobs',
    imageRepository: imageRepository,
    imageTag: imageTag,
    adminPassword: 'admin',

    // Grafana's database and plugin state; scan posture is stored separately.
    storageSize: '1Gi',
    storageClassName: null,  // null uses the cluster's default StorageClass
    storageRetentionDays: 90,

    // Also render a Kyverno ClusterPolicy that only admits the image if its
    // signature and SBOM attestation verify. Needs Kyverno in the cluster.
    verifyImageSignatures: false,

    excludeNamespaces: excludeNamespaces,
    scanSchedule: '0 * * * *',  // hourly
    scanNow: scanNow,
    showWorkloads: showWorkloads,
    trivyImage: 'ghcr.io/aquasecurity/trivy:0.74.0',
  })
