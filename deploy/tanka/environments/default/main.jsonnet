local vulnobs = import 'vulnobs/main.libsonnet';

// Top-level arguments override the image without editing this file, e.g. to
// deploy a locally built image:
//   tk apply environments/default --tla-str imageRepository=vulnobs --tla-str imageTag=dev
function(
  // Grafana with the Vulnobs plugins baked in, built, signed and SBOM-attested
  // by .github/workflows/image.yml in this repo.
  imageRepository='ghcr.io/rupeshkoushik07/grafana-vulnobs',
  imageTag='main',
)
  vulnobs.new({
    namespace: 'vulnobs',

    repo: 'rupeshkoushik07/grafana-vulnobs',
    imageRepository: imageRepository,
    imageTag: imageTag,
    adminPassword: 'admin',

    // Grafana's data volume: its database and the ingested scans.
    storageSize: '1Gi',
    storageClassName: null,  // null uses the cluster's default StorageClass

    // Also render a Kyverno ClusterPolicy that only admits the image if its
    // signature and SBOM attestation verify. Needs Kyverno in the cluster.
    verifyImageSignatures: false,

    // Scan every image running in the cluster, except in these namespaces.
    excludeNamespaces: ['kube-system', 'kube-public', 'kube-node-lease', 'local-path-storage'],
    scanSchedule: '0 * * * *',  // hourly
    trivyImage: 'ghcr.io/aquasecurity/trivy:0.74.0',
  })
