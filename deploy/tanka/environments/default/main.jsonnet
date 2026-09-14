local vulnobs = import 'vulnobs/main.libsonnet';

// Top-level arguments override the image and scan target without editing this
// file, e.g. to deploy a locally built image:
//   tk apply environments/default --tla-str imageRepository=vulnobs --tla-str imageTag=dev
function(
  // Grafana with the Vulnobs plugins baked in, built, signed and SBOM-attested
  // by .github/workflows/image.yml in this repo.
  imageRepository='ghcr.io/rupeshkoushik07/grafana-vulnobs',
  imageTag='main',
  // Image the scheduled Trivy scan checks.
  targetImage='python:3.12',
)
  vulnobs.new({
    namespace: 'vulnobs',

    repo: 'rupeshkoushik07/grafana-vulnobs',
    imageRepository: imageRepository,
    imageTag: imageTag,
    adminPassword: 'admin',

    // Also render a Kyverno ClusterPolicy that only admits the image if its
    // signature and SBOM attestation verify. Needs Kyverno in the cluster.
    verifyImageSignatures: false,

    // Continuous scan target + cadence.
    targetImage: targetImage,
    trivyImage: 'ghcr.io/aquasecurity/trivy:0.74.0',
    scanSchedule: '0 * * * *', // hourly
  })
