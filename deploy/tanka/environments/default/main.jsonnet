local vulnobs = import 'vulnobs/main.libsonnet';

vulnobs.new({
  namespace: 'vulnobs',

  // Grafana with the Vulnobs plugins baked in, built, signed and SBOM-attested
  // by .github/workflows/image.yml in this repo.
  repo: 'rupeshkoushik07/grafana-vulnobs',
  imageRepository: 'ghcr.io/rupeshkoushik07/grafana-vulnobs',
  imageTag: 'main',
  adminPassword: 'admin',

  // Also render a Kyverno ClusterPolicy that only admits the image if its
  // signature and SBOM attestation verify. Needs Kyverno in the cluster.
  verifyImageSignatures: false,

  // Continuous scan target + cadence.
  targetImage: 'python:3.12',
  trivyImage: 'aquasec/trivy:0.55.0',
  scanSchedule: '0 * * * *', // hourly
})
