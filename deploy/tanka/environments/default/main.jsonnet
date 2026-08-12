local vulnobs = import 'vulnobs/main.libsonnet';

vulnobs.new({
  namespace: 'vulnobs',

  // Where the plugin release zips are downloaded from.
  repo: 'rupeshkoushik07/grafana-vulnobs',
  pluginVersion: 'v0.1.0',

  grafanaImage: 'grafana/grafana:11.2.0',
  adminPassword: 'admin',

  // Continuous scan target + cadence.
  targetImage: 'python:3.12',
  trivyImage: 'aquasec/trivy:0.55.0',
  scanSchedule: '0 * * * *', // hourly
})
