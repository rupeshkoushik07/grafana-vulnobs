import { DataSourceJsonData } from '@grafana/data';
import { DataQuery } from '@grafana/schema';

export enum QueryType {
  // Look up vulnerabilities in OSV by package or by id.
  Vulnerabilities = 'vulnerabilities',
  // The scans ingested by the Vulnobs app, one row per asset.
  Assets = 'assets',
}

export interface MyQuery extends DataQuery {
  // Package lookup mode
  ecosystem?: string;
  package?: string;
  version?: string;
  // Direct lookup mode (CVE / GHSA / OSV id). Takes precedence when set.
  vulnId?: string;
  // Ingested assets mode: the number returned per asset (kev, critical, high,
  // moderate, low, unknown, total, or all).
  metric?: string;
}

export const DEFAULT_QUERY: Partial<MyQuery> = {
  ecosystem: 'npm',
};

/**
 * Options configured for each DataSource instance
 */
export interface MyDataSourceOptions extends DataSourceJsonData {
  osvBaseUrl?: string;
  // The Vulnobs app's data directory, where it saves ingested scans.
  assetsDataDir?: string;
}

/**
 * Value that is used in the backend, but never sent over HTTP to the frontend.
 * Reserved for enrichment feeds (NVD / GitHub Advisory) in a later phase.
 */
export interface MySecureJsonData {
  apiKey?: string;
}
