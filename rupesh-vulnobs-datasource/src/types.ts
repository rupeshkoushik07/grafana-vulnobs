import { DataSourceJsonData } from '@grafana/data';
import { DataQuery } from '@grafana/schema';

export interface MyQuery extends DataQuery {
  // Package lookup mode
  ecosystem?: string;
  package?: string;
  version?: string;
  // Direct lookup mode (CVE / GHSA / OSV id). Takes precedence when set.
  vulnId?: string;
}

export const DEFAULT_QUERY: Partial<MyQuery> = {
  ecosystem: 'npm',
};

/**
 * Options configured for each DataSource instance
 */
export interface MyDataSourceOptions extends DataSourceJsonData {
  osvBaseUrl?: string;
}

/**
 * Value that is used in the backend, but never sent over HTTP to the frontend.
 * Reserved for enrichment feeds (NVD / GitHub Advisory) in a later phase.
 */
export interface MySecureJsonData {
  apiKey?: string;
}
