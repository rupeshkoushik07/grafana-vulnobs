import { DataSourceInstanceSettings, CoreApp, ScopedVars } from '@grafana/data';
import { DataSourceWithBackend, getTemplateSrv } from '@grafana/runtime';

import { MyQuery, MyDataSourceOptions, DEFAULT_QUERY, QueryType } from './types';

export class DataSource extends DataSourceWithBackend<MyQuery, MyDataSourceOptions> {
  constructor(instanceSettings: DataSourceInstanceSettings<MyDataSourceOptions>) {
    super(instanceSettings);
  }

  getDefaultQuery(_: CoreApp): Partial<MyQuery> {
    return DEFAULT_QUERY;
  }

  applyTemplateVariables(query: MyQuery, scopedVars: ScopedVars) {
    const tsrv = getTemplateSrv();
    return {
      ...query,
      package: query.package ? tsrv.replace(query.package, scopedVars) : query.package,
      version: query.version ? tsrv.replace(query.version, scopedVars) : query.version,
      vulnId: query.vulnId ? tsrv.replace(query.vulnId, scopedVars) : query.vulnId,
    };
  }

  filterQuery(query: MyQuery): boolean {
    // Assets queries need no input; OSV lookups only run when there is something to look up.
    return query.queryType === QueryType.Assets || !!(query.package || query.vulnId);
  }
}
