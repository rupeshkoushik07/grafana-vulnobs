import React, { ChangeEvent } from 'react';
import { InlineField, Input, RadioButtonGroup, Select, Stack } from '@grafana/ui';
import { QueryEditorProps, SelectableValue } from '@grafana/data';
import { DataSource } from '../datasource';
import { MyDataSourceOptions, MyQuery, QueryType } from '../types';

type Props = QueryEditorProps<DataSource, MyQuery, MyDataSourceOptions>;

// Common OSV ecosystems. The Select allows custom values for anything not listed.
// Full list: https://ossf.github.io/osv-schema/#defined-ecosystems
const ECOSYSTEMS: Array<SelectableValue<string>> = [
  'npm',
  'Go',
  'PyPI',
  'Maven',
  'RubyGems',
  'crates.io',
  'NuGet',
  'Packagist',
  'Pub',
  'Hex',
  'Debian',
  'Alpine',
].map((e) => ({ label: e, value: e }));

const QUERY_TYPES: Array<SelectableValue<QueryType>> = [
  { label: 'Package or CVE', value: QueryType.Vulnerabilities, description: 'Look up vulnerabilities in OSV' },
  { label: 'Ingested assets', value: QueryType.Assets, description: 'Scans ingested by the Vulnobs app' },
];

// Alert rules need a single number per row, so every option but "all" returns one.
const METRICS: Array<SelectableValue<string>> = [
  { label: 'Actively exploited (CISA KEV)', value: 'kev' },
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Moderate', value: 'moderate' },
  { label: 'Low', value: 'low' },
  { label: 'Unknown severity', value: 'unknown' },
  { label: 'Total', value: 'total' },
  { label: 'All counts (tables, not alert rules)', value: 'all' },
];

export function QueryEditor({ query, onChange, onRunQuery }: Props) {
  const queryType = query.queryType === QueryType.Assets ? QueryType.Assets : QueryType.Vulnerabilities;

  const onQueryTypeChange = (value: QueryType) => {
    onChange({ ...query, queryType: value });
    onRunQuery();
  };

  const onMetricChange = (v: SelectableValue<string>) => {
    onChange({ ...query, metric: v?.value });
    onRunQuery();
  };

  const onEcosystemChange = (v: SelectableValue<string>) => {
    onChange({ ...query, ecosystem: v?.value });
  };

  const onPackageChange = (event: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...query, package: event.target.value });
  };

  const onVersionChange = (event: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...query, version: event.target.value });
  };

  const onVulnIdChange = (event: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...query, vulnId: event.target.value });
  };

  const { ecosystem, package: pkg, version, vulnId, metric } = query;

  return (
    <Stack gap={1} direction="column">
      <InlineField label="Query type" labelWidth={16}>
        <RadioButtonGroup options={QUERY_TYPES} value={queryType} onChange={onQueryTypeChange} />
      </InlineField>

      {queryType === QueryType.Assets ? (
        <InlineField
          label="Value"
          labelWidth={16}
          tooltip="The number returned for each ingested asset. Asset, source and namespaces become labels in alert rules."
        >
          <Select
            inputId="query-editor-metric"
            options={METRICS}
            value={metric || 'kev'}
            onChange={onMetricChange}
            width={36}
          />
        </InlineField>
      ) : (
        <>
          <Stack gap={0}>
            <InlineField label="Ecosystem" labelWidth={16} tooltip="Package ecosystem, e.g. npm, Go, PyPI">
              <Select
                inputId="query-editor-ecosystem"
                options={ECOSYSTEMS}
                value={ecosystem}
                onChange={onEcosystemChange}
                allowCustomValue
                width={20}
                placeholder="Select"
              />
            </InlineField>
            <InlineField label="Package" labelWidth={16} tooltip="Package name, e.g. lodash">
              <Input
                id="query-editor-package"
                onChange={onPackageChange}
                onBlur={onRunQuery}
                value={pkg || ''}
                width={28}
                placeholder="e.g. lodash"
              />
            </InlineField>
            <InlineField label="Version" labelWidth={12} tooltip="Optional. Limit to vulns affecting this version">
              <Input
                id="query-editor-version"
                onChange={onVersionChange}
                onBlur={onRunQuery}
                value={version || ''}
                width={16}
                placeholder="optional"
              />
            </InlineField>
          </Stack>
          <InlineField
            label="Vulnerability ID"
            labelWidth={16}
            tooltip="Look up a single CVE / GHSA / OSV id directly. Overrides the package fields."
          >
            <Input
              id="query-editor-vuln-id"
              onChange={onVulnIdChange}
              onBlur={onRunQuery}
              value={vulnId || ''}
              width={28}
              placeholder="e.g. CVE-2021-23337"
            />
          </InlineField>
        </>
      )}
    </Stack>
  );
}
