import React, { ChangeEvent } from 'react';
import { InlineField, Input, Select, Stack } from '@grafana/ui';
import { QueryEditorProps, SelectableValue } from '@grafana/data';
import { DataSource } from '../datasource';
import { MyDataSourceOptions, MyQuery } from '../types';

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

export function QueryEditor({ query, onChange, onRunQuery }: Props) {
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

  const { ecosystem, package: pkg, version, vulnId } = query;

  return (
    <Stack gap={1} direction="column">
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
    </Stack>
  );
}
