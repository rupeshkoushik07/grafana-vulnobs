import React, { useState } from 'react';
import { css } from '@emotion/css';
import { GrafanaTheme2, SelectableValue } from '@grafana/data';
import { PluginPage, getBackendSrv } from '@grafana/runtime';
import {
  Alert,
  Badge,
  BadgeColor,
  Button,
  InlineField,
  Input,
  InteractiveTable,
  LoadingPlaceholder,
  Select,
  Stack,
  useStyles2,
  type Column,
} from '@grafana/ui';
import pluginJson from '../plugin.json';
import { testIds } from '../components/testIds';

const SEARCH_URL = `/api/plugins/${pluginJson.id}/resources/search`;

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

interface VulnRow {
  id: string;
  cve: string;
  severity: string;
  severityScore: number;
  cvss: string;
  summary: string;
  fixedVersion: string;
  published: string;
  modified: string;
  url: string;
}

const SEVERITY_COLOR: Record<string, BadgeColor> = {
  CRITICAL: 'red',
  HIGH: 'orange',
  MODERATE: 'purple',
  LOW: 'blue',
  UNKNOWN: 'darkgrey',
};

function SearchPage() {
  const s = useStyles2(getStyles);

  const [ecosystem, setEcosystem] = useState<string>('npm');
  const [pkg, setPkg] = useState('');
  const [version, setVersion] = useState('');
  const [vulnId, setVulnId] = useState('');

  const [rows, setRows] = useState<VulnRow[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSearch = !!(pkg.trim() || vulnId.trim());

  const onSearch = async () => {
    if (!canSearch) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = {};
      if (vulnId.trim()) {
        params.vulnId = vulnId.trim();
      } else {
        params.ecosystem = ecosystem;
        params.package = pkg.trim();
        if (version.trim()) {
          params.version = version.trim();
        }
      }
      const res = await getBackendSrv().get<{ vulns: VulnRow[] }>(SEARCH_URL, params);
      setRows(res.vulns ?? []);
    } catch (e: any) {
      setError(e?.data?.error ?? e?.statusText ?? 'Search failed');
      setRows(null);
    } finally {
      setLoading(false);
    }
  };

  const columns: Array<Column<VulnRow>> = [
    {
      id: 'severity',
      header: 'Severity',
      cell: ({ row: { original: r } }) => (
        <Badge text={r.severity} color={SEVERITY_COLOR[r.severity] ?? 'darkgrey'} />
      ),
    },
    {
      id: 'id',
      header: 'ID',
      cell: ({ row: { original: r } }) => (
        <a className={s.link} href={r.url} target="_blank" rel="noreferrer">
          {r.id}
        </a>
      ),
    },
    { id: 'cve', header: 'CVE' },
    { id: 'summary', header: 'Summary' },
    { id: 'fixedVersion', header: 'Fixed in' },
  ];

  return (
    <PluginPage>
      <div data-testid={testIds.search.container}>
        <p className={s.intro}>
          Search public vulnerability data from <a href="https://osv.dev" target="_blank" rel="noreferrer">OSV</a>.
          Look up a package by ecosystem, or fetch a single advisory by its CVE / GHSA id.
        </p>

        <Stack gap={1} alignItems="flex-end" wrap="wrap">
          <InlineField label="Ecosystem" labelWidth={12}>
            <Select
              inputId="search-ecosystem"
              width={18}
              options={ECOSYSTEMS}
              value={ecosystem}
              onChange={(v) => setEcosystem(v?.value ?? 'npm')}
              allowCustomValue
            />
          </InlineField>
          <InlineField label="Package" labelWidth={10}>
            <Input
              data-testid={testIds.search.package}
              width={26}
              value={pkg}
              placeholder="e.g. lodash"
              onChange={(e) => setPkg(e.currentTarget.value)}
            />
          </InlineField>
          <InlineField label="Version" labelWidth={10} tooltip="Optional">
            <Input width={14} value={version} placeholder="optional" onChange={(e) => setVersion(e.currentTarget.value)} />
          </InlineField>
          <InlineField label="or CVE / GHSA id" labelWidth={16} tooltip="Overrides the package fields">
            <Input
              width={24}
              value={vulnId}
              placeholder="e.g. CVE-2021-23337"
              onChange={(e) => setVulnId(e.currentTarget.value)}
            />
          </InlineField>
          <Button data-testid={testIds.search.submit} onClick={onSearch} disabled={!canSearch || loading}>
            Search
          </Button>
        </Stack>

        <div className={s.results}>
          {loading && <LoadingPlaceholder text="Querying OSV…" />}
          {error && <Alert title="Search failed" severity="error">{error}</Alert>}
          {!loading && !error && rows && rows.length === 0 && (
            <Alert title="No known vulnerabilities found" severity="success">
              OSV returned no vulnerabilities for that query.
            </Alert>
          )}
          {!loading && !error && rows && rows.length > 0 && (
            <>
              <p className={s.count}>{rows.length} vulnerabilit{rows.length === 1 ? 'y' : 'ies'} found</p>
              <InteractiveTable columns={columns} data={rows} getRowId={(r) => r.id} />
            </>
          )}
        </div>
      </div>
    </PluginPage>
  );
}

export default SearchPage;

const getStyles = (theme: GrafanaTheme2) => ({
  intro: css`
    color: ${theme.colors.text.secondary};
    margin-bottom: ${theme.spacing(2)};
  `,
  results: css`
    margin-top: ${theme.spacing(3)};
  `,
  count: css`
    color: ${theme.colors.text.secondary};
    margin-bottom: ${theme.spacing(1)};
  `,
  link: css`
    color: ${theme.colors.text.link};
  `,
});
