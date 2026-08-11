import React, { useMemo, useState } from 'react';
import { css, cx } from '@emotion/css';
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

// Highest severity first — used for the summary row and table ordering.
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'];

function SearchPage() {
  const s = useStyles2(getStyles);

  const [ecosystem, setEcosystem] = useState<string>('npm');
  const [pkg, setPkg] = useState('');
  const [version, setVersion] = useState('');
  const [vulnId, setVulnId] = useState('');

  const [rows, setRows] = useState<VulnRow[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeSeverity, setActiveSeverity] = useState<string | null>(null);

  const canSearch = !!(pkg.trim() || vulnId.trim());

  // Counts by severity, ordered highest-first, over the full result set.
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of rows ?? []) {
      c[r.severity] = (c[r.severity] ?? 0) + 1;
    }
    return SEVERITY_ORDER.filter((sev) => c[sev]).map((sev) => ({ severity: sev, count: c[sev] }));
  }, [rows]);

  // Table rows: sorted by severity, filtered to the active severity chip if any.
  const visibleRows = useMemo(() => {
    const filtered = (rows ?? []).filter((r) => !activeSeverity || r.severity === activeSeverity);
    return [...filtered].sort((a, b) => b.severityScore - a.severityScore);
  }, [rows, activeSeverity]);

  const onSearch = async () => {
    if (!canSearch) {
      return;
    }
    setLoading(true);
    setError(null);
    setActiveSeverity(null);
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
              <p className={s.count}>
                {rows.length} vulnerabilit{rows.length === 1 ? 'y' : 'ies'} found
                {activeSeverity && ` — showing ${visibleRows.length} ${activeSeverity}`}
              </p>

              <div className={s.summary}>
                {counts.map(({ severity, count }) => {
                  const active = activeSeverity === severity;
                  return (
                    <button
                      key={severity}
                      type="button"
                      className={cx(s.chip, active && s.chipActive)}
                      onClick={() => setActiveSeverity(active ? null : severity)}
                      aria-pressed={active}
                    >
                      <Badge text={String(count)} color={SEVERITY_COLOR[severity] ?? 'darkgrey'} />
                      <span className={s.chipLabel}>{severity}</span>
                    </button>
                  );
                })}
                {activeSeverity && (
                  <button type="button" className={s.chip} onClick={() => setActiveSeverity(null)}>
                    <span className={s.chipLabel}>Clear filter</span>
                  </button>
                )}
              </div>

              <InteractiveTable columns={columns} data={visibleRows} getRowId={(r) => r.id} />
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
  summary: css`
    display: flex;
    flex-wrap: wrap;
    gap: ${theme.spacing(1)};
    margin-bottom: ${theme.spacing(2)};
  `,
  chip: css`
    display: inline-flex;
    align-items: center;
    gap: ${theme.spacing(0.5)};
    padding: ${theme.spacing(0.5, 1)};
    background: ${theme.colors.background.secondary};
    border: 1px solid ${theme.colors.border.weak};
    border-radius: ${theme.shape.radius.default};
    cursor: pointer;
    &:hover {
      background: ${theme.colors.action.hover};
    }
  `,
  chipActive: css`
    border-color: ${theme.colors.primary.border};
    background: ${theme.colors.action.selected};
  `,
  chipLabel: css`
    color: ${theme.colors.text.primary};
    font-size: ${theme.typography.bodySmall.fontSize};
  `,
  link: css`
    color: ${theme.colors.text.link};
  `,
});
