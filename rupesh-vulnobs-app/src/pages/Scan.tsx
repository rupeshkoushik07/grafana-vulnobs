import React, { useMemo, useState } from 'react';
import { css } from '@emotion/css';
import { lastValueFrom } from 'rxjs';
import { GrafanaTheme2 } from '@grafana/data';
import { PluginPage, getBackendSrv } from '@grafana/runtime';
import {
  Alert,
  Badge,
  BadgeColor,
  FileDropzone,
  InteractiveTable,
  LoadingPlaceholder,
  useStyles2,
  type Column,
} from '@grafana/ui';
import pluginJson from '../plugin.json';
import { testIds } from '../components/testIds';
import { SEVERITY_ORDER, severityColor } from '../severity';

const SCAN_URL = `/api/plugins/${pluginJson.id}/resources/scan`;

interface ScanRow {
  package: string;
  ecosystem: string;
  version: string;
  id: string;
  cve: string;
  severity: string;
  severityScore: number;
  fixedVersion: string;
  summary: string;
  url: string;
  epss: number;
  kev: boolean;
  priority: number;
  action: string;
}

const ACTION_COLOR: Record<string, BadgeColor> = {
  now: 'red',
  urgent: 'orange',
  soon: 'purple',
  backlog: 'darkgrey',
};

interface ScanResult {
  format: string;
  image: string;
  packagesScanned: number;
  packagesQueried: number;
  vulnerablePackages: number;
  skippedOsPackages: number;
  truncated: boolean;
  rows: ScanRow[];
}

function ScanPage() {
  const s = useStyles2(getStyles);

  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onLoad = async (content: string | ArrayBuffer | null) => {
    if (typeof content !== 'string') {
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const resp = await lastValueFrom(
        getBackendSrv().fetch<ScanResult>({
          url: SCAN_URL,
          method: 'POST',
          data: content,
          headers: { 'Content-Type': 'application/json' },
        })
      );
      setResult(resp.data);
    } catch (e: any) {
      setError(e?.data?.error ?? e?.statusText ?? 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of result?.rows ?? []) {
      c[r.severity] = (c[r.severity] ?? 0) + 1;
    }
    return SEVERITY_ORDER.filter((sev) => c[sev]).map((sev) => ({ severity: sev, count: c[sev] }));
  }, [result]);

  const kevCount = useMemo(() => (result?.rows ?? []).filter((r) => r.kev).length, [result]);

  const columns: Array<Column<ScanRow>> = [
    {
      id: 'priority',
      header: 'Priority',
      cell: ({ row: { original: r } }) => (
        <span className={s.priorityCell}>
          {r.kev && <span title="Actively exploited (CISA KEV)">🔥</span>}
          <Badge text={r.action} color={ACTION_COLOR[r.action] ?? 'darkgrey'} />
        </span>
      ),
    },
    {
      id: 'severity',
      header: 'Severity',
      cell: ({ row: { original: r } }) => <Badge text={r.severity} color={severityColor(r.severity)} />,
    },
    { id: 'package', header: 'Package' },
    { id: 'version', header: 'Version' },
    {
      id: 'cve',
      header: 'CVE / Advisory',
      cell: ({ row: { original: r } }) => (
        <a className={s.link} href={r.url} target="_blank" rel="noreferrer">
          {r.cve || r.id}
        </a>
      ),
    },
    {
      id: 'epss',
      header: 'EPSS',
      cell: ({ row: { original: r } }) => <span>{r.cve ? `${(r.epss * 100).toFixed(1)}%` : '—'}</span>,
    },
    { id: 'fixedVersion', header: 'Fixed in' },
  ];

  return (
    <PluginPage>
      <div data-testid={testIds.scan.container}>
        <p className={s.intro}>
          Upload a <strong>Trivy</strong>, <strong>Grype</strong>, <strong>CycloneDX</strong>, or{' '}
          <strong>SPDX</strong> report. Vulnobs extracts its package inventory and matches every package against{' '}
          <a href="https://osv.dev" target="_blank" rel="noreferrer">OSV</a> live — so you see the vulnerabilities known{' '}
          <em>right now</em>, including ones published after the scan was taken.
        </p>

        <div data-testid={testIds.scan.dropzone}>
          <FileDropzone
            readAs="readAsText"
            options={{ multiple: false }}
            onLoad={onLoad}
            onFileRemove={() => setResult(null)}
          />
        </div>

        <div className={s.results}>
          {loading && <LoadingPlaceholder text="Matching packages against OSV…" />}
          {error && (
            <Alert title="Scan failed" severity="error">
              {error}
            </Alert>
          )}

          {!loading && !error && result && (
            <>
              <div className={s.summaryCard}>
                <div className={s.summaryHead}>
                  <span className={s.image}>{result.image || 'scan'}</span>
                  <Badge text={result.format} color="blue" />
                </div>
                <div className={s.stats}>
                  <Stat label="Packages scanned" value={result.packagesScanned} />
                  <Stat label="Vulnerable packages" value={result.vulnerablePackages} />
                  <Stat label="Vulnerabilities" value={result.rows.length} />
                  <Stat label="🔥 Actively exploited" value={kevCount} />
                  {result.skippedOsPackages > 0 && (
                    <Stat label="OS packages skipped" value={result.skippedOsPackages} muted />
                  )}
                </div>
                {result.truncated && (
                  <Alert title="Large scan truncated" severity="info">
                    Only the first {result.packagesQueried} packages were queried.
                  </Alert>
                )}
              </div>

              {kevCount > 0 && (
                <Alert title={`${kevCount} vulnerabilit${kevCount === 1 ? 'y is' : 'ies are'} being actively exploited`} severity="error">
                  These carry a 🔥 and are ranked first — patch them now. The rest are ordered by exploit
                  probability (EPSS), so severity alone no longer sets the order.
                </Alert>
              )}

              {counts.length > 0 && (
                <div className={s.summary}>
                  {counts.map(({ severity, count }) => (
                    <span key={severity} className={s.chip}>
                      <Badge text={String(count)} color={severityColor(severity)} />
                      <span className={s.chipLabel}>{severity}</span>
                    </span>
                  ))}
                </div>
              )}

              {result.rows.length > 0 ? (
                <InteractiveTable columns={columns} data={result.rows} getRowId={(r) => `${r.package}-${r.id}`} />
              ) : (
                <Alert title="No known vulnerabilities" severity="success">
                  OSV reported no current vulnerabilities for the packages in this scan.
                </Alert>
              )}
            </>
          )}
        </div>
      </div>
    </PluginPage>
  );
}

function Stat({ label, value, muted }: { label: string; value: number; muted?: boolean }) {
  const s = useStyles2(getStyles);
  return (
    <div className={s.stat}>
      <span className={muted ? s.statValueMuted : s.statValue}>{value}</span>
      <span className={s.statLabel}>{label}</span>
    </div>
  );
}

export default ScanPage;

const getStyles = (theme: GrafanaTheme2) => ({
  intro: css`
    color: ${theme.colors.text.secondary};
    margin-bottom: ${theme.spacing(2)};
    max-width: 780px;
  `,
  results: css`
    margin-top: ${theme.spacing(3)};
  `,
  summaryCard: css`
    padding: ${theme.spacing(2)};
    background: ${theme.colors.background.secondary};
    border: 1px solid ${theme.colors.border.weak};
    border-radius: ${theme.shape.radius.default};
    margin-bottom: ${theme.spacing(2)};
  `,
  summaryHead: css`
    display: flex;
    align-items: center;
    gap: ${theme.spacing(1)};
    margin-bottom: ${theme.spacing(2)};
  `,
  image: css`
    font-size: ${theme.typography.h4.fontSize};
    font-weight: ${theme.typography.fontWeightMedium};
  `,
  stats: css`
    display: flex;
    flex-wrap: wrap;
    gap: ${theme.spacing(3)};
  `,
  stat: css`
    display: flex;
    flex-direction: column;
  `,
  statValue: css`
    font-size: ${theme.typography.h2.fontSize};
    font-weight: ${theme.typography.fontWeightBold};
  `,
  statValueMuted: css`
    font-size: ${theme.typography.h2.fontSize};
    font-weight: ${theme.typography.fontWeightBold};
    color: ${theme.colors.text.secondary};
  `,
  statLabel: css`
    color: ${theme.colors.text.secondary};
    font-size: ${theme.typography.bodySmall.fontSize};
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
  `,
  chipLabel: css`
    color: ${theme.colors.text.primary};
    font-size: ${theme.typography.bodySmall.fontSize};
  `,
  link: css`
    color: ${theme.colors.text.link};
  `,
  priorityCell: css`
    display: inline-flex;
    align-items: center;
    gap: ${theme.spacing(0.5)};
  `,
});
