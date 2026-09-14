import React, { useMemo } from 'react';
import { css } from '@emotion/css';
import { GrafanaTheme2 } from '@grafana/data';
import { Alert, Badge, BadgeColor, InteractiveTable, useStyles2, type Column } from '@grafana/ui';
import { SEVERITY_ORDER, severityColor } from '../../severity';

/** One (package, vulnerability) finding, as returned by the app's scan and asset endpoints. */
export interface ScanRow {
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

export interface ResultStat {
  label: string;
  value: number;
  muted?: boolean;
}

interface Props {
  title: string;
  format?: string;
  subtitle?: React.ReactNode;
  stats: ResultStat[];
  rows: ScanRow[];
  /** Shown under the summary, e.g. a truncation notice. */
  notice?: React.ReactNode;
}

const ACTION_COLOR: Record<string, BadgeColor> = {
  now: 'red',
  urgent: 'orange',
  soon: 'purple',
  backlog: 'darkgrey',
};

export function countKev(rows: ScanRow[]): number {
  return rows.filter((r) => r.kev).length;
}

/**
 * A scan's findings ranked by exploit risk: a summary card, a callout for
 * actively exploited vulnerabilities, severity counts and the findings table.
 * Used by the Scan page and for ingested assets.
 */
export function ScanResults({ title, format, subtitle, stats, rows, notice }: Props) {
  const s = useStyles2(getStyles);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of rows) {
      c[r.severity] = (c[r.severity] ?? 0) + 1;
    }
    return SEVERITY_ORDER.filter((sev) => c[sev]).map((sev) => ({ severity: sev, count: c[sev] }));
  }, [rows]);

  const kevCount = useMemo(() => countKev(rows), [rows]);

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
    <>
      <div className={s.summaryCard}>
        <div className={s.summaryHead}>
          <span className={s.title}>{title}</span>
          {format && <Badge text={format} color="blue" />}
        </div>
        {subtitle && <div className={s.subtitle}>{subtitle}</div>}
        <div className={s.stats}>
          {stats.map((stat) => (
            <div key={stat.label} className={s.stat}>
              <span className={stat.muted ? s.statValueMuted : s.statValue}>{stat.value}</span>
              <span className={s.statLabel}>{stat.label}</span>
            </div>
          ))}
        </div>
        {notice}
      </div>

      {kevCount > 0 && (
        <Alert
          title={`${kevCount} vulnerabilit${kevCount === 1 ? 'y is' : 'ies are'} being actively exploited`}
          severity="error"
        >
          These carry a 🔥 and are ranked first — patch them now. The rest are ordered by exploit probability (EPSS), so
          severity alone no longer sets the order.
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

      {rows.length > 0 ? (
        <InteractiveTable columns={columns} data={rows} getRowId={(r) => `${r.package}-${r.id}`} />
      ) : (
        <Alert title="No known vulnerabilities" severity="success">
          OSV reported no current vulnerabilities for these packages.
        </Alert>
      )}
    </>
  );
}

const getStyles = (theme: GrafanaTheme2) => ({
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
    margin-bottom: ${theme.spacing(1)};
  `,
  title: css`
    font-size: ${theme.typography.h4.fontSize};
    font-weight: ${theme.typography.fontWeightMedium};
    word-break: break-all;
  `,
  subtitle: css`
    color: ${theme.colors.text.secondary};
    margin-bottom: ${theme.spacing(2)};
  `,
  stats: css`
    display: flex;
    flex-wrap: wrap;
    gap: ${theme.spacing(3)};
    margin-top: ${theme.spacing(1)};
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
