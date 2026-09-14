import React, { useState } from 'react';
import { css } from '@emotion/css';
import { lastValueFrom } from 'rxjs';
import { GrafanaTheme2 } from '@grafana/data';
import { PluginPage, getBackendSrv } from '@grafana/runtime';
import { Alert, FileDropzone, LoadingPlaceholder, useStyles2 } from '@grafana/ui';
import pluginJson from '../plugin.json';
import { testIds } from '../components/testIds';
import { ScanResults, countKev, type ScanRow } from '../components/ScanResults/ScanResults';

const SCAN_URL = `/api/plugins/${pluginJson.id}/resources/scan`;

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

  return (
    <PluginPage>
      <div data-testid={testIds.scan.container}>
        <p className={s.intro}>
          Upload a <strong>Trivy</strong>, <strong>Grype</strong>, <strong>CycloneDX</strong>, or{' '}
          <strong>SPDX</strong> report. Vulnobs extracts its package inventory and matches every package against{' '}
          <a href="https://osv.dev" target="_blank" rel="noreferrer">
            OSV
          </a>{' '}
          live — so you see the vulnerabilities known <em>right now</em>, including ones published after the scan was
          taken.
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
            <ScanResults
              title={result.image || 'scan'}
              format={result.format}
              rows={result.rows}
              stats={[
                { label: 'Packages scanned', value: result.packagesScanned },
                { label: 'Vulnerable packages', value: result.vulnerablePackages },
                { label: 'Vulnerabilities', value: result.rows.length },
                { label: '🔥 Actively exploited', value: countKev(result.rows) },
                ...(result.skippedOsPackages > 0
                  ? [{ label: 'OS packages skipped', value: result.skippedOsPackages, muted: true }]
                  : []),
              ]}
              notice={
                result.truncated && (
                  <Alert title="Large scan truncated" severity="info">
                    Only the first {result.packagesQueried} packages were queried.
                  </Alert>
                )
              }
            />
          )}
        </div>
      </div>
    </PluginPage>
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
});
