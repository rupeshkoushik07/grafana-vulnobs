import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { css } from '@emotion/css';
import { lastValueFrom } from 'rxjs';
import { GrafanaTheme2, dateTimeFormatTimeAgo } from '@grafana/data';
import { PluginPage, getBackendSrv } from '@grafana/runtime';
import { Alert, Badge, Button, InteractiveTable, LoadingPlaceholder, useStyles2, type Column } from '@grafana/ui';
import pluginJson from '../plugin.json';
import { testIds } from '../components/testIds';
import { ScanResults, type ScanRow } from '../components/ScanResults/ScanResults';
import { SEVERITY_ORDER, severityColor } from '../severity';

const API = `/api/plugins/${pluginJson.id}/resources`;

export interface AssetSummary {
  asset: string;
  source: string;
  namespaces?: string[];
  format: string;
  lastScanned: string;
  counts: Record<string, number>;
  kev: number;
  total: number;
}

interface AssetDetail extends AssetSummary {
  rows?: ScanRow[];
}

interface AssetsResponse {
  assets: AssetSummary[];
  storage: { persistent: boolean; dataDir?: string };
}

interface ScanRun {
  name: string;
  trigger: 'manual' | 'schedule';
  state: 'running' | 'succeeded' | 'failed';
  started?: string;
  ended?: string;
}

// Answer of GET/POST /cluster-scan: whether the app can start the cluster scan
// CronJob, and its most recent run.
export interface ClusterScanStatus {
  available: boolean;
  reason?: string;
  cronJob?: string;
  namespace?: string;
  schedule?: string;
  running: boolean;
  last?: ScanRun;
  // 'agent': Grafana has no access to Kubernetes; an agent in the cluster
  // starts the scan when asked (the app's remote mode).
  mode?: string;
  // The latest Scan now request in that mode, until its run shows up as last.
  request?: ScanRequest;
}

interface ScanRequest {
  id: string;
  requestedAt: string;
  requestedBy?: string;
  state: 'pending' | 'running' | 'succeeded' | 'failed';
  job?: string;
  message?: string;
}

const SCAN_POLL_MS = 5000;

interface WorkloadImage {
  image: string;
  digest?: string;
}

export interface Workload {
  namespace: string;
  kind: string;
  name: string;
  pods: number;
  ready: number;
  images: WorkloadImage[];
}

// Answer of GET /workloads: what runs in the cluster right now, scanned or not.
interface WorkloadsResponse {
  available: boolean;
  reason?: string;
  workloads: Workload[];
  // 'prometheus': built from kube-state-metrics instead of the Kubernetes API.
  source?: string;
  // Set on a GET in that mode: the queries to run against the data source,
  // whose results go back in a POST to get the workloads.
  prometheus?: { datasourceUid: string; queries: Record<string, string> };
}

interface PromSample {
  metric: Record<string, string>;
}

// The slice of a Grafana data frame that carries labels.
interface Frame {
  schema?: { fields?: Array<{ name: string; type?: string; labels?: Record<string, string> }> };
  data?: { values?: unknown[][] };
}

interface DsQueryResponse {
  results?: Record<string, { status?: number; error?: string; frames?: Frame[] }>;
}

// An instant vector comes back as one frame per series, with the series'
// labels on its value field. A table-shaped frame (one column per label) is
// read too, so either answer format works.
export function samplesFromFrames(frames: Frame[] = []): PromSample[] {
  const samples: PromSample[] = [];
  for (const frame of frames) {
    const fields = frame.schema?.fields ?? [];
    const labelled = fields.filter((f) => f.type === 'number' && f.labels);
    if (labelled.length > 0) {
      labelled.forEach((f) => samples.push({ metric: f.labels! }));
      continue;
    }
    const columns = fields.map((f, i) => ({ f, i })).filter(({ f }) => f.type === 'string');
    const rows = frame.data?.values?.[0]?.length ?? 0;
    if (columns.length === 0 && fields.some((f) => f.type === 'number') && rows > 0) {
      samples.push({ metric: {} }); // a series without labels, such as count(...)
      continue;
    }
    for (let row = 0; columns.length > 0 && row < rows; row++) {
      const metric: Record<string, string> = {};
      columns.forEach(({ f, i }) => (metric[f.name] = String(frame.data?.values?.[i]?.[row] ?? '')));
      samples.push({ metric });
    }
  }
  return samples;
}

// Remote mode: run the app's kube-state-metrics queries through the chosen
// Prometheus data source, as the viewer, and let the app turn the series into
// workloads.
async function workloadsFromPrometheus(prom: NonNullable<WorkloadsResponse['prometheus']>): Promise<WorkloadsResponse> {
  const unavailable = (reason: string): WorkloadsResponse => ({
    available: false,
    source: 'prometheus',
    reason,
    workloads: [],
  });
  let results: DsQueryResponse['results'];
  try {
    const resp = await lastValueFrom(
      getBackendSrv().fetch<DsQueryResponse>({
        url: '/api/ds/query',
        method: 'POST',
        showErrorAlert: false,
        data: {
          from: 'now-5m',
          to: 'now',
          queries: Object.entries(prom.queries).map(([refId, expr]) => ({
            refId,
            expr,
            datasource: { uid: prom.datasourceUid },
            instant: true,
            range: false,
          })),
        },
      })
    );
    results = resp.data.results;
  } catch (e) {
    // A failed query still answers with per-query results that say why.
    results = (e as { data?: DsQueryResponse })?.data?.results;
    if (!results) {
      return unavailable(`Could not query the Prometheus data source: ${errorMessage(e, 'request failed')}`);
    }
  }
  const body: Record<string, PromSample[]> = {};
  for (const refId of Object.keys(prom.queries)) {
    const result = results?.[refId];
    if (result?.error) {
      return unavailable(`The Prometheus data source refused a query: ${result.error}`);
    }
    body[refId] = samplesFromFrames(result?.frames);
  }
  const resp = await lastValueFrom(
    getBackendSrv().fetch<WorkloadsResponse>({
      url: `${API}/workloads`,
      method: 'POST',
      data: body,
      showErrorAlert: false,
    })
  );
  return resp.data;
}

// One image of one workload, with its scan result if there is one.
interface WorkloadRow {
  id: string;
  workload: Workload;
  image: string;
  asset?: AssetSummary;
}

// New deployments should appear on their own, without a click.
const WORKLOADS_POLL_MS = 15000;

// The scan job stores an image under its reference, or under
// "<reference>@<digest>" when one tag runs at several digests.
function assetFor(img: WorkloadImage, byName: Map<string, AssetSummary>): AssetSummary | undefined {
  return (img.digest ? byName.get(`${img.image}@${img.digest}`) : undefined) ?? byName.get(img.image);
}

// Not scanned yet first (they need a scan), then the most urgent findings.
function compareRows(a: WorkloadRow, b: WorkloadRow): number {
  if (!a.asset || !b.asset) {
    return a.asset ? 1 : b.asset ? -1 : a.id.localeCompare(b.id);
  }
  return (
    b.asset.kev - a.asset.kev ||
    (b.asset.counts?.CRITICAL ?? 0) - (a.asset.counts?.CRITICAL ?? 0) ||
    (b.asset.counts?.HIGH ?? 0) - (a.asset.counts?.HIGH ?? 0) ||
    b.asset.total - a.asset.total ||
    a.id.localeCompare(b.id)
  );
}

function errorMessage(e: unknown, fallback: string): string {
  const err = e as { data?: { error?: string; message?: string }; statusText?: string };
  return err?.data?.error ?? err?.data?.message ?? err?.statusText ?? fallback;
}

function AssetsPage() {
  const [params, setParams] = useSearchParams();
  const selected = params.get('asset');

  return (
    <PluginPage>
      <div data-testid={testIds.assets.container}>
        {selected ? (
          // Keyed by asset, so opening another one starts from a fresh loading state.
          <AssetDetailView key={selected} name={selected} onBack={() => setParams({})} />
        ) : (
          <AssetList onSelect={(asset) => setParams({ asset })} />
        )}
      </div>
    </PluginPage>
  );
}

function AssetList({ onSelect }: { onSelect: (asset: string) => void }) {
  const s = useStyles2(getStyles);
  const [data, setData] = useState<AssetsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // State is only set once the request settles, so this is safe to call from an effect.
  const fetchAssets = useCallback(
    () =>
      lastValueFrom(getBackendSrv().fetch<AssetsResponse>({ url: `${API}/assets` }))
        .then((resp) => {
          setData(resp.data);
          setError(null);
        })
        .catch((e) => setError(errorMessage(e, 'Could not load assets')))
        .finally(() => setLoading(false)),
    []
  );

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  const refresh = () => {
    setLoading(true);
    fetchAssets();
    fetchWorkloads();
  };

  // Workloads: what runs in the cluster, whether or not it has been scanned.
  // Only there when the backend may list pods, or (in remote mode) when a
  // Prometheus data source has them; otherwise the page is the plain list of
  // scanned assets.
  const [workloads, setWorkloads] = useState<WorkloadsResponse | null>(null);
  const fetchWorkloads = useCallback(
    () =>
      lastValueFrom(getBackendSrv().fetch<WorkloadsResponse>({ url: `${API}/workloads`, showErrorAlert: false }))
        .then((resp) =>
          resp.data.available && resp.data.prometheus ? workloadsFromPrometheus(resp.data.prometheus) : resp.data
        )
        .then(setWorkloads)
        .catch(() => setWorkloads(null)),
    []
  );

  useEffect(() => {
    fetchWorkloads();
  }, [fetchWorkloads]);

  const showWorkloads = Boolean(workloads?.available);
  // In remote mode the admin asked for the list, so say why it isn't there
  // and keep trying: metrics may just not have arrived yet.
  const workloadsProblem = workloads && !workloads.available && workloads.source === 'prometheus' ? workloads : null;
  const pollWorkloads = showWorkloads || Boolean(workloadsProblem);
  useEffect(() => {
    if (!pollWorkloads) {
      return;
    }
    const timer = setInterval(fetchWorkloads, WORKLOADS_POLL_MS);
    return () => clearInterval(timer);
  }, [pollWorkloads, fetchWorkloads]);

  const { workloadRows, otherAssets } = useMemo(() => {
    const assets = data?.assets ?? [];
    const byName = new Map(assets.map((a) => [a.asset, a]));
    const matched = new Set<string>();
    const rows: WorkloadRow[] = [];
    for (const w of workloads?.workloads ?? []) {
      for (const img of w.images ?? []) {
        const asset = assetFor(img, byName);
        if (asset) {
          matched.add(asset.asset);
        }
        rows.push({
          id: `${w.namespace}/${w.kind}/${w.name}/${img.image}@${img.digest ?? ''}`,
          workload: w,
          image: img.image,
          asset,
        });
      }
    }
    rows.sort(compareRows);
    return { workloadRows: rows, otherAssets: assets.filter((a) => !matched.has(a.asset)) };
  }, [workloads, data]);

  // "Scan now": only offered when the backend says it can start the scan
  // CronJob (it runs in Kubernetes with a service account allowed to).
  const [scan, setScan] = useState<ClusterScanStatus | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const wasRunning = useRef(false);

  const fetchScan = useCallback(
    () =>
      lastValueFrom(getBackendSrv().fetch<ClusterScanStatus>({ url: `${API}/cluster-scan`, showErrorAlert: false }))
        .then((resp) => setScan(resp.data))
        .catch(() => setScan(null)),
    []
  );

  useEffect(() => {
    fetchScan();
  }, [fetchScan]);

  // While a run is going, keep asking; when it ends, show what it found.
  const running = Boolean(scan?.available && scan.running);
  useEffect(() => {
    if (wasRunning.current && !running) {
      fetchAssets();
      fetchWorkloads();
    }
    wasRunning.current = running;
    if (!running) {
      return;
    }
    const timer = setInterval(fetchScan, SCAN_POLL_MS);
    return () => clearInterval(timer);
  }, [running, fetchScan, fetchAssets, fetchWorkloads]);

  const startScan = () => {
    setStarting(true);
    setScanError(null);
    lastValueFrom(
      getBackendSrv().fetch<ClusterScanStatus>({ url: `${API}/cluster-scan`, method: 'POST', showErrorAlert: false })
    )
      .then((resp) => setScan(resp.data))
      .catch((e) => {
        // 409: someone else (or the schedule) started one first. Follow that run.
        if ((e as { status?: number })?.status === 409 && (e as { data?: ClusterScanStatus }).data?.available) {
          setScan((e as { data: ClusterScanStatus }).data);
        } else {
          setScanError(errorMessage(e, 'Could not start the cluster scan'));
        }
      })
      .finally(() => setStarting(false));
  };

  const columns: Array<Column<AssetSummary>> = [
    {
      id: 'asset',
      header: 'Asset',
      cell: ({ row: { original: a } }) => (
        <Button fill="text" size="sm" className={s.assetButton} onClick={() => onSelect(a.asset)}>
          {a.asset}
        </Button>
      ),
    },
    {
      id: 'namespaces',
      header: 'Namespaces',
      cell: ({ row: { original: a } }) => <span>{a.namespaces?.length ? a.namespaces.join(', ') : '—'}</span>,
    },
    {
      id: 'severity',
      header: 'Vulnerabilities',
      cell: ({ row: { original: a } }) => vulnerabilityBadges(a),
    },
    {
      id: 'kev',
      header: 'Actively exploited',
      cell: ({ row: { original: a } }) => <span>{a.kev > 0 ? `🔥 ${a.kev}` : '0'}</span>,
    },
    { id: 'total', header: 'Total' },
    {
      id: 'source',
      header: 'Source',
      cell: ({ row: { original: a } }) => <Badge text={a.source || 'api'} color="blue" />,
    },
    {
      id: 'lastScanned',
      header: 'Last scanned',
      cell: ({ row: { original: a } }) => <span>{dateTimeFormatTimeAgo(a.lastScanned)}</span>,
    },
  ];

  const vulnerabilityBadges = (a: AssetSummary) => (
    <span className={s.badges}>
      {SEVERITY_ORDER.filter((sev) => a.counts?.[sev]).map((sev) => (
        <Badge key={sev} text={`${a.counts[sev]} ${sev}`} color={severityColor(sev)} />
      ))}
      {a.total === 0 && <Badge text="none known" color="green" />}
    </span>
  );

  const workloadColumns: Array<Column<WorkloadRow>> = [
    {
      id: 'workload',
      header: 'Workload',
      cell: ({ row: { original: r } }) => (
        <span>
          <span className={s.workloadName}>{r.workload.name}</span> <span className={s.muted}>{r.workload.kind}</span>
        </span>
      ),
    },
    {
      id: 'namespace',
      header: 'Namespace',
      cell: ({ row: { original: r } }) => <span>{r.workload.namespace}</span>,
    },
    {
      id: 'pods',
      header: 'Pods ready',
      cell: ({ row: { original: r } }) => (
        <span>
          {r.workload.ready}/{r.workload.pods}
        </span>
      ),
    },
    {
      id: 'image',
      header: 'Image',
      cell: ({ row: { original: r } }) =>
        r.asset ? (
          <Button fill="text" size="sm" className={s.assetButton} onClick={() => onSelect(r.asset!.asset)}>
            {r.image}
          </Button>
        ) : (
          <span>{r.image}</span>
        ),
    },
    {
      id: 'severity',
      header: 'Vulnerabilities',
      cell: ({ row: { original: r } }) =>
        r.asset ? vulnerabilityBadges(r.asset) : <Badge text="not scanned yet" color="orange" icon="clock-nine" />,
    },
    {
      id: 'kev',
      header: 'Actively exploited',
      cell: ({ row: { original: r } }) => <span>{!r.asset ? '—' : r.asset.kev > 0 ? `🔥 ${r.asset.kev}` : '0'}</span>,
    },
    {
      id: 'lastScanned',
      header: 'Last scanned',
      cell: ({ row: { original: r } }) => <span>{r.asset ? dateTimeFormatTimeAgo(r.asset.lastScanned) : '—'}</span>,
    },
  ];

  const unscanned = workloadRows.filter((r) => !r.asset).length;

  return (
    <>
      <div className={s.header}>
        <p className={s.intro}>
          The latest scan of every ingested asset, matched against live OSV and ranked by exploit risk. The Kubernetes
          deployment builds a CycloneDX SBOM of every image running in the cluster on a schedule, pinned to the digest
          each pod runs; anything else can push a report to the app&apos;s <code>/ingest</code> endpoint.
        </p>
        <div className={s.actions}>
          {scan?.available && (
            <Button
              icon={running ? 'fa fa-spinner' : 'play'}
              onClick={startScan}
              disabled={running || starting}
              data-testid={testIds.assets.scanNow}
              tooltip="Scan every image running in the cluster now, instead of waiting for the schedule"
            >
              {running ? 'Scanning…' : 'Scan now'}
            </Button>
          )}
          <Button icon="sync" variant="secondary" onClick={refresh} disabled={loading}>
            Refresh
          </Button>
        </div>
      </div>

      {scanError && (
        <Alert title="Could not start the cluster scan" severity="error" onRemove={() => setScanError(null)}>
          {scanError}
        </Alert>
      )}
      {scan?.available && scan.request?.state === 'failed' && (
        <Alert title="The requested cluster scan did not start" severity="warning">
          The scan agent in the cluster could not start it: {scan.request.message || 'no reason given'}.
        </Alert>
      )}
      {scan?.available && scan.request?.state === 'pending' ? (
        <p className={s.scanLine} data-testid={testIds.assets.scanStatus}>
          Cluster scan requested{scan.request.requestedBy ? ` by ${scan.request.requestedBy}` : ''}. Waiting for the
          scan agent in the cluster to pick it up.
        </p>
      ) : (
        scan?.available && scan.last && <ScanRunLine run={scan.last} schedule={scan.schedule} />
      )}
      {scan && !scan.available && scan.mode === 'agent' && scan.reason && (
        <p className={s.scanLine} data-testid={testIds.assets.scanStatus}>
          Scan now is unavailable. {scan.reason}.
        </p>
      )}

      {loading && <LoadingPlaceholder text="Loading assets…" />}
      {error && (
        <Alert title="Could not load assets" severity="error">
          {error}
        </Alert>
      )}

      {!loading && !error && data && (
        <>
          {!data.storage?.persistent && (
            <Alert title="Scans are kept in memory only" severity="info">
              They are lost when Grafana restarts. Set <code>dataDir</code> in the app&apos;s settings (jsonData) to
              save them to disk.
            </Alert>
          )}
          {workloadsProblem && (
            <Alert
              title="The list of running workloads is unavailable"
              severity="warning"
              data-testid={testIds.assets.workloadsUnavailable}
            >
              {workloadsProblem.reason}. Scanned assets are listed below.
            </Alert>
          )}
          {showWorkloads && (
            <div data-testid={testIds.assets.workloads}>
              <h4 className={s.sectionTitle}>Running in the cluster</h4>
              {workloads?.source === 'prometheus' && (
                <p className={s.scanLine}>
                  From kube-state-metrics in Prometheus. A new workload shows up after its next scrape.
                </p>
              )}
              {workloadRows.length > 0 ? (
                <>
                  {unscanned > 0 && (
                    <p className={s.scanLine}>
                      {unscanned === 1 ? '1 image has' : `${unscanned} images have`} not been scanned yet.
                      {scan?.available ? ' Scan now picks them up.' : ' The next scheduled scan picks them up.'}
                    </p>
                  )}
                  <InteractiveTable columns={workloadColumns} data={workloadRows} getRowId={(r) => r.id} />
                </>
              ) : (
                <p className={s.scanLine}>Nothing is running outside the excluded namespaces.</p>
              )}
              {otherAssets.length > 0 && (
                <>
                  <h4 className={s.sectionTitle}>Other assets</h4>
                  <p className={s.scanLine}>Scanned, but not running in the cluster now: pushed by something else.</p>
                  <InteractiveTable columns={columns} data={otherAssets} getRowId={(a) => a.asset} />
                </>
              )}
            </div>
          )}
          {showWorkloads ? null : data.assets.length > 0 ? (
            <InteractiveTable columns={columns} data={data.assets} getRowId={(a) => a.asset} />
          ) : (
            <Alert title="No scanned assets yet" severity="info">
              <p>
                Deploy with the Tanka environment in <code>deploy/tanka</code> to scan every image running in your
                cluster on a schedule, or push a Trivy, Grype, CycloneDX or SPDX report:
              </p>
              <pre className={s.pre}>
                {`curl -X POST "<grafana>/api/plugins/${pluginJson.id}/resources/ingest?asset=my-image:1.0" \\
  -H "Content-Type: application/json" --data-binary @report.json`}
              </pre>
            </Alert>
          )}
        </>
      )}
    </>
  );
}

// One line on the latest run of the cluster scan.
function ScanRunLine({ run, schedule }: { run: ScanRun; schedule?: string }) {
  const s = useStyles2(getStyles);
  const how = run.trigger === 'manual' ? 'started by hand' : 'on schedule';
  if (run.state === 'failed') {
    return (
      <Alert title="The last cluster scan failed" severity="warning">
        Job <code>{run.name}</code> ({how}) failed{run.ended ? ` ${dateTimeFormatTimeAgo(run.ended)}` : ''}. Its pod
        logs say which step broke. Assets below are from the last scan that worked.
      </Alert>
    );
  }
  return (
    <p className={s.scanLine} data-testid={testIds.assets.scanStatus}>
      {run.state === 'running' ? (
        <>
          Cluster scan <code>{run.name}</code> is running ({how}
          {run.started ? `, began ${dateTimeFormatTimeAgo(run.started)}` : ''}). Assets update when it finishes.
        </>
      ) : (
        <>
          Last cluster scan finished {run.ended ? dateTimeFormatTimeAgo(run.ended) : 'recently'} ({how}).
          {schedule ? (
            <>
              {' '}
              Schedule: <code>{schedule}</code>.
            </>
          ) : null}
        </>
      )}
    </p>
  );
}

function AssetDetailView({ name, onBack }: { name: string; onBack: () => void }) {
  const s = useStyles2(getStyles);
  const [asset, setAsset] = useState<AssetDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    lastValueFrom(getBackendSrv().fetch<AssetDetail>({ url: `${API}/asset`, params: { name }, showErrorAlert: false }))
      .then((resp) => !cancelled && setAsset(resp.data))
      .catch((e) => !cancelled && setError(errorMessage(e, 'Could not load the asset')))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [name]);

  const rows = asset?.rows ?? [];
  const vulnerablePackages = new Set(rows.map((r) => `${r.ecosystem} ${r.package} ${r.version}`)).size;

  return (
    <>
      <Button icon="arrow-left" variant="secondary" fill="text" onClick={onBack} className={s.back}>
        All assets
      </Button>

      {loading && <LoadingPlaceholder text="Loading asset…" />}
      {error && (
        <Alert title={`No scan stored for ${name}`} severity="warning">
          {error}
        </Alert>
      )}

      {!loading && !error && asset && (
        <ScanResults
          title={asset.asset}
          format={asset.format}
          subtitle={
            <>
              Scanned {dateTimeFormatTimeAgo(asset.lastScanned)} · source {asset.source || 'api'}
              {asset.namespaces?.length ? ` · running in ${asset.namespaces.join(', ')}` : ''}
            </>
          }
          rows={rows}
          stats={[
            { label: 'Vulnerable packages', value: vulnerablePackages },
            { label: 'Vulnerabilities', value: asset.total },
            { label: '🔥 Actively exploited', value: asset.kev },
          ]}
        />
      )}
    </>
  );
}

export default AssetsPage;

const getStyles = (theme: GrafanaTheme2) => ({
  header: css`
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: ${theme.spacing(2)};
    margin-bottom: ${theme.spacing(2)};
  `,
  intro: css`
    color: ${theme.colors.text.secondary};
    max-width: 780px;
    margin: 0;
  `,
  sectionTitle: css`
    margin: ${theme.spacing(2, 0, 1)};
  `,
  workloadName: css`
    font-weight: ${theme.typography.fontWeightMedium};
  `,
  muted: css`
    color: ${theme.colors.text.secondary};
    font-size: ${theme.typography.bodySmall.fontSize};
  `,
  actions: css`
    display: flex;
    flex-shrink: 0;
    gap: ${theme.spacing(1)};
  `,
  scanLine: css`
    color: ${theme.colors.text.secondary};
    font-size: ${theme.typography.bodySmall.fontSize};
    margin: ${theme.spacing(0, 0, 2)};
  `,
  assetButton: css`
    padding: 0;
    font-weight: ${theme.typography.fontWeightMedium};
  `,
  badges: css`
    display: inline-flex;
    flex-wrap: wrap;
    gap: ${theme.spacing(0.5)};
  `,
  back: css`
    margin-bottom: ${theme.spacing(2)};
  `,
  pre: css`
    white-space: pre-wrap;
    margin: ${theme.spacing(1, 0, 0)};
  `,
});
