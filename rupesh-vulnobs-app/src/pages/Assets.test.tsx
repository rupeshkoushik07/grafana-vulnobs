import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { of, throwError } from 'rxjs';
import { render, screen, fireEvent } from '@testing-library/react';
import AssetsPage, { samplesFromFrames } from './Assets';
import { testIds } from '../components/testIds';

const fetchMock = jest.fn();

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  PluginPage: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  getBackendSrv: () => ({ fetch: fetchMock }),
}));

const summary = {
  asset: 'ghcr.io/org/api:1.0',
  source: 'cluster',
  namespaces: ['shop'],
  format: 'trivy',
  lastScanned: new Date().toISOString(),
  counts: { CRITICAL: 1, HIGH: 1 },
  kev: 1,
  total: 2,
};

const row = {
  package: 'org.apache.logging.log4j:log4j-core',
  ecosystem: 'Maven',
  version: '2.14.1',
  id: 'GHSA-jfh8-c2jp-5v3q',
  cve: 'CVE-2021-44228',
  severity: 'CRITICAL',
  severityScore: 4,
  fixedVersion: '2.15.0',
  summary: 'Log4Shell',
  url: 'https://github.com/advisories/GHSA-jfh8-c2jp-5v3q',
  epss: 0.97,
  kev: true,
  priority: 100,
  action: 'now',
};

describe('Assets page', () => {
  beforeEach(() => fetchMock.mockReset());

  test('lists ingested assets and opens one', async () => {
    fetchMock.mockImplementation(({ url }: { url: string }) =>
      url.endsWith('/assets')
        ? of({ data: { assets: [summary], storage: { persistent: true, dataDir: '/var/lib/grafana/vulnobs' } } })
        : of({ data: { ...summary, rows: [row] } })
    );

    render(
      <MemoryRouter>
        <AssetsPage />
      </MemoryRouter>
    );

    const link = await screen.findByRole('button', { name: summary.asset });
    expect(screen.getByText('🔥 1')).toBeInTheDocument();
    expect(screen.getByText('shop')).toBeInTheDocument();

    fireEvent.click(link);

    expect(await screen.findByText('CVE-2021-44228')).toBeInTheDocument();
    expect(screen.getByText(/being actively exploited/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenLastCalledWith(expect.objectContaining({ params: { name: summary.asset } }));
  });

  test('explains how to ingest when there are no assets', async () => {
    fetchMock.mockReturnValue(of({ data: { assets: [], storage: { persistent: false } } }));

    render(
      <MemoryRouter>
        <AssetsPage />
      </MemoryRouter>
    );

    expect(await screen.findByText('No scanned assets yet')).toBeInTheDocument();
    expect(screen.getByText('Scans are kept in memory only')).toBeInTheDocument();
  });

  describe('Scan now', () => {
    const assetsResponse = { data: { assets: [summary], storage: { persistent: true } } };
    const idle = {
      available: true,
      cronJob: 'vulnobs-scan',
      namespace: 'vulnobs',
      schedule: '0 * * * *',
      running: false,
    };
    const runningStatus = {
      ...idle,
      running: true,
      last: { name: 'vulnobs-scan-manual-abc12', trigger: 'manual', state: 'running' },
    };

    const renderPage = () =>
      render(
        <MemoryRouter>
          <AssetsPage />
        </MemoryRouter>
      );

    test('is hidden when Grafana cannot start the scan', async () => {
      fetchMock.mockImplementation(({ url }: { url: string }) =>
        url.endsWith('/cluster-scan')
          ? of({ data: { available: false, reason: 'no service account', running: false } })
          : of(assetsResponse)
      );
      renderPage();

      await screen.findByRole('button', { name: summary.asset });
      expect(screen.queryByTestId(testIds.assets.scanNow)).not.toBeInTheDocument();
    });

    test('starts a run and follows it', async () => {
      fetchMock.mockImplementation(({ url, method }: { url: string; method?: string }) => {
        if (!url.endsWith('/cluster-scan')) {
          return of(assetsResponse);
        }
        return of({ data: method === 'POST' ? runningStatus : idle });
      });
      renderPage();

      const button = await screen.findByTestId(testIds.assets.scanNow);
      expect(button).not.toHaveAttribute('aria-disabled', 'true');
      fireEvent.click(button);

      expect(await screen.findByText(/is running/)).toBeInTheDocument();
      expect(screen.getByText('vulnobs-scan-manual-abc12')).toBeInTheDocument();
      // Grafana's Button marks itself disabled with aria-disabled.
      expect(screen.getByTestId(testIds.assets.scanNow)).toHaveAttribute('aria-disabled', 'true');
      expect(fetchMock).toHaveBeenCalledWith(expect.objectContaining({ method: 'POST' }));
    });

    test('reports why a run could not start', async () => {
      fetchMock.mockImplementation(({ url, method }: { url: string; method?: string }) => {
        if (!url.endsWith('/cluster-scan')) {
          return of(assetsResponse);
        }
        return method === 'POST'
          ? throwError(() => ({ status: 403, data: { error: 'only editors and admins can start a cluster scan' } }))
          : of({ data: idle });
      });
      renderPage();

      fireEvent.click(await screen.findByTestId(testIds.assets.scanNow));
      expect(await screen.findByText('only editors and admins can start a cluster scan')).toBeInTheDocument();
    });

    test('shows a failed run', async () => {
      const failed = { ...idle, last: { name: 'vulnobs-scan-29', trigger: 'schedule', state: 'failed' } };
      fetchMock.mockImplementation(({ url }: { url: string }) =>
        url.endsWith('/cluster-scan') ? of({ data: failed }) : of(assetsResponse)
      );
      renderPage();

      expect(await screen.findByText('The last cluster scan failed')).toBeInTheDocument();
      expect(screen.getByTestId(testIds.assets.scanNow)).not.toHaveAttribute('aria-disabled', 'true');
    });
  });

  describe('Workloads', () => {
    const scanned = { ...summary, asset: 'python:3.12', namespaces: ['shop'] };
    const pushedByCi = { ...summary, asset: 'ci-build:42', source: 'api', namespaces: [], kev: 0 };
    const workloads = {
      available: true,
      workloads: [
        {
          namespace: 'shop',
          kind: 'Deployment',
          name: 'catalog',
          pods: 2,
          ready: 1,
          images: [{ image: 'python:3.12', digest: 'sha256:abc' }],
        },
        {
          namespace: 'payments',
          kind: 'StatefulSet',
          name: 'ledger',
          pods: 1,
          ready: 1,
          images: [{ image: 'redis:7' }],
        },
      ],
    };

    const mockBackend = (workloadsData: unknown) =>
      fetchMock.mockImplementation(({ url }: { url: string }) => {
        if (url.endsWith('/workloads')) {
          return of({ data: workloadsData });
        }
        if (url.endsWith('/cluster-scan')) {
          return of({ data: { available: false, running: false } });
        }
        return of({ data: { assets: [scanned, pushedByCi], storage: { persistent: true } } });
      });

    const renderPage = () =>
      render(
        <MemoryRouter>
          <AssetsPage />
        </MemoryRouter>
      );

    test('shows the scan job\'s pod while it runs', async () => {
      mockBackend({
        ...workloads,
        scanPods: [
          {
            namespace: 'vulnobs',
            job: 'vulnobs-scan-manual-abc12',
            pod: 'vulnobs-scan-manual-abc12-xk2p9',
            step: 'trivy',
            images: ['vulnobs:1', 'trivy:0.74'],
          },
        ],
      });
      renderPage();

      expect(await screen.findByText('Scanning now')).toBeInTheDocument();
      expect(screen.getByText('vulnobs-scan-manual-abc12-xk2p9')).toBeInTheDocument();
      expect(screen.getByText(/Step 2 of 3: building a package list/)).toBeInTheDocument();
    });

    test('shows what runs in the cluster, scanned or not', async () => {
      mockBackend(workloads);
      renderPage();

      expect(await screen.findByText('Running in the cluster')).toBeInTheDocument();
      // The scanned workload links to its findings; the other one says it is waiting.
      expect(screen.getByText('catalog')).toBeInTheDocument();
      expect(screen.getByText('1/2')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'python:3.12' })).toBeInTheDocument();
      expect(screen.getByText('ledger')).toBeInTheDocument();
      expect(screen.getByText('redis:7')).toBeInTheDocument();
      expect(screen.getByText('not scanned yet')).toBeInTheDocument();
      expect(screen.getByText(/1 image has not been scanned yet/)).toBeInTheDocument();
      // An asset nothing in the cluster runs is still listed, separately.
      expect(screen.getByText('Other assets')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'ci-build:42' })).toBeInTheDocument();
    });

    test('falls back to the plain asset list when pods cannot be listed', async () => {
      mockBackend({ available: false, reason: 'forbidden', workloads: [] });
      renderPage();

      expect(await screen.findByRole('button', { name: 'python:3.12' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'ci-build:42' })).toBeInTheDocument();
      expect(screen.queryByTestId(testIds.assets.workloads)).not.toBeInTheDocument();
      expect(screen.queryByText('not scanned yet')).not.toBeInTheDocument();
    });
  });
  // The app's remote mode: Grafana has no access to Kubernetes. Workloads come
  // from kube-state-metrics through a Prometheus data source, and Scan now is
  // a request the in-cluster scan agent picks up.
  describe('Remote mode', () => {
    const scanned = { ...summary, asset: 'python:3.12', namespaces: ['shop'] };
    const queries = {
      containers: 'group by (namespace, pod, container, image, image_spec, image_id) (kube_pod_container_info{})',
      owners: 'group by (namespace, pod, owner_kind, owner_name, owner_is_controller) (kube_pod_owner{})',
      present: 'count(kube_pod_container_info{})',
    };
    const instructions = {
      available: true,
      source: 'prometheus',
      prometheus: { datasourceUid: 'prom-uid', queries },
      workloads: [],
    };
    // One frame per series, labels on the value field: how Grafana answers an instant query.
    const series = (labels: Record<string, string>) => ({
      schema: {
        fields: [
          { name: 'Time', type: 'time' },
          { name: 'Value', type: 'number', labels },
        ],
      },
      data: { values: [[1], [1]] },
    });
    const container = { namespace: 'shop', pod: 'catalog-1', container: 'app', image_spec: 'python:3.12' };
    const dsAnswer = {
      results: {
        containers: { status: 200, frames: [series(container)] },
        owners: { status: 200, frames: [] },
        present: { status: 200, frames: [series({})] },
      },
    };
    const mapped = {
      available: true,
      source: 'prometheus',
      workloads: [
        {
          namespace: 'shop',
          kind: 'Deployment',
          name: 'catalog',
          pods: 2,
          ready: 1,
          images: [{ image: 'python:3.12' }],
        },
        {
          namespace: 'payments',
          kind: 'StatefulSet',
          name: 'ledger',
          pods: 1,
          ready: 1,
          images: [{ image: 'redis:7' }],
        },
      ],
    };
    const agentIdle = {
      available: true,
      mode: 'agent',
      cronJob: 'vulnobs-scan',
      namespace: 'vulnobs',
      schedule: '0 * * * *',
      running: false,
    };

    interface Call {
      url: string;
      method?: string;
      data?: unknown;
    }
    // ds: what the data source answers; scan: what /cluster-scan answers to GET and POST.
    const mockBackend = (opts: {
      ds?: () => unknown;
      workloads?: unknown;
      scanGet?: unknown;
      scanPost?: () => unknown;
    }) =>
      fetchMock.mockImplementation(({ url, method }: Call) => {
        if (url === '/api/ds/query') {
          return opts.ds ? opts.ds() : of({ data: dsAnswer });
        }
        if (url.endsWith('/workloads')) {
          return of({ data: method === 'POST' ? mapped : (opts.workloads ?? instructions) });
        }
        if (url.endsWith('/cluster-scan')) {
          return method === 'POST' && opts.scanPost
            ? opts.scanPost()
            : of({ data: opts.scanGet ?? { available: false, mode: 'agent', running: false } });
        }
        return of({ data: { assets: [scanned], storage: { persistent: true } } });
      });

    const renderPage = () =>
      render(
        <MemoryRouter>
          <AssetsPage />
        </MemoryRouter>
      );
    const calls = (match: (c: Call) => boolean) => fetchMock.mock.calls.map(([c]) => c as Call).filter(match);

    test('builds the workloads list from the Prometheus data source', async () => {
      mockBackend({});
      renderPage();

      expect(await screen.findByText('Running in the cluster')).toBeInTheDocument();
      expect(screen.getByText(/From kube-state-metrics in Prometheus/)).toBeInTheDocument();
      // Same rows as with the Kubernetes API: scanned or waiting.
      expect(screen.getByText('catalog')).toBeInTheDocument();
      expect(screen.getByText('1/2')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'python:3.12' })).toBeInTheDocument();
      expect(screen.getByText('ledger')).toBeInTheDocument();
      expect(screen.getByText('not scanned yet')).toBeInTheDocument();

      // The app's queries went to the chosen data source, as instant queries...
      const [ds] = calls((c) => c.url === '/api/ds/query');
      expect(ds.method).toBe('POST');
      expect((ds.data as { queries: unknown[] }).queries).toEqual(
        Object.entries(queries).map(([refId, expr]) => ({
          refId,
          expr,
          datasource: { uid: 'prom-uid' },
          instant: true,
          range: false,
        }))
      );
      // ...and the series' labels went back to the app to be mapped.
      const [post] = calls((c) => c.url.endsWith('/workloads') && c.method === 'POST');
      expect(post.data).toEqual({ containers: [{ metric: container }], owners: [], present: [{ metric: {} }] });
    });

    test('says why when the data source cannot be queried', async () => {
      mockBackend({ ds: () => throwError(() => ({ status: 404, data: { message: 'Data source not found' } })) });
      renderPage();

      const alert = await screen.findByTestId(testIds.assets.workloadsUnavailable);
      expect(alert).toHaveTextContent('Data source not found');
      // The scanned assets are still there, as the plain list.
      expect(screen.getByRole('button', { name: 'python:3.12' })).toBeInTheDocument();
      expect(screen.queryByTestId(testIds.assets.workloads)).not.toBeInTheDocument();
      expect(calls((c) => c.url.endsWith('/workloads') && c.method === 'POST')).toHaveLength(0);
    });

    test('says why when a query fails or the app has no data source', async () => {
      mockBackend({
        ds: () =>
          throwError(() => ({
            status: 400,
            data: { results: { containers: { status: 400, error: 'parse error: unexpected }' } } },
          })),
      });
      const { unmount } = renderPage();
      expect(await screen.findByTestId(testIds.assets.workloadsUnavailable)).toHaveTextContent('parse error');
      unmount();

      fetchMock.mockReset();
      mockBackend({
        workloads: {
          available: false,
          source: 'prometheus',
          reason: 'No Prometheus data source is chosen',
          workloads: [],
        },
      });
      renderPage();
      expect(await screen.findByTestId(testIds.assets.workloadsUnavailable)).toHaveTextContent(
        'No Prometheus data source is chosen'
      );
      expect(calls((c) => c.url === '/api/ds/query')).toHaveLength(0);
    });

    test('Scan now records a request and waits for the scan agent', async () => {
      const pending = {
        ...agentIdle,
        running: true,
        request: { id: 'r1', requestedAt: new Date().toISOString(), requestedBy: 'rosa', state: 'pending' },
      };
      mockBackend({ scanGet: agentIdle, scanPost: () => of({ data: pending }) });
      renderPage();

      const button = await screen.findByTestId(testIds.assets.scanNow);
      expect(button).not.toHaveAttribute('aria-disabled', 'true');
      fireEvent.click(button);

      expect(await screen.findByText(/requested by rosa/)).toBeInTheDocument();
      expect(screen.getByText(/Waiting for the scan agent/)).toBeInTheDocument();
      expect(screen.getByTestId(testIds.assets.scanNow)).toHaveAttribute('aria-disabled', 'true');
    });

    test('follows the run the agent started, like an in-cluster one', async () => {
      const running = {
        ...agentIdle,
        running: true,
        last: { name: 'vulnobs-scan-manual-abc12', trigger: 'manual', state: 'running' },
        request: {
          id: 'r1',
          requestedAt: new Date().toISOString(),
          state: 'running',
          job: 'vulnobs-scan-manual-abc12',
        },
      };
      mockBackend({ scanGet: running });
      renderPage();

      expect(await screen.findByText(/is running/)).toBeInTheDocument();
      expect(screen.getByText('vulnobs-scan-manual-abc12')).toBeInTheDocument();
      expect(screen.getByTestId(testIds.assets.scanNow)).toHaveAttribute('aria-disabled', 'true');
    });

    test('shows why the agent could not start the scan', async () => {
      const failed = {
        ...agentIdle,
        request: {
          id: 'r1',
          requestedAt: new Date().toISOString(),
          state: 'failed',
          message: 'jobs.batch is forbidden',
        },
      };
      mockBackend({ scanGet: failed });
      renderPage();

      expect(await screen.findByText('The requested cluster scan did not start')).toBeInTheDocument();
      expect(screen.getByText(/jobs.batch is forbidden/)).toBeInTheDocument();
      // A new attempt is possible.
      expect(screen.getByTestId(testIds.assets.scanNow)).not.toHaveAttribute('aria-disabled', 'true');
    });

    test('says why Scan now is off when no agent is connected', async () => {
      mockBackend({
        scanGet: { available: false, mode: 'agent', running: false, reason: 'No scan agent has connected yet' },
      });
      renderPage();

      expect(await screen.findByText(/No scan agent has connected yet/)).toBeInTheDocument();
      expect(screen.queryByTestId(testIds.assets.scanNow)).not.toBeInTheDocument();
    });
  });

  test('reads series labels from either frame shape', () => {
    const perSeries = {
      schema: {
        fields: [
          { name: 'Time', type: 'time' },
          { name: 'Value', type: 'number', labels: { pod: 'a' } },
        ],
      },
      data: { values: [[1], [1]] },
    };
    const table = {
      schema: {
        fields: [
          { name: 'Time', type: 'time' },
          { name: 'namespace', type: 'string' },
          { name: 'pod', type: 'string' },
          { name: 'Value', type: 'number' },
        ],
      },
      data: {
        values: [
          [1, 1],
          ['shop', 'shop'],
          ['b', 'c'],
          [1, 1],
        ],
      },
    };
    expect(samplesFromFrames([perSeries, table])).toEqual([
      { metric: { pod: 'a' } },
      { metric: { namespace: 'shop', pod: 'b' } },
      { metric: { namespace: 'shop', pod: 'c' } },
    ]);
    expect(samplesFromFrames(undefined)).toEqual([]);
  });
});
