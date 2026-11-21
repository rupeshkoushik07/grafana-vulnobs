import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { of, throwError } from 'rxjs';
import { render, screen, fireEvent } from '@testing-library/react';
import AssetsPage from './Assets';
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
});
