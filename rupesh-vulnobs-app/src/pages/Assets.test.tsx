import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { of } from 'rxjs';
import { render, screen, fireEvent } from '@testing-library/react';
import AssetsPage from './Assets';

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
});
