import React from 'react';
import { of } from 'rxjs';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { PluginType } from '@grafana/data';
import AppConfig, { AppConfigProps } from './AppConfig';
import { testIds } from 'components/testIds';

const fetchMock = jest.fn();

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  getBackendSrv: () => ({ fetch: fetchMock }),
  // The real picker needs Grafana's data source service.
  DataSourcePicker: ({ current, onChange }: { current: string | null; onChange: (ds: { uid: string }) => void }) => (
    <button type="button" data-testid="ds-picker" onClick={() => onChange({ uid: 'prom-uid' })}>
      {current ?? 'none'}
    </button>
  ),
}));

describe('Components/AppConfig', () => {
  let props: AppConfigProps;

  beforeEach(() => {
    jest.resetAllMocks();

    props = {
      plugin: {
        meta: {
          id: 'sample-app',
          name: 'Sample App',
          type: PluginType.app,
          enabled: true,
          jsonData: {},
        },
      },
      query: {},
    } as unknown as AppConfigProps;
  });

  test('renders the storage API URL and token fields', () => {
    const plugin = { meta: { ...props.plugin.meta, enabled: false } };

    // @ts-ignore - We don't need to provide `addConfigPage()` and `setChannelSupport()` for these tests
    render(<AppConfig plugin={plugin} query={props.query} />);

    expect(screen.queryByRole('group', { name: /storage api/i })).toBeInTheDocument();
    expect(screen.queryByTestId(testIds.appConfig.storageToken)).toBeInTheDocument();
    expect(screen.queryByTestId(testIds.appConfig.storageUrl)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /save settings/i })).toBeInTheDocument();
    // The default mode asks for nothing more.
    expect(screen.getByRole('radio', { name: /kubernetes api/i })).toBeChecked();
    expect(screen.queryByTestId(testIds.appConfig.remote)).not.toBeInTheDocument();
  });

  test('saves the remote mode settings and keeps the ones it does not show', async () => {
    fetchMock.mockReturnValue(of({ data: {} }));
    const plugin = {
      meta: {
        ...props.plugin.meta,
        jsonData: { storageUrl: 'http://storage:8080', scanCronJob: 'my-scan' },
        secureJsonFields: { storageToken: true },
      },
    };

    // @ts-ignore - see above
    render(<AppConfig plugin={plugin} query={props.query} />);

    fireEvent.click(screen.getByRole('radio', { name: /prometheus and scan agent/i }));
    fireEvent.click(screen.getByTestId('ds-picker'));
    fireEvent.change(screen.getByTestId(testIds.appConfig.metricsSelector), { target: { value: 'cluster="prod"' } });

    // A token too short for the backend to accept can't be saved.
    fireEvent.change(screen.getByTestId(testIds.appConfig.scannerToken), { target: { value: 'short' } });
    expect(screen.getByTestId(testIds.appConfig.submit)).toBeDisabled();
    const token = 'a'.repeat(32);
    fireEvent.change(screen.getByTestId(testIds.appConfig.scannerToken), { target: { value: token } });
    fireEvent.click(screen.getByTestId(testIds.appConfig.submit));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(fetchMock).toHaveBeenCalledWith(
      expect.objectContaining({
        url: '/api/plugins/sample-app/settings',
        method: 'POST',
        data: expect.objectContaining({
          jsonData: {
            storageUrl: 'http://storage:8080',
            scanCronJob: 'my-scan',
            clusterMode: 'remote',
            prometheusDatasourceUid: 'prom-uid',
            metricsSelector: 'cluster="prod"',
          },
          // The storage token is already set, so only the new secret is sent.
          secureJsonData: { scannerToken: token },
        }),
      })
    );
  });
});
