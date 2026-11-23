import React, { ChangeEvent, useState } from 'react';
import { lastValueFrom } from 'rxjs';
import { css } from '@emotion/css';
import { AppPluginMeta, GrafanaTheme2, PluginConfigPageProps, PluginMeta } from '@grafana/data';
import { DataSourcePicker, getBackendSrv } from '@grafana/runtime';
import { Button, Field, FieldSet, Input, RadioButtonGroup, SecretInput, useStyles2 } from '@grafana/ui';
import { testIds } from '../testIds';

// How the app learns about the cluster. "in-cluster" (the default): through
// the Kubernetes API, which only works when Grafana runs in the cluster.
// "remote": from kube-state-metrics in Prometheus and the in-cluster scan
// agent, so Grafana can run anywhere.
type ClusterMode = 'in-cluster' | 'remote';

type AppPluginSettings = {
  storageUrl?: string;
  clusterMode?: string;
  prometheusDatasourceUid?: string;
  metricsSelector?: string;
};

type State = {
  storageUrl: string;
  storageToken: string;
  isStorageTokenSet: boolean;
  clusterMode: ClusterMode;
  prometheusDatasourceUid: string;
  metricsSelector: string;
  scannerToken: string;
  isScannerTokenSet: boolean;
};

const MIN_SCANNER_TOKEN = 32;

const clusterModes: Array<{ label: string; value: ClusterMode; description: string }> = [
  {
    label: 'Kubernetes API',
    value: 'in-cluster',
    description: 'Grafana runs in the cluster and has a service account',
  },
  {
    label: 'Prometheus and scan agent',
    value: 'remote',
    description: 'Grafana runs anywhere and never talks to Kubernetes',
  },
];

export interface AppConfigProps extends PluginConfigPageProps<AppPluginMeta<AppPluginSettings>> {}

const AppConfig = ({ plugin }: AppConfigProps) => {
  const s = useStyles2(getStyles);
  const { enabled, pinned, jsonData, secureJsonFields } = plugin.meta;
  const [state, setState] = useState<State>({
    storageUrl: jsonData?.storageUrl || '',
    storageToken: '',
    isStorageTokenSet: Boolean(secureJsonFields?.storageToken),
    clusterMode: jsonData?.clusterMode === 'remote' ? 'remote' : 'in-cluster',
    prometheusDatasourceUid: jsonData?.prometheusDatasourceUid || '',
    metricsSelector: jsonData?.metricsSelector || '',
    scannerToken: '',
    isScannerTokenSet: Boolean(secureJsonFields?.scannerToken),
  });

  const remote = state.clusterMode === 'remote';
  const scannerTokenTooShort = Boolean(state.scannerToken) && state.scannerToken.length < MIN_SCANNER_TOKEN;
  const isSubmitDisabled = Boolean(
    !state.storageUrl || (!state.isStorageTokenSet && !state.storageToken) || scannerTokenTooShort
  );

  const onResetStorageToken = () =>
    setState({
      ...state,
      storageToken: '',
      isStorageTokenSet: false,
    });

  const onResetScannerToken = () => setState({ ...state, scannerToken: '', isScannerTokenSet: false });

  const onChange = (event: ChangeEvent<HTMLInputElement>) => {
    setState({
      ...state,
      [event.target.name]: event.target.value.trim(),
    });
  };

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (isSubmitDisabled) {
      return;
    }

    updatePluginAndReload(plugin.meta.id, {
      enabled,
      pinned,
      jsonData: {
        // Settings this form doesn't show (set by provisioning) are kept.
        ...jsonData,
        storageUrl: state.storageUrl,
        clusterMode: state.clusterMode,
        prometheusDatasourceUid: state.prometheusDatasourceUid,
        metricsSelector: state.metricsSelector,
      },
      // Only the secrets typed in now; Grafana keeps the others.
      secureJsonData: secrets(state),
    });
  };

  return (
    <form onSubmit={onSubmit}>
      <FieldSet label="Storage API">
        <Field label="Storage API URL" description="Base URL of the Vulnobs authenticated storage service.">
          <Input
            width={60}
            name="storageUrl"
            id="config-storage-url"
            data-testid={testIds.appConfig.storageUrl}
            value={state.storageUrl}
            placeholder="https://storage.example.com"
            onChange={onChange}
          />
        </Field>
        <Field
          label="Storage API token"
          description="Stored securely by Grafana; use the same token in the Vulnobs datasource."
        >
          <SecretInput
            width={60}
            id="config-storage-token"
            data-testid={testIds.appConfig.storageToken}
            name="storageToken"
            value={state.storageToken}
            isConfigured={state.isStorageTokenSet}
            placeholder="A 32-character or longer token"
            onChange={onChange}
            onReset={onResetStorageToken}
          />
        </Field>
      </FieldSet>

      <FieldSet label="Cluster access">
        <Field
          label="How the app sees the cluster"
          description="The Assets page lists running workloads and offers Scan now. Both need to learn about the cluster one way or the other."
        >
          <RadioButtonGroup
            id="config-cluster-mode"
            options={clusterModes}
            value={state.clusterMode}
            onChange={(clusterMode) => setState({ ...state, clusterMode })}
          />
        </Field>
        {remote && (
          <div data-testid={testIds.appConfig.remote}>
            <Field
              label="Prometheus data source"
              description="The one that holds this cluster's kube-state-metrics series. The workloads list is built from them."
            >
              <DataSourcePicker
                inputId="config-prometheus-datasource"
                width={60}
                noDefault
                filter={(ds) => ds.type.includes('prometheus')}
                current={state.prometheusDatasourceUid || null}
                onChange={(ds) => setState({ ...state, prometheusDatasourceUid: ds.uid })}
              />
            </Field>
            <Field
              label="Metrics selector"
              description={
                'Optional label matchers added to every query, for a Prometheus that holds several clusters: cluster="prod"'
              }
            >
              <Input
                width={60}
                name="metricsSelector"
                id="config-metrics-selector"
                data-testid={testIds.appConfig.metricsSelector}
                value={state.metricsSelector}
                placeholder={'cluster="prod"'}
                onChange={onChange}
              />
            </Field>
            <Field
              label="Scanner token"
              description="The scan job and the scan agent in the cluster send this token; give them the same one. Scan now stays off without it."
              invalid={scannerTokenTooShort}
              error={`Use ${MIN_SCANNER_TOKEN} characters or more`}
            >
              <SecretInput
                width={60}
                id="config-scanner-token"
                data-testid={testIds.appConfig.scannerToken}
                name="scannerToken"
                value={state.scannerToken}
                isConfigured={state.isScannerTokenSet}
                placeholder="A 32-character or longer token"
                onChange={onChange}
                onReset={onResetScannerToken}
              />
            </Field>
          </div>
        )}
      </FieldSet>

      <div className={s.marginTop}>
        <Button type="submit" data-testid={testIds.appConfig.submit} disabled={isSubmitDisabled}>
          Save settings
        </Button>
      </div>
    </form>
  );
};

export default AppConfig;

const getStyles = (theme: GrafanaTheme2) => ({
  marginTop: css`
    margin-top: ${theme.spacing(3)};
  `,
});

const secrets = (state: State): Record<string, string> | undefined => {
  const out: Record<string, string> = {};
  if (!state.isStorageTokenSet && state.storageToken) {
    out.storageToken = state.storageToken;
  }
  if (!state.isScannerTokenSet && state.scannerToken) {
    out.scannerToken = state.scannerToken;
  }
  return Object.keys(out).length > 0 ? out : undefined;
};

const updatePluginAndReload = async (pluginId: string, data: Partial<PluginMeta<AppPluginSettings>>) => {
  try {
    await updatePlugin(pluginId, data);
    window.location.reload();
  } catch (e) {
    console.error('Error while updating the plugin', e);
  }
};

const updatePlugin = async (pluginId: string, data: Partial<PluginMeta>) => {
  const response = await getBackendSrv().fetch({
    url: `/api/plugins/${pluginId}/settings`,
    method: 'POST',
    data,
  });

  return lastValueFrom(response);
};
