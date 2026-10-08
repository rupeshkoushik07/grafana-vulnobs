import React, { ChangeEvent, useState } from 'react';
import { lastValueFrom } from 'rxjs';
import { css } from '@emotion/css';
import { AppPluginMeta, GrafanaTheme2, PluginConfigPageProps, PluginMeta } from '@grafana/data';
import { getBackendSrv } from '@grafana/runtime';
import { Button, Field, FieldSet, Input, SecretInput, useStyles2 } from '@grafana/ui';
import { testIds } from '../testIds';

type AppPluginSettings = {
  storageUrl?: string;
};

type State = {
  storageUrl: string;
  storageToken: string;
  isStorageTokenSet: boolean;
};

export interface AppConfigProps extends PluginConfigPageProps<AppPluginMeta<AppPluginSettings>> {}

const AppConfig = ({ plugin }: AppConfigProps) => {
  const s = useStyles2(getStyles);
  const { enabled, pinned, jsonData, secureJsonFields } = plugin.meta;
  const [state, setState] = useState<State>({
    storageUrl: jsonData?.storageUrl || '',
    storageToken: '',
    isStorageTokenSet: Boolean(secureJsonFields?.storageToken),
  });

  const isSubmitDisabled = Boolean(!state.storageUrl || (!state.isStorageTokenSet && !state.storageToken));

  const onResetStorageToken = () =>
    setState({
      ...state,
      storageToken: '',
      isStorageTokenSet: false,
    });

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
        storageUrl: state.storageUrl,
      },
      secureJsonData: state.isStorageTokenSet ? undefined : { storageToken: state.storageToken },
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
        <Field label="Storage API token" description="Stored securely by Grafana; use the same token in the Vulnobs datasource.">
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
        <div className={s.marginTop}>
          <Button type="submit" data-testid={testIds.appConfig.submit} disabled={isSubmitDisabled}>
            Save storage settings
          </Button>
        </div>
      </FieldSet>
    </form>
  );
};

export default AppConfig;

const getStyles = (theme: GrafanaTheme2) => ({
  marginTop: css`
    margin-top: ${theme.spacing(3)};
  `,
});

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
