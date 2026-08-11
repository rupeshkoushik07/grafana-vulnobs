import React, { ChangeEvent } from 'react';
import { InlineField, Input, SecretInput } from '@grafana/ui';
import { DataSourcePluginOptionsEditorProps } from '@grafana/data';
import { MyDataSourceOptions, MySecureJsonData } from '../types';

interface Props extends DataSourcePluginOptionsEditorProps<MyDataSourceOptions, MySecureJsonData> {}

export function ConfigEditor(props: Props) {
  const { onOptionsChange, options } = props;
  const { jsonData, secureJsonFields, secureJsonData } = options;

  const onBaseUrlChange = (event: ChangeEvent<HTMLInputElement>) => {
    onOptionsChange({
      ...options,
      jsonData: {
        ...jsonData,
        osvBaseUrl: event.target.value,
      },
    });
  };

  // Secure field (only sent to the backend). Reserved for enrichment feeds.
  const onAPIKeyChange = (event: ChangeEvent<HTMLInputElement>) => {
    onOptionsChange({
      ...options,
      secureJsonData: {
        apiKey: event.target.value,
      },
    });
  };

  const onResetAPIKey = () => {
    onOptionsChange({
      ...options,
      secureJsonFields: {
        ...options.secureJsonFields,
        apiKey: false,
      },
      secureJsonData: {
        ...options.secureJsonData,
        apiKey: '',
      },
    });
  };

  return (
    <>
      <InlineField
        label="OSV API URL"
        labelWidth={18}
        interactive
        tooltip={'Base URL of the OSV API. Leave blank to use https://api.osv.dev'}
      >
        <Input
          id="config-editor-osv-url"
          onChange={onBaseUrlChange}
          value={jsonData.osvBaseUrl}
          placeholder="https://api.osv.dev"
          width={40}
        />
      </InlineField>
      <InlineField
        label="API Key (optional)"
        labelWidth={18}
        interactive
        tooltip={'Reserved for NVD / GitHub Advisory enrichment (later phase). Not required for OSV.'}
      >
        <SecretInput
          id="config-editor-api-key"
          isConfigured={secureJsonFields.apiKey}
          value={secureJsonData?.apiKey}
          placeholder="not required for OSV"
          width={40}
          onReset={onResetAPIKey}
          onChange={onAPIKeyChange}
        />
      </InlineField>
    </>
  );
}
