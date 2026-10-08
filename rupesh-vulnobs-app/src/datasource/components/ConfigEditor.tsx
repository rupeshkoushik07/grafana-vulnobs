import React, { ChangeEvent } from 'react';
import { InlineField, Input, SecretInput } from '@grafana/ui';
import { DataSourcePluginOptionsEditorProps } from '@grafana/data';
import { MyDataSourceOptions, MySecureJsonData } from '../types';

interface Props extends DataSourcePluginOptionsEditorProps<MyDataSourceOptions, MySecureJsonData> {}

export function ConfigEditor(props: Props) {
  const { onOptionsChange, options } = props;
  const { jsonData, secureJsonFields, secureJsonData } = options;

  const onStorageUrlChange = (event: ChangeEvent<HTMLInputElement>) => {
    onOptionsChange({
      ...options,
      jsonData: {
        ...jsonData,
        storageUrl: event.target.value,
      },
    });
  };

  const onStorageTokenChange = (event: ChangeEvent<HTMLInputElement>) => {
    onOptionsChange({
      ...options,
      secureJsonData: {
        storageToken: event.target.value,
      },
    });
  };

  const onResetStorageToken = () => {
    onOptionsChange({
      ...options,
      secureJsonFields: {
        ...options.secureJsonFields,
        storageToken: false,
      },
      secureJsonData: {
        ...options.secureJsonData,
        storageToken: '',
      },
    });
  };

  return (
    <>
      <InlineField
        label="Storage API URL"
        labelWidth={18}
        interactive
        tooltip="Base URL of the authenticated Vulnobs storage API configured in the app."
      >
        <Input
          id="config-editor-storage-url"
          onChange={onStorageUrlChange}
          value={jsonData.storageUrl}
          placeholder="https://storage.example.com"
          width={40}
        />
      </InlineField>
      <InlineField
        label="Storage API token"
        labelWidth={18}
        interactive
        tooltip="Use the same tenant token configured in the Vulnobs app. Grafana stores it as a secure setting."
      >
        <SecretInput
          id="config-editor-storage-token"
          isConfigured={secureJsonFields.storageToken}
          value={secureJsonData?.storageToken}
          placeholder="A 32-character or longer token"
          width={40}
          onReset={onResetStorageToken}
          onChange={onStorageTokenChange}
        />
      </InlineField>
    </>
  );
}
