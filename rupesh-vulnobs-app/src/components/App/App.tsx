import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { AppRootProps } from '@grafana/data';
import { ROUTES } from '../../constants';
const SearchPage = React.lazy(() => import('../../pages/Search'));
const ScanPage = React.lazy(() => import('../../pages/Scan'));
const AssetsPage = React.lazy(() => import('../../pages/Assets'));

function App(props: AppRootProps) {
  return (
    <Routes>
      <Route path={ROUTES.Scan} element={<ScanPage />} />
      <Route path={ROUTES.Assets} element={<AssetsPage />} />
      {/* Search is the default page. */}
      <Route path="*" element={<SearchPage />} />
    </Routes>
  );
}

export default App;
