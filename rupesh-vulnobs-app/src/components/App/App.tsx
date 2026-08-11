import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { AppRootProps } from '@grafana/data';
import { ROUTES } from '../../constants';
const SearchPage = React.lazy(() => import('../../pages/Search'));
const ScanPage = React.lazy(() => import('../../pages/Scan'));

function App(props: AppRootProps) {
  return (
    <Routes>
      <Route path={ROUTES.Scan} element={<ScanPage />} />
      {/* Search is the default page. */}
      <Route path="*" element={<SearchPage />} />
    </Routes>
  );
}

export default App;
