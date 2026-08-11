import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { AppRootProps } from '@grafana/data';
const SearchPage = React.lazy(() => import('../../pages/Search'));

function App(props: AppRootProps) {
  return (
    <Routes>
      {/* Search is the default (and currently only) page. */}
      <Route path="*" element={<SearchPage />} />
    </Routes>
  );
}

export default App;
