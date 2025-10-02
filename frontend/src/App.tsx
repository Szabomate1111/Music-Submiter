import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import SearchPage from './pages/SearchPage';
import AdminPage from './pages/AdminPage';

function App(): JSX.Element {
  return (
    <div className="dark">
      <Router>
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
          <Routes>
            <Route path="/" element={<SearchPage />} />
            <Route path="/admin" element={<AdminPage />} />
          </Routes>
        </div>
      </Router>
    </div>
  );
}

export default App;