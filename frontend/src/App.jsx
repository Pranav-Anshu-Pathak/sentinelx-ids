import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { WebSocketProvider } from './context/WebSocketContext';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import LogsPage from './pages/LogsPage';
import RulesPage from './pages/RulesPage';
import InvestigationsPage from './pages/InvestigationsPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import SettingsPage from './pages/SettingsPage';
import HealthPage from './pages/HealthPage';
import AuditLogPage from './pages/AuditLogPage';

function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return children;
}

function AppRoutes() {
  const { isAuthenticated } = useAuth();

  return (
    <Routes>
      <Route
        path="/login"
        element={
          isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />
        }
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <WebSocketProvider>
              <Layout />
            </WebSocketProvider>
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="investigations" element={<InvestigationsPage />} />
        <Route path="intel" element={<ThreatIntelPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="health" element={<HealthPage />} />
        <Route path="audit" element={<AuditLogPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
