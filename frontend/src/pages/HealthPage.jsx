import { useEffect, useState } from 'react';
import { api } from '../api/client';
import StatusBadge from '../components/StatusBadge';

export default function HealthPage() {
  const [health, setHealth] = useState(null);
  const [metrics, setMetrics] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        setHealth(await api.getHealth());
        setMetrics(await api.getMetrics());
      } catch (e) {
        console.error(e);
      }
    };
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="font-orbitron text-2xl font-bold">System Health</h1>

      {health && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl border border-border-default bg-bg-secondary">
            <p className="text-xs text-text-muted">Status</p>
            <p className="text-lg font-bold text-accent mt-1 capitalize">{health.status}</p>
          </div>
          <div className="p-4 rounded-xl border border-border-default bg-bg-secondary">
            <p className="text-xs text-text-muted">Version</p>
            <p className="text-lg font-mono mt-1">{health.version}</p>
          </div>
          <div className="p-4 rounded-xl border border-border-default bg-bg-secondary">
            <p className="text-xs text-text-muted">Database</p>
            <p className="text-lg mt-1 capitalize">{health.database}</p>
          </div>
          <div className="p-4 rounded-xl border border-border-default bg-bg-secondary">
            <p className="text-xs text-text-muted">Uptime</p>
            <p className="text-lg font-mono mt-1">{Math.floor(health.uptime_seconds)}s</p>
          </div>
        </div>
      )}

      {metrics && (
        <div className="rounded-xl border border-border-default bg-bg-secondary p-6">
          <h2 className="text-sm font-semibold text-text-secondary mb-4">Metrics</h2>
          <dl className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
            <div><dt className="text-text-muted">Events/sec</dt><dd className="font-mono text-accent">{metrics.events_per_second}</dd></div>
            <div><dt className="text-text-muted">Total Logs</dt><dd className="font-mono">{metrics.total_logs}</dd></div>
            <div><dt className="text-text-muted">Total Alerts</dt><dd className="font-mono">{metrics.total_alerts}</dd></div>
            <div><dt className="text-text-muted">Open Alerts</dt><dd className="font-mono">{metrics.open_alerts}</dd></div>
            <div><dt className="text-text-muted">Critical</dt><dd className="font-mono text-danger">{metrics.critical_alerts}</dd></div>
            <div><dt className="text-text-muted">Active Rules</dt><dd className="font-mono">{metrics.active_rules}</dd></div>
          </dl>
        </div>
      )}

      {health?.demo_mode && (
        <p className="text-sm text-warning">Demo mode is enabled — synthetic logs are being generated.</p>
      )}
    </div>
  );
}
