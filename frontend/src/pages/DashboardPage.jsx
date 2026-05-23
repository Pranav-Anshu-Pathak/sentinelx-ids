import { useEffect, useState } from 'react';
import { Activity, Zap, List, Crosshair, AlertTriangle, Sparkles, Cpu } from 'lucide-react';
import { api } from '../api/client';
import AIButton from '../components/AIButton';
import AIModal from '../components/AIModal';
import MetricCard from '../components/MetricCard';
import AlertFeed from '../components/AlertFeed';
import LogStream from '../components/LogStream';
import MitreHeatmap from '../components/MitreHeatmap';
import { useWebSocket } from '../context/WebSocketContext';

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const diff = Math.floor((Date.now() - d) / 60000);
  if (diff < 1) return 'just now';
  if (diff < 60) return `${diff} min ago`;
  return d.toLocaleTimeString();
}

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [modal, setModal] = useState({ open: false, title: '', body: '', provider: '' });
  const { subscribe } = useWebSocket();

  const load = async () => {
    try {
      const dash = await api.getDashboard();
      setData(dash);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    load();
    api.getAiStatus().then(setAiStatus).catch(() => {});
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, []);

  const askCopilot = async () => {
    setAiLoading(true);
    try {
      const open = data?.metrics?.open_alerts ?? 0;
      const res = await api.aiChat(
        `Give a brief SOC briefing: ${open} open alerts, summarize priorities.`
      );
      setModal({ open: true, title: 'SOC Briefing', body: res.reply, provider: res.provider });
    } catch (e) {
      setModal({ open: true, title: 'Error', body: e.message, provider: '' });
    } finally {
      setAiLoading(false);
    }
  };

  useEffect(() => {
    return subscribe('*', () => load());
  }, [subscribe]);

  const m = data?.metrics || {};
  const alerts = (data?.recent_alerts || []).map((a) => ({
    id: a.id,
    title: a.title,
    severity: a.severity,
    source_ip: a.source_ip,
    hostname: a.hostname || '—',
    timestamp: formatTime(a.created_at),
  }));

  const logs = (data?.recent_logs || []).map((l) => ({
    id: l.id,
    timestamp: new Date(l.timestamp).toLocaleTimeString(),
    severity: (l.severity || 'info').toUpperCase(),
    source: (l.source || 'syslog').toUpperCase(),
    message: l.raw_message,
    ip: l.source_ip,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-orbitron text-2xl font-bold text-text-primary">Command Center</h1>
        <p className="text-sm text-text-muted mt-1">Real-time security operations overview</p>
      </div>

      {aiStatus && (
        <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl border border-purple/20 bg-purple/5">
          <div className="flex items-center gap-3">
            <Sparkles className="w-5 h-5 text-purple" />
            <div>
              <p className="text-sm font-medium text-text-primary">AI Engine Active</p>
              <p className="text-xs text-text-muted flex items-center gap-1">
                <Cpu className="w-3 h-3" />
                Provider: {aiStatus.llm_provider}
                {aiStatus.is_local ? ' (offline — no API key)' : ''}
              </p>
            </div>
          </div>
          <AIButton label="SOC Briefing" onClick={askCopilot} loading={aiLoading} variant="purple" />
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="Total Logs" value={m.total_logs ?? 0} color="cyan" icon={List} />
        <MetricCard label="Open Alerts" value={m.open_alerts ?? 0} color="red" icon={Zap} />
        <MetricCard label="Critical" value={m.critical_alerts ?? 0} color="amber" icon={AlertTriangle} />
        <MetricCard label="Active Rules" value={m.active_rules ?? 0} color="green" icon={Crosshair} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl border border-border-default bg-bg-secondary p-5">
          <h2 className="text-sm font-semibold text-text-secondary mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-accent" /> Live Log Stream
          </h2>
          <LogStream logs={logs.length ? logs : undefined} />
        </div>
        <div className="rounded-xl border border-border-default bg-bg-secondary p-5">
          <h2 className="text-sm font-semibold text-text-secondary mb-4">Recent Alerts</h2>
          <AlertFeed alerts={alerts.length ? alerts : undefined} />
        </div>
      </div>

      <MitreHeatmap data={data?.alerts_by_severity} />

      <AIModal
        open={modal.open}
        title={modal.title}
        provider={modal.provider}
        onClose={() => setModal({ open: false, title: '', body: '', provider: '' })}
      >
        {modal.body}
      </AIModal>
    </div>
  );
}
