import { useEffect, useState } from 'react';
import { api } from '../api/client';
import LogStream from '../components/LogStream';
import { useWebSocket } from '../context/WebSocketContext';
import AIModal from '../components/AIModal';
import AIButton from '../components/AIButton';

export default function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [rawLogs, setRawLogs] = useState([]);
  const [query, setQuery] = useState('');
  const [nlpQuery, setNlpQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [modal, setModal] = useState({ open: false, title: '', body: '', provider: '' });
  const { subscribe } = useWebSocket();

  const mapLogs = (items) =>
    items.map((l) => ({
      id: l.id,
      timestamp: new Date(l.timestamp).toLocaleTimeString(),
      severity: (l.severity || 'info').toUpperCase(),
      source: (l.source || 'syslog').toUpperCase(),
      message: l.raw_message,
      ip: l.source_ip,
    }));

  const load = async () => {
    try {
      const res = query
        ? await fetch(`/api/logs/search?q=${encodeURIComponent(query)}`, {
            headers: { Authorization: `Bearer ${localStorage.getItem('sentinelx_token') || ''}` },
          }).then((r) => r.json())
        : await api.getLogs({ page_size: 100 });
      const items = res?.items || [];
      setRawLogs(items);
      setLogs(mapLogs(items));
    } catch (e) {
      console.error(e);
    }
  };

  const runNlpSearch = async () => {
    if (!nlpQuery.trim()) return;
    setLoading(true);
    try {
      const res = await api.aiNlpSearch(nlpQuery.trim());
      const items = res.results || [];
      setRawLogs(items);
      setLogs(mapLogs(items));
      setModal({
        open: true,
        title: 'NLP Search Results',
        body: `${res.interpreted_query}\n\nFound ${res.total} ${res.search_type} records.`,
        provider: 'nlp_query',
      });
    } catch (e) {
      setModal({ open: true, title: 'Error', body: e.message, provider: '' });
    } finally {
      setLoading(false);
    }
  };

  const scoreLatest = async () => {
    const latest = rawLogs[0];
    if (!latest) {
      setModal({ open: true, title: 'Score Event', body: 'No logs to score.', provider: '' });
      return;
    }
    setLoading(true);
    try {
      const res = await api.aiScoreEvent({ log_id: latest.id });
      setModal({
        open: true,
        title: `Anomaly Score — Log #${latest.id}`,
        body: `Score: ${res.anomaly_score} (${res.risk_percent}%)\nLevel: ${res.level}\nAnomalous: ${res.is_anomalous}\n\n${JSON.stringify(res.baseline, null, 2)}`,
        provider: 'anomaly_scorer',
      });
    } catch (e) {
      setModal({ open: true, title: 'Error', body: e.message, provider: '' });
    } finally {
      setLoading(false);
    }
  };

  const scoreAllVisible = async () => {
    if (!rawLogs.length) return;
    setLoading(true);
    try {
      const scores = await Promise.all(
        rawLogs.slice(0, 5).map((l) => api.aiScoreEvent({ log_id: l.id }))
      );
      const lines = scores.map(
        (s, i) => `Log #${rawLogs[i].id}: ${s.anomaly_score} (${s.level})`
      );
      setModal({
        open: true,
        title: 'Batch Anomaly Scores',
        body: lines.join('\n'),
        provider: 'anomaly_scorer',
      });
    } catch (e) {
      setModal({ open: true, title: 'Error', body: e.message, provider: '' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    return subscribe('events', (msg) => {
      if (msg.type === 'log') load();
    });
  }, [subscribe]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="font-orbitron text-2xl font-bold">Live Logs</h1>
        <div className="flex flex-wrap gap-2">
          <AIButton label="Score Latest" onClick={scoreLatest} loading={loading} variant="warning" />
          <AIButton label="Score Top 5" onClick={scoreAllVisible} loading={loading} variant="warning" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="flex gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Keyword search..."
            className="flex-1 px-4 py-2 rounded-lg bg-bg-secondary border border-border-default text-sm"
          />
          <button
            onClick={load}
            className="px-4 py-2 rounded-lg bg-accent text-bg-primary text-sm font-medium"
          >
            Search
          </button>
        </div>
        <div className="flex gap-2">
          <input
            value={nlpQuery}
            onChange={(e) => setNlpQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runNlpSearch()}
            placeholder="NLP: failed logins in the last hour..."
            className="flex-1 px-4 py-2 rounded-lg bg-bg-secondary border border-border-default text-sm"
          />
          <AIButton label="AI NLP Search" onClick={runNlpSearch} loading={loading} variant="purple" />
        </div>
      </div>

      <div className="rounded-xl border border-border-default bg-bg-secondary p-5">
        <LogStream logs={logs} maxItems={100} />
      </div>

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
