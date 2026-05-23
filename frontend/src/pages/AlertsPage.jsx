import { useEffect, useState } from 'react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import AIModal from '../components/AIModal';
import AIButton from '../components/AIButton';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);
  const [modal, setModal] = useState({ open: false, title: '', body: '', provider: '' });

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.getAlerts({ page_size: 50 });
      setAlerts(res?.items || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const updateStatus = async (id, status) => {
    await api.updateAlert(id, { status });
    load();
  };

  const showModal = (title, body, provider = 'AI') => {
    setModal({ open: true, title, body, provider });
  };

  const runAi = async (key, alertId, fn) => {
    setActionLoading(`${key}-${alertId}`);
    try {
      const res = await fn(alertId);
      if (key === 'analyze') {
        showModal(
          `Analysis: Alert #${alertId}`,
          `${res.analysis}\n\n--- Local copilot ---\n\n${res.local_analysis}`,
          `${res.provider} · ${res.model}`
        );
      } else if (key === 'remediate') {
        showModal(
          `Remediation: Alert #${alertId}`,
          res.steps.map((s, i) => `${i + 1}. ${s}`).join('\n'),
          'local copilot'
        );
      } else if (key === 'score') {
        showModal(
          `Anomaly Score: Alert #${alertId}`,
          `Score: ${res.anomaly_score} (${res.risk_percent}%)\nLevel: ${res.level}\nAnomalous: ${res.is_anomalous ? 'YES' : 'no'}\nRule risk: ${res.rule_risk_score}\n\nBaseline:\n${JSON.stringify(res.baseline, null, 2)}`,
          'anomaly_scorer'
        );
      } else if (key === 'chat') {
        showModal(`Copilot: Alert #${alertId}`, res.reply, res.provider);
      }
    } catch (e) {
      showModal('Error', e.message, '');
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="font-orbitron text-2xl font-bold">Alerts</h1>
        <p className="text-xs text-text-muted">AI actions per row: Analyze · Remediate · Score · Ask</p>
      </div>

      {loading ? (
        <p className="text-text-muted">Loading...</p>
      ) : (
        <div className="rounded-xl border border-border-default overflow-x-auto">
          <table className="w-full text-sm min-w-[900px]">
            <thead className="bg-bg-tertiary text-text-muted text-left">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Source IP</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">AI Actions</th>
                <th className="px-4 py-3">Update</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id} className="border-t border-border-default hover:bg-bg-tertiary/50">
                  <td className="px-4 py-3"><SeverityBadge severity={a.severity} /></td>
                  <td className="px-4 py-3 text-text-primary max-w-[200px] truncate">{a.title}</td>
                  <td className="px-4 py-3 font-mono text-text-secondary">{a.source_ip || '—'}</td>
                  <td className="px-4 py-3">{a.risk_score?.toFixed?.(0) ?? a.risk_score}</td>
                  <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      <AIButton
                        label="Analyze"
                        variant="purple"
                        loading={actionLoading === `analyze-${a.id}`}
                        onClick={() => runAi('analyze', a.id, api.aiAnalyzeAlert)}
                      />
                      <AIButton
                        label="Fix"
                        loading={actionLoading === `remediate-${a.id}`}
                        onClick={() => runAi('remediate', a.id, api.aiRemediate)}
                      />
                      <AIButton
                        label="Score"
                        variant="warning"
                        loading={actionLoading === `score-${a.id}`}
                        onClick={() => runAi('score', a.id, api.aiScoreAlert)}
                      />
                      <AIButton
                        label="Ask"
                        loading={actionLoading === `chat-${a.id}`}
                        onClick={() =>
                          runAi('chat', a.id, (id) =>
                            api.aiChat(`Summarize alert ${id} and next steps`, id)
                          )
                        }
                      />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <select
                      value={a.status}
                      onChange={(e) => updateStatus(a.id, e.target.value)}
                      className="bg-bg-primary border border-border-default rounded px-2 py-1 text-xs"
                    >
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!alerts.length && (
            <p className="p-8 text-center text-text-muted">
              No alerts yet. Demo collector will generate some shortly.
            </p>
          )}
        </div>
      )}

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
