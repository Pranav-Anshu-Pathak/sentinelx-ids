import { useEffect, useState } from 'react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';

export default function RulesPage() {
  const [rules, setRules] = useState([]);

  const load = async () => {
    try {
      setRules((await api.getRules()) || []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const toggle = async (id, enabled) => {
    await api.toggleRule(id, !enabled);
    load();
  };

  return (
    <div className="space-y-6">
      <h1 className="font-orbitron text-2xl font-bold">Detection Rules</h1>
      <div className="grid gap-4">
        {rules.map((r) => (
          <div
            key={r.id}
            className="flex items-center justify-between p-4 rounded-xl border border-border-default bg-bg-secondary"
          >
            <div>
              <h3 className="font-medium text-text-primary">{r.name}</h3>
              <p className="text-xs text-text-muted mt-1">{r.category} · {r.mitre_technique}</p>
              <p className="text-xs text-text-secondary mt-2 line-clamp-2">{r.description}</p>
            </div>
            <div className="flex items-center gap-4 shrink-0">
              <SeverityBadge severity={r.severity} />
              <span className="text-xs text-text-muted">{r.hits} hits</span>
              <button
                onClick={() => toggle(r.id, r.enabled)}
                className={`px-3 py-1 rounded text-xs font-medium ${
                  r.enabled ? 'bg-success/20 text-success' : 'bg-bg-tertiary text-text-muted'
                }`}
              >
                {r.enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>
          </div>
        ))}
        {!rules.length && (
          <p className="text-text-muted">No rules loaded. Restart backend to seed from YAML.</p>
        )}
      </div>
    </div>
  );
}
