import { useEffect, useState } from 'react';
import { Send, Sparkles, Search, BookOpen, Cpu } from 'lucide-react';
import { api } from '../api/client';
import AIModal from '../components/AIModal';
import AIButton from '../components/AIButton';

const TABS = [
  { id: 'chat', label: 'Copilot Chat', icon: Sparkles },
  { id: 'nlp', label: 'NLP Search', icon: Search },
  { id: 'explain', label: 'Explain Attack', icon: BookOpen },
];

export default function InvestigationsPage() {
  const [tab, setTab] = useState('chat');
  const [aiStatus, setAiStatus] = useState(null);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: 'SentinelX AI ready. Use Chat (LLM or local), NLP Search, or Explain Attack.',
    },
  ]);
  const [nlpQuery, setNlpQuery] = useState('');
  const [nlpResult, setNlpResult] = useState(null);
  const [attackType, setAttackType] = useState('brute_force');
  const [loading, setLoading] = useState(false);
  const [modal, setModal] = useState({ open: false, title: '', body: '', provider: '' });

  useEffect(() => {
    api.getAiStatus().then(setAiStatus).catch(console.error);
  }, []);

  const sendChat = async () => {
    if (!message.trim()) return;
    const userMsg = message.trim();
    setMessages((m) => [...m, { role: 'user', text: userMsg }]);
    setMessage('');
    setLoading(true);
    try {
      const res = await api.aiChat(userMsg);
      setMessages((m) => [
        ...m,
        {
          role: 'assistant',
          text: res.reply,
          provider: `${res.provider} · ${res.model}${res.fallback_used ? ' (local fallback)' : ''}`,
        },
      ]);
    } catch (e) {
      setMessages((m) => [...m, { role: 'assistant', text: `Error: ${e.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  const runNlpSearch = async () => {
    if (!nlpQuery.trim()) return;
    setLoading(true);
    setNlpResult(null);
    try {
      const res = await api.aiNlpSearch(nlpQuery.trim());
      setNlpResult(res);
    } catch (e) {
      setNlpResult({ error: e.message });
    } finally {
      setLoading(false);
    }
  };

  const runExplain = async () => {
    setLoading(true);
    try {
      const res = await api.aiExplainAttack(attackType);
      setModal({
        open: true,
        title: `Attack: ${attackType.replace(/_/g, ' ')}`,
        body: res.explanation,
        provider: 'local copilot',
      });
    } catch (e) {
      setModal({ open: true, title: 'Error', body: e.message, provider: '' });
    } finally {
      setLoading(false);
    }
  };

  const applySuggestion = (q) => {
    setNlpQuery(q);
    setTab('nlp');
  };

  return (
    <div className="space-y-6 h-[calc(100vh-8rem)] flex flex-col">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Sparkles className="w-6 h-6 text-purple" />
          <h1 className="font-orbitron text-2xl font-bold">AI Copilot</h1>
        </div>
        {aiStatus && (
          <div className="flex items-center gap-2 text-xs text-text-muted px-3 py-2 rounded-lg bg-bg-secondary border border-border-default">
            <Cpu className="w-4 h-4 text-accent" />
            <span>
              LLM: <strong className="text-accent">{aiStatus.llm_provider}</strong>
              {aiStatus.is_local && ' (offline mode)'}
            </span>
            <span className="text-border-default">|</span>
            <span>Modules: copilot, scorer, nlp, llm</span>
          </div>
        )}
      </div>

      <div className="flex gap-2 border-b border-border-default pb-2">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
              tab === t.id
                ? 'bg-purple/15 text-purple border border-purple/30'
                : 'text-text-muted hover:text-text-primary'
            }`}
          >
            <t.icon className="w-4 h-4" />
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'chat' && (
        <>
          <div className="flex-1 overflow-y-auto space-y-4 rounded-xl border border-border-default bg-bg-secondary p-5 min-h-[300px]">
            {messages.map((msg, i) => (
              <div
                key={i}
                className={`max-w-[90%] p-4 rounded-lg text-sm whitespace-pre-wrap ${
                  msg.role === 'user'
                    ? 'ml-auto bg-accent/10 text-text-primary border border-accent/20'
                    : 'bg-bg-tertiary text-text-secondary'
                }`}
              >
                {msg.text}
                {msg.provider && (
                  <p className="text-[10px] text-text-muted mt-2">{msg.provider}</p>
                )}
              </div>
            ))}
            {loading && <p className="text-text-muted text-sm">Analyzing...</p>}
          </div>
          <div className="flex gap-2">
            <input
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendChat()}
              placeholder="Ask about alerts, MITRE, remediation..."
              className="flex-1 px-4 py-3 rounded-lg bg-bg-secondary border border-border-default"
            />
            <button
              onClick={sendChat}
              disabled={loading}
              className="px-5 py-3 rounded-lg bg-accent text-bg-primary flex items-center gap-2 disabled:opacity-50"
            >
              <Send className="w-4 h-4" />
              Send
            </button>
          </div>
        </>
      )}

      {tab === 'nlp' && (
        <div className="flex-1 flex flex-col gap-4 min-h-[300px]">
          <div className="flex gap-2">
            <input
              value={nlpQuery}
              onChange={(e) => setNlpQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runNlpSearch()}
              placeholder="e.g. critical alerts in the last 24 hours"
              className="flex-1 px-4 py-3 rounded-lg bg-bg-secondary border border-border-default"
            />
            <AIButton label="NLP Search" onClick={runNlpSearch} loading={loading} variant="purple" />
          </div>
          <div className="flex flex-wrap gap-2">
            {(aiStatus?.attack_types || []).slice(0, 4).map((t) => (
              <button
                key={t}
                onClick={() => applySuggestion(`show ${t.replace(/_/g, ' ')} alerts`)}
                className="text-[10px] px-2 py-1 rounded bg-bg-tertiary text-text-muted hover:text-accent"
              >
                {t.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
          {nlpResult && (
            <div className="flex-1 overflow-y-auto rounded-xl border border-border-default bg-bg-secondary p-4">
              <p className="text-xs text-accent mb-2">{nlpResult.interpreted_query}</p>
              <p className="text-xs text-text-muted mb-3">
                Found {nlpResult.total} results ({nlpResult.search_type})
              </p>
              <pre className="text-xs overflow-auto max-h-96">
                {JSON.stringify(nlpResult.results?.slice(0, 10) || nlpResult.error, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {tab === 'explain' && (
        <div className="rounded-xl border border-border-default bg-bg-secondary p-6 space-y-4 max-w-lg">
          <p className="text-sm text-text-muted">
            Offline MITRE-backed explanations (no API key required).
          </p>
          <select
            value={attackType}
            onChange={(e) => setAttackType(e.target.value)}
            className="w-full px-4 py-3 rounded-lg bg-bg-primary border border-border-default"
          >
            {(aiStatus?.attack_types || ['brute_force', 'port_scan', 'reverse_shell']).map((t) => (
              <option key={t} value={t}>
                {t.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
          <AIButton label="Explain Attack" onClick={runExplain} loading={loading} variant="purple" />
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
