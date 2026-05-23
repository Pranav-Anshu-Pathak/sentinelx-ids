import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Settings, Bell, Slack, Mail, MessageSquare, CheckCircle,
  XCircle, AlertTriangle, Send, Clock, RefreshCw, Eye, EyeOff,
  ChevronRight, Zap, Shield, Activity, Info,
} from 'lucide-react';
import { api } from '../api/client';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function timeAgo(ts) {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const h = Math.floor(mins / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const STATUS_COLORS = {
  sent:    { bg: 'rgba(0,230,118,0.08)', border: 'rgba(0,230,118,0.2)', text: '#00e676', icon: CheckCircle },
  skipped: { bg: 'rgba(255,171,0,0.08)', border: 'rgba(255,171,0,0.2)',  text: '#ffab00', icon: AlertTriangle },
  error:   { bg: 'rgba(255,59,92,0.08)', border: 'rgba(255,59,92,0.2)',  text: '#ff3b5c', icon: XCircle },
};

const CHANNEL_ICONS = {
  slack:   { icon: '💬', label: 'Slack',   color: '#4A154B' },
  discord: { icon: '🎮', label: 'Discord', color: '#5865F2' },
  email:   { icon: '📧', label: 'Email',   color: '#00d4ff' },
  all:     { icon: '📡', label: 'All',     color: '#8aa4c8' },
};

// ─── Channel Card ─────────────────────────────────────────────────────────────

function ChannelCard({ channel, configured, detail, onTest, testing }) {
  const ch = CHANNEL_ICONS[channel] || CHANNEL_ICONS.all;
  const isConfigured = configured;

  return (
    <motion.div
      whileHover={{ y: -2 }}
      className="rounded-xl border p-5 flex flex-col gap-4"
      style={{
        borderColor: isConfigured ? 'rgba(0,230,118,0.2)' : 'rgba(30,48,80,0.8)',
        background: isConfigured ? 'rgba(0,230,118,0.03)' : 'rgba(12,20,34,0.8)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center text-xl"
            style={{ background: isConfigured ? 'rgba(0,230,118,0.1)' : 'rgba(30,48,80,0.5)' }}
          >
            {ch.icon}
          </div>
          <div>
            <div className="font-semibold text-text-primary">{ch.label}</div>
            <div className="text-xs text-text-muted">{detail || 'Not configured'}</div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div
            className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-medium"
            style={
              isConfigured
                ? { background: 'rgba(0,230,118,0.1)', color: '#00e676', border: '1px solid rgba(0,230,118,0.2)' }
                : { background: 'rgba(74,106,154,0.1)', color: '#4a6a9a', border: '1px solid rgba(74,106,154,0.2)' }
            }
          >
            <div className="w-1.5 h-1.5 rounded-full" style={{ background: isConfigured ? '#00e676' : '#4a6a9a' }} />
            {isConfigured ? 'Active' : 'Inactive'}
          </div>
        </div>
      </div>

      {/* Config hint */}
      {!isConfigured && (
        <div className="text-xs text-text-muted bg-bg-tertiary rounded-lg px-3 py-2 font-mono">
          {channel === 'slack'   && 'Set SLACK_WEBHOOK_URL in .env'}
          {channel === 'discord' && 'Set DISCORD_WEBHOOK_URL in .env'}
          {channel === 'email'   && 'Set SMTP_HOST, SMTP_USER, ALERT_EMAIL_TO in .env'}
        </div>
      )}

      {/* Test button */}
      <button
        onClick={() => onTest(channel)}
        disabled={!isConfigured || testing === channel}
        className="flex items-center justify-center gap-2 w-full py-2 rounded-lg text-sm font-medium transition-all disabled:opacity-40 disabled:cursor-not-allowed"
        style={
          isConfigured
            ? { background: 'rgba(0,212,255,0.08)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.2)' }
            : { background: 'rgba(30,48,80,0.3)', color: '#4a6a9a', border: '1px solid rgba(30,48,80,0.5)' }
        }
      >
        {testing === channel ? (
          <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Sending test…</>
        ) : (
          <><Send className="w-3.5 h-3.5" /> Send Test</>
        )}
      </button>
    </motion.div>
  );
}

// ─── History Row ─────────────────────────────────────────────────────────────

function HistoryRow({ entry }) {
  const s = STATUS_COLORS[entry.status] || STATUS_COLORS.skipped;
  const Icon = s.icon;
  const ch = CHANNEL_ICONS[entry.channel] || CHANNEL_ICONS.all;

  return (
    <div
      className="flex items-center gap-3 px-4 py-3 border-t border-border-default hover:bg-bg-tertiary/40 transition-colors"
    >
      <Icon className="w-4 h-4 shrink-0" style={{ color: s.text }} />
      <span className="text-base shrink-0">{ch.icon}</span>
      <div className="flex-1 min-w-0">
        <div className="text-sm text-text-primary truncate">{entry.alert_title}</div>
        {entry.detail && (
          <div className="text-xs text-text-muted truncate">{entry.detail}</div>
        )}
      </div>
      <span
        className="text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0"
        style={{ background: s.bg, color: s.text, border: `1px solid ${s.border}` }}
      >
        {entry.status.toUpperCase()}
      </span>
      <span className="text-xs text-text-muted shrink-0">{timeAgo(entry.timestamp)}</span>
    </div>
  );
}

// ─── Notification Settings Section ───────────────────────────────────────────

function NotificationSection() {
  const [config, setConfig] = useState(null);
  const [history, setHistory] = useState([]);
  const [testing, setTesting] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    api.getNotificationConfig().then(setConfig).catch(console.error);
  }, []);

  const loadHistory = async () => {
    setLoadingHistory(true);
    try {
      const h = await api.getNotificationHistory();
      setHistory(h);
      setShowHistory(true);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleTest = async (channel) => {
    setTesting(channel);
    setTestResult(null);
    try {
      let result;
      if (channel === 'all') {
        result = await api.testNotifications();
      } else {
        result = await api.testNotificationChannel(channel);
      }
      setTestResult({ ok: true, ...result });
    } catch (e) {
      setTestResult({ ok: false, error: e.message });
    } finally {
      setTesting(null);
      // Refresh history after test
      setTimeout(() => {
        api.getNotificationHistory().then(setHistory).catch(console.error);
      }, 1000);
    }
  };

  const configuredCount = config
    ? [config.slack?.configured, config.discord?.configured, config.email?.configured].filter(Boolean).length
    : 0;

  return (
    <div className="space-y-6">
      {/* Header row */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-warning to-orange-500 flex items-center justify-center">
            <Bell className="w-4 h-4 text-white" />
          </div>
          <div>
            <h2 className="font-semibold text-text-primary">Alert Notifications</h2>
            <p className="text-xs text-text-muted">
              {configuredCount > 0
                ? `${configuredCount} channel${configuredCount > 1 ? 's' : ''} active`
                : 'No channels configured'}
            </p>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={loadHistory}
            disabled={loadingHistory}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs border border-border-default text-text-secondary hover:text-text-primary transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingHistory ? 'animate-spin text-accent' : ''}`} />
            History
          </button>
          <button
            onClick={() => handleTest('all')}
            disabled={configuredCount === 0 || testing === 'all'}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-accent text-bg-primary hover:bg-accent-dark transition-colors disabled:opacity-40"
          >
            {testing === 'all' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
            Test All
          </button>
        </div>
      </div>

      {/* Config info */}
      <div className="flex items-start gap-2 text-xs text-text-muted bg-bg-tertiary rounded-lg px-4 py-3 border border-border-default">
        <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-accent" />
        <div>
          Notifications fire for <strong className="text-text-secondary">Medium, High, and Critical</strong> alerts.
          Same source IP is rate-limited to <strong className="text-text-secondary">1 notification per 5 minutes</strong>.
          Configure channels by editing <code className="bg-bg-quaternary px-1 rounded">.env</code> and restarting the backend.
        </div>
      </div>

      {/* Test result banner */}
      <AnimatePresence>
        {testResult && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="flex items-start gap-3 px-4 py-3 rounded-xl border text-sm"
            style={
              testResult.ok
                ? { background: 'rgba(0,230,118,0.07)', borderColor: 'rgba(0,230,118,0.2)', color: '#00e676' }
                : { background: 'rgba(255,59,92,0.07)', borderColor: 'rgba(255,59,92,0.2)', color: '#ff3b5c' }
            }
          >
            {testResult.ok ? <CheckCircle className="w-4 h-4 shrink-0 mt-0.5" /> : <XCircle className="w-4 h-4 shrink-0 mt-0.5" />}
            <div>
              {testResult.ok
                ? `Test sent to: ${testResult.dispatched?.join(', ') || 'no channels'}`
                : `Test failed: ${testResult.error}`}
            </div>
            <button onClick={() => setTestResult(null)} className="ml-auto opacity-60 hover:opacity-100">✕</button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Channel cards */}
      {config ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <ChannelCard
            channel="slack"
            configured={config.slack?.configured}
            detail={config.slack?.configured ? 'Webhook configured' : null}
            onTest={handleTest}
            testing={testing}
          />
          <ChannelCard
            channel="discord"
            configured={config.discord?.configured}
            detail={config.discord?.configured ? 'Webhook configured' : null}
            onTest={handleTest}
            testing={testing}
          />
          <ChannelCard
            channel="email"
            configured={config.email?.configured}
            detail={
              config.email?.configured
                ? `${config.email.recipients_count} recipient${config.email.recipients_count !== 1 ? 's' : ''} via ${config.email.smtp_host}`
                : null
            }
            onTest={handleTest}
            testing={testing}
          />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[0, 1, 2].map((i) => (
            <div key={i} className="rounded-xl border border-border-default p-5 animate-pulse h-44 bg-bg-secondary" />
          ))}
        </div>
      )}

      {/* Severity info */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { sev: 'CRITICAL', color: '#ff3b5c', notified: true },
          { sev: 'HIGH',     color: '#ff6b35', notified: true },
          { sev: 'MEDIUM',   color: '#ffab00', notified: true },
          { sev: 'LOW',      color: '#00d4ff', notified: false },
        ].map(({ sev, color, notified }) => (
          <div
            key={sev}
            className="rounded-lg px-3 py-2.5 flex items-center gap-2 border text-xs font-medium"
            style={{
              borderColor: `${color}25`,
              background: `${color}08`,
              color: notified ? color : '#4a6a9a',
            }}
          >
            {notified
              ? <Bell className="w-3.5 h-3.5 shrink-0" />
              : <Bell className="w-3.5 h-3.5 shrink-0 opacity-40" />}
            <span>{sev}</span>
            <span className="ml-auto text-[10px]" style={{ color: notified ? color : '#4a6a9a' }}>
              {notified ? 'NOTIFIED' : 'MUTED'}
            </span>
          </div>
        ))}
      </div>

      {/* Notification history */}
      <AnimatePresence>
        {showHistory && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="rounded-xl border border-border-default overflow-hidden"
          >
            <div className="flex items-center justify-between px-4 py-3 bg-bg-tertiary">
              <div className="flex items-center gap-2 text-sm font-semibold text-text-primary">
                <Clock className="w-4 h-4 text-accent" />
                Notification History
                <span className="text-xs text-text-muted font-normal">({history.length} entries)</span>
              </div>
              <button
                onClick={() => setShowHistory(false)}
                className="text-text-muted hover:text-text-primary text-xs"
              >
                Close
              </button>
            </div>
            {history.length === 0 ? (
              <div className="px-4 py-8 text-center text-text-muted text-sm">
                No notifications recorded yet. Send a test to get started.
              </div>
            ) : (
              <div className="divide-y divide-border-default max-h-72 overflow-y-auto">
                {history.map((entry, i) => (
                  <HistoryRow key={i} entry={entry} />
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── System Info Section ──────────────────────────────────────────────────────

function SystemSection() {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent to-accent-dark flex items-center justify-center">
          <Shield className="w-4 h-4 text-bg-primary" />
        </div>
        <div>
          <h2 className="font-semibold text-text-primary">System</h2>
          <p className="text-xs text-text-muted">Version and runtime info</p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Version',    value: '1.0.0',     icon: '🏷️' },
          { label: 'Mode',       value: 'Demo',       icon: '🧪' },
          { label: 'Database',   value: 'SQLite',     icon: '🗄️' },
          { label: 'Auth',       value: 'JWT (HS256)', icon: '🔑' },
        ].map(({ label, value, icon }) => (
          <div key={label} className="rounded-xl border border-border-default p-4 bg-bg-secondary">
            <div className="text-base mb-1">{icon}</div>
            <div className="text-sm font-semibold text-text-primary">{value}</div>
            <div className="text-xs text-text-muted">{label}</div>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-border-default p-4 bg-bg-secondary">
        <div className="text-xs font-semibold text-text-muted uppercase tracking-widest mb-3">API Keys Status</div>
        <div className="space-y-2">
          {[
            { name: 'AbuseIPDB',    envKey: 'ABUSEIPDB_API_KEY',    description: 'IP reputation lookups' },
            { name: 'VirusTotal',   envKey: 'VIRUSTOTAL_API_KEY',   description: 'File/IP/domain analysis' },
            { name: 'OpenAI',       envKey: 'OPENAI_API_KEY',       description: 'GPT-4 AI analysis' },
            { name: 'Gemini',       envKey: 'GEMINI_API_KEY',       description: 'Gemini AI analysis' },
          ].map(({ name, envKey, description }) => (
            <div key={name} className="flex items-center justify-between text-sm py-1.5 border-b border-border-default last:border-0">
              <div>
                <span className="text-text-primary font-medium">{name}</span>
                <span className="text-text-muted text-xs ml-2">{description}</span>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono text-text-muted">
                <span>Set via</span>
                <code className="bg-bg-tertiary px-1.5 py-0.5 rounded text-accent">{envKey}</code>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'system',        label: 'System',        icon: Shield },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('notifications');

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="font-orbitron text-2xl font-bold text-text-primary flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple to-accent flex items-center justify-center">
            <Settings className="w-4 h-4 text-bg-primary" />
          </div>
          Settings
        </h1>
        <p className="text-text-muted text-sm mt-1">Configure notifications, integrations, and system options</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 p-1 rounded-xl bg-bg-secondary border border-border-default w-fit">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === id ? 'bg-accent/10 text-accent' : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <AnimatePresence mode="wait">
        {activeTab === 'notifications' && (
          <motion.div key="notif" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
            <NotificationSection />
          </motion.div>
        )}
        {activeTab === 'system' && (
          <motion.div key="sys" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
            <SystemSection />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
