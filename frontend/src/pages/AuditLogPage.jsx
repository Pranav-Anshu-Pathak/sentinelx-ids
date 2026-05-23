import { useEffect, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ClipboardList, Search, RefreshCw, Filter, User, Shield,
  AlertTriangle, CheckCircle, XCircle, Clock, ChevronDown,
  ChevronUp, Activity, Lock, Unlock, Trash2, Eye, LogIn,
  LogOut, Settings, Zap, Database, Globe,
} from 'lucide-react';
import { api } from '../api/client';

// ─── Constants ────────────────────────────────────────────────────────────────

const ACTION_META = {
  login:                { icon: LogIn,    color: '#00e676', label: 'Login' },
  logout:               { icon: LogOut,   color: '#8aa4c8', label: 'Logout' },
  login_failed:         { icon: XCircle,  color: '#ff3b5c', label: 'Login Failed' },
  alert_view:           { icon: Eye,      color: '#00d4ff', label: 'Alert Viewed' },
  alert_update:         { icon: AlertTriangle, color: '#ffab00', label: 'Alert Updated' },
  alert_create:         { icon: AlertTriangle, color: '#ff6b35', label: 'Alert Created' },
  alert_delete:         { icon: Trash2,   color: '#ff3b5c', label: 'Alert Deleted' },
  rule_create:          { icon: Shield,   color: '#00e676', label: 'Rule Created' },
  rule_update:          { icon: Shield,   color: '#ffab00', label: 'Rule Updated' },
  rule_delete:          { icon: Shield,   color: '#ff3b5c', label: 'Rule Deleted' },
  rule_toggle:          { icon: Shield,   color: '#b388ff', label: 'Rule Toggled' },
  ioc_create:           { icon: Database, color: '#00e676', label: 'IOC Added' },
  ioc_update:           { icon: Database, color: '#ffab00', label: 'IOC Updated' },
  ioc_delete:           { icon: Database, color: '#ff3b5c', label: 'IOC Deleted' },
  ioc_lookup:           { icon: Globe,    color: '#00d4ff', label: 'IOC Lookup' },
  ip_block:             { icon: Lock,     color: '#ff3b5c', label: 'IP Blocked' },
  ip_unblock:           { icon: Unlock,   color: '#00e676', label: 'IP Unblocked' },
  feed_sync:            { icon: RefreshCw,color: '#b388ff', label: 'Feed Sync' },
  investigation_create: { icon: Search,   color: '#00e676', label: 'Investigation Created' },
  investigation_update: { icon: Search,   color: '#ffab00', label: 'Investigation Updated' },
  notification_test:    { icon: Zap,      color: '#ffab00', label: 'Notification Test' },
  settings_view:        { icon: Settings, color: '#8aa4c8', label: 'Settings Viewed' },
  export:               { icon: Activity, color: '#00d4ff', label: 'Data Exported' },
  system:               { icon: Activity, color: '#4a6a9a', label: 'System Action' },
};

const ROLE_COLORS = {
  admin:   '#ff6b35',
  analyst: '#00d4ff',
  viewer:  '#8aa4c8',
  system:  '#4a6a9a',
};

function timeAgo(ts) {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(ts).toLocaleDateString();
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleString('en-IN', { dateStyle: 'short', timeStyle: 'medium' });
}

// ─── Stats Cards ─────────────────────────────────────────────────────────────

function StatsRow({ stats }) {
  if (!stats) return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {[0,1,2,3].map(i => <div key={i} className="h-20 rounded-xl bg-bg-secondary border border-border-default animate-pulse" />)}
    </div>
  );

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {[
        { label: 'Total (all time)', value: stats.total_all_time, color: '#00d4ff', icon: ClipboardList },
        { label: `Events (${stats.window_days}d)`,  value: stats.total_in_window, color: '#b388ff', icon: Activity },
        { label: 'Failures',         value: stats.failures,       color: '#ff3b5c', icon: XCircle },
        { label: 'Active Users',     value: stats.by_user?.length ?? 0, color: '#00e676', icon: User },
      ].map(({ label, value, color, icon: Icon }) => (
        <motion.div
          key={label}
          whileHover={{ scale: 1.02 }}
          className="rounded-xl p-4 border flex items-center gap-3"
          style={{ background: `${color}08`, borderColor: `${color}20` }}
        >
          <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: `${color}15` }}>
            <Icon className="w-4 h-4" style={{ color }} />
          </div>
          <div>
            <div className="text-xl font-bold font-mono" style={{ color }}>{value?.toLocaleString()}</div>
            <div className="text-[10px] text-text-muted uppercase tracking-wider">{label}</div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

// ─── Top Users Bar ────────────────────────────────────────────────────────────

function TopUsers({ users = [] }) {
  if (!users.length) return null;
  const max = users[0]?.count || 1;

  return (
    <div className="rounded-xl border border-border-default p-4 bg-bg-secondary">
      <div className="text-xs font-semibold text-text-muted uppercase tracking-widest mb-4">Top Active Users</div>
      <div className="space-y-3">
        {users.slice(0, 5).map(({ username, count }) => {
          const pct = Math.round((count / max) * 100);
          return (
            <div key={username}>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-text-primary font-medium">{username || 'system'}</span>
                <span className="font-mono text-text-muted">{count}</span>
              </div>
              <div className="h-1.5 rounded-full bg-bg-quaternary overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${pct}%` }}
                  transition={{ duration: 0.8, ease: 'easeOut' }}
                  className="h-full rounded-full"
                  style={{ background: 'linear-gradient(90deg, #00d4ff, #b388ff)' }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Action Breakdown ─────────────────────────────────────────────────────────

function ActionBreakdown({ byAction = {} }) {
  const sorted = Object.entries(byAction).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!sorted.length) return null;

  return (
    <div className="rounded-xl border border-border-default p-4 bg-bg-secondary">
      <div className="text-xs font-semibold text-text-muted uppercase tracking-widest mb-4">Action Breakdown</div>
      <div className="space-y-2">
        {sorted.map(([action, count]) => {
          const meta = ACTION_META[action] || { color: '#4a6a9a', label: action };
          return (
            <div key={action} className="flex items-center gap-3 text-xs">
              <div className="w-2 h-2 rounded-full shrink-0" style={{ background: meta.color }} />
              <span className="text-text-secondary flex-1 truncate">{meta.label || action}</span>
              <span className="font-mono font-bold" style={{ color: meta.color }}>{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Audit Table Row ─────────────────────────────────────────────────────────

function AuditRow({ entry, isExpanded, onToggle }) {
  const meta = ACTION_META[entry.action] || { icon: Activity, color: '#4a6a9a', label: entry.action };
  const Icon = meta.icon;
  const isFailure = entry.status === 'failure';

  return (
    <>
      <tr
        className="border-t border-border-default hover:bg-bg-tertiary/40 transition-colors cursor-pointer"
        onClick={onToggle}
      >
        {/* Time */}
        <td className="px-4 py-3 text-xs text-text-muted whitespace-nowrap">
          <div>{timeAgo(entry.timestamp)}</div>
          <div className="text-[10px] opacity-60">{fmtTime(entry.timestamp)}</div>
        </td>

        {/* User */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold"
              style={{ background: `${ROLE_COLORS[entry.user_role] || '#4a6a9a'}20`, color: ROLE_COLORS[entry.user_role] || '#4a6a9a' }}>
              {(entry.username || 'S')[0].toUpperCase()}
            </div>
            <div>
              <div className="text-xs font-medium text-text-primary">{entry.username || 'system'}</div>
              <div className="text-[10px] text-text-muted capitalize">{entry.user_role}</div>
            </div>
          </div>
        </td>

        {/* Action */}
        <td className="px-4 py-3">
          <span
            className="inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-full font-medium"
            style={{ background: `${meta.color}15`, color: meta.color, border: `1px solid ${meta.color}30` }}
          >
            <Icon className="w-3 h-3" />
            {meta.label}
          </span>
        </td>

        {/* Resource */}
        <td className="px-4 py-3 text-xs text-text-muted">
          {entry.resource_type && (
            <span className="font-mono">
              {entry.resource_type}
              {entry.resource_id ? <span className="text-text-primary">/{entry.resource_id}</span> : ''}
            </span>
          )}
        </td>

        {/* Description */}
        <td className="px-4 py-3 text-xs text-text-secondary max-w-xs truncate">
          {entry.description || '—'}
        </td>

        {/* Status */}
        <td className="px-4 py-3">
          {isFailure ? (
            <span className="flex items-center gap-1 text-danger text-xs">
              <XCircle className="w-3 h-3" /> Failure
            </span>
          ) : (
            <span className="flex items-center gap-1 text-success text-xs">
              <CheckCircle className="w-3 h-3" /> OK
            </span>
          )}
        </td>

        {/* Expand */}
        <td className="px-3 py-3 text-text-muted">
          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </td>
      </tr>

      {/* Expanded detail */}
      {isExpanded && (
        <tr className="bg-bg-secondary border-t border-border-default">
          <td colSpan={7} className="px-6 py-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div>
                <div className="text-text-muted mb-1">IP Address</div>
                <div className="font-mono text-text-primary">{entry.ip_address || '—'}</div>
              </div>
              <div>
                <div className="text-text-muted mb-1">Timestamp</div>
                <div className="font-mono text-text-primary">{fmtTime(entry.timestamp)}</div>
              </div>
              <div>
                <div className="text-text-muted mb-1">Audit ID</div>
                <div className="font-mono text-text-primary">#{entry.id}</div>
              </div>
              <div>
                <div className="text-text-muted mb-1">User Agent</div>
                <div className="text-text-primary truncate">{entry.user_agent ? entry.user_agent.substring(0, 60) + '…' : '—'}</div>
              </div>
              {entry.extra && Object.keys(entry.extra).length > 0 && (
                <div className="col-span-2 md:col-span-4">
                  <div className="text-text-muted mb-1">Extra Data</div>
                  <pre className="bg-bg-quaternary rounded-lg p-3 text-xs text-text-secondary overflow-auto max-h-32">
                    {JSON.stringify(entry.extra, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AuditLogPage() {
  const [logs, setLogs]         = useState([]);
  const [stats, setStats]       = useState(null);
  const [total, setTotal]       = useState(0);
  const [page, setPage]         = useState(1);
  const [loading, setLoading]   = useState(false);
  const [expandedId, setExpId]  = useState(null);

  // Filters
  const [search,    setSearch]    = useState('');
  const [username,  setUsername]  = useState('');
  const [action,    setAction]    = useState('');
  const [resType,   setResType]   = useState('');
  const [statusF,   setStatusF]   = useState('');
  const [days,      setDays]      = useState(7);
  const [showFilters, setShowFilters] = useState(false);

  const PAGE_SIZE = 50;

  const loadLogs = useCallback(async (p = 1) => {
    setLoading(true);
    try {
      const params = { page: p, page_size: PAGE_SIZE };
      if (search)   params.search        = search;
      if (username) params.username      = username;
      if (action)   params.action        = action;
      if (resType)  params.resource_type = resType;
      if (statusF)  params.status        = statusF;
      const data = await api.getAuditLogs(params);
      setLogs(data.items || []);
      setTotal(data.total || 0);
      setPage(p);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [search, username, action, resType, statusF]);

  const loadStats = useCallback(async () => {
    try { setStats(await api.getAuditStats(days)); }
    catch (e) { console.error(e); }
  }, [days]);

  useEffect(() => { loadLogs(1); }, []);
  useEffect(() => { loadStats(); }, [days]);

  const handleFilter = (e) => {
    e.preventDefault();
    loadLogs(1);
  };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="font-orbitron text-2xl font-bold text-text-primary flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple to-accent flex items-center justify-center">
              <ClipboardList className="w-4 h-4 text-bg-primary" />
            </div>
            Audit Log
          </h1>
          <p className="text-text-muted text-sm mt-1">Immutable trail of every user action in SentinelX</p>
        </div>
        <div className="flex gap-2">
          <select
            value={days}
            onChange={e => setDays(Number(e.target.value))}
            className="px-3 py-2 rounded-lg text-sm bg-bg-secondary border border-border-default text-text-primary"
          >
            {[1,7,14,30,90].map(d => <option key={d} value={d}>Last {d}d</option>)}
          </select>
          <button
            onClick={() => { loadLogs(1); loadStats(); }}
            className="p-2 rounded-lg border border-border-default text-text-muted hover:text-accent transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-accent' : ''}`} />
          </button>
        </div>
      </div>

      {/* Stats */}
      <StatsRow stats={stats} />

      {/* Mini charts */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <TopUsers users={stats.by_user} />
          <ActionBreakdown byAction={stats.by_action} />
        </div>
      )}

      {/* Filter bar */}
      <form onSubmit={handleFilter} className="space-y-3">
        <div className="flex gap-2 flex-wrap">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search descriptions…"
              className="w-full pl-9 pr-4 py-2 rounded-lg text-sm bg-bg-secondary border border-border-default text-text-primary focus:border-accent/50"
            />
          </div>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="Username…"
            className="px-3 py-2 rounded-lg text-sm w-36 bg-bg-secondary border border-border-default text-text-primary"
          />
          <button
            type="button"
            onClick={() => setShowFilters(x => !x)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm border transition-colors ${showFilters ? 'bg-accent/10 border-accent/30 text-accent' : 'border-border-default text-text-muted hover:text-text-primary'}`}
          >
            <Filter className="w-3.5 h-3.5" /> Filters
          </button>
          <button type="submit"
            className="px-4 py-2 rounded-lg text-sm bg-accent text-bg-primary font-medium hover:bg-accent-dark transition-colors">
            Search
          </button>
        </div>

        <AnimatePresence>
          {showFilters && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="flex flex-wrap gap-3"
            >
              <select value={action} onChange={e => setAction(e.target.value)}
                className="px-3 py-2 rounded-lg text-sm bg-bg-secondary border border-border-default text-text-primary">
                <option value="">All Actions</option>
                {Object.entries(ACTION_META).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
              <select value={resType} onChange={e => setResType(e.target.value)}
                className="px-3 py-2 rounded-lg text-sm bg-bg-secondary border border-border-default text-text-primary">
                <option value="">All Resources</option>
                {['alert','rule','ioc','auth','user','system'].map(r => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
              <select value={statusF} onChange={e => setStatusF(e.target.value)}
                className="px-3 py-2 rounded-lg text-sm bg-bg-secondary border border-border-default text-text-primary">
                <option value="">All Status</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
              </select>
              <button type="button"
                onClick={() => { setAction(''); setResType(''); setStatusF(''); setUsername(''); setSearch(''); }}
                className="px-3 py-2 text-xs text-text-muted hover:text-danger transition-colors">
                Clear filters
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </form>

      {/* Table */}
      <div className="rounded-xl border border-border-default overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-bg-tertiary text-text-muted text-left">
              <th className="px-4 py-3 text-xs uppercase tracking-wider">Time</th>
              <th className="px-4 py-3 text-xs uppercase tracking-wider">User</th>
              <th className="px-4 py-3 text-xs uppercase tracking-wider">Action</th>
              <th className="px-4 py-3 text-xs uppercase tracking-wider">Resource</th>
              <th className="px-4 py-3 text-xs uppercase tracking-wider">Description</th>
              <th className="px-4 py-3 text-xs uppercase tracking-wider">Status</th>
              <th className="px-3 py-3 w-8"></th>
            </tr>
          </thead>
          <tbody>
            {loading && logs.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center">
                  <RefreshCw className="w-6 h-6 mx-auto text-accent animate-spin mb-2" />
                  <div className="text-text-muted text-sm">Loading audit log…</div>
                </td>
              </tr>
            )}
            {!loading && logs.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center">
                  <ClipboardList className="w-8 h-8 mx-auto mb-3 opacity-20" />
                  <div className="text-text-muted">No audit events found</div>
                  <div className="text-text-muted text-xs mt-1">Actions will appear here as users interact with the system</div>
                </td>
              </tr>
            )}
            {logs.map(entry => (
              <AuditRow
                key={entry.id}
                entry={entry}
                isExpanded={expandedId === entry.id}
                onToggle={() => setExpId(expandedId === entry.id ? null : entry.id)}
              />
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <div className="text-text-muted">
            Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, total)} of {total.toLocaleString()} events
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => loadLogs(page - 1)}
              disabled={page <= 1 || loading}
              className="px-3 py-1.5 rounded-lg border border-border-default text-text-secondary hover:text-text-primary disabled:opacity-40 transition-colors"
            >
              ← Prev
            </button>
            <span className="px-3 py-1.5 text-text-muted">
              {page} / {totalPages}
            </span>
            <button
              onClick={() => loadLogs(page + 1)}
              disabled={page >= totalPages || loading}
              className="px-3 py-1.5 rounded-lg border border-border-default text-text-secondary hover:text-text-primary disabled:opacity-40 transition-colors"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
