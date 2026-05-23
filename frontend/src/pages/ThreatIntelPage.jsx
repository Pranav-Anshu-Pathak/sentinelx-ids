import { useEffect, useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe, Shield, Search, RefreshCw, Plus, Trash2, Lock, Unlock,
  AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp,
  Wifi, Database, Layers, Activity, Eye, X, Upload, Download,
  MapPin, Server, Hash, Link, Copy, ExternalLink, Clock, Zap,
} from 'lucide-react';
import { api } from '../api/client';

// ─── Helper utilities ─────────────────────────────────────────────────────────

function scoreColor(score) {
  if (score >= 85) return '#ff3b5c';
  if (score >= 65) return '#ff6b35';
  if (score >= 40) return '#ffab00';
  if (score >= 15) return '#00d4ff';
  return '#00e676';
}

function scoreLabel(score) {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 15) return 'LOW';
  return 'CLEAN';
}

function typeIcon(type) {
  if (type === 'ip') return <Wifi className="w-3.5 h-3.5" />;
  if (type === 'domain') return <Link className="w-3.5 h-3.5" />;
  if (type === 'hash') return <Hash className="w-3.5 h-3.5" />;
  return <Shield className="w-3.5 h-3.5" />;
}

function countryFlag(code) {
  if (!code) return '🌐';
  return code
    .toUpperCase()
    .replace(/./g, (c) => String.fromCodePoint(c.charCodeAt(0) + 127397));
}

function timeAgo(ts) {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

// ─── Score Gauge ─────────────────────────────────────────────────────────────

function ScoreGauge({ score }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const fill = circ * (1 - score / 100);
  const color = scoreColor(score);

  return (
    <div className="relative flex items-center justify-center" style={{ width: 96, height: 96 }}>
      <svg width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={r} fill="none" stroke="rgba(30,48,80,0.8)" strokeWidth="6" />
        <circle
          cx="48" cy="48" r={r}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeDasharray={circ}
          strokeDashoffset={fill}
          strokeLinecap="round"
          transform="rotate(-90 48 48)"
          style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: 'stroke-dashoffset 1s ease' }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-lg font-bold font-mono" style={{ color }}>{Math.round(score)}</span>
        <span className="text-[9px] font-semibold tracking-wider" style={{ color }}>{scoreLabel(score)}</span>
      </div>
    </div>
  );
}

// ─── Score Bar ───────────────────────────────────────────────────────────────

function ScoreBar({ score, label, color }) {
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-text-secondary">{label}</span>
        <span className="font-mono" style={{ color: scoreColor(score) }}>{Math.round(score)}</span>
      </div>
      <div className="h-1.5 rounded-full bg-bg-quaternary overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          className="h-full rounded-full"
          style={{ background: scoreColor(score), boxShadow: `0 0 8px ${scoreColor(score)}80` }}
        />
      </div>
    </div>
  );
}

// ─── Verdict Card ─────────────────────────────────────────────────────────────

function VerdictCard({ verdict, onBlock, onUnblock, isLoading }) {
  if (!verdict) return null;

  const isThreat = verdict.is_known_threat;
  const color = scoreColor(verdict.final_score);
  const geo = verdict.geo || {};
  const scores = verdict.scores || {};
  const ext = verdict.external || {};
  const abuse = ext.abuseipdb || {};
  const vt = ext.virustotal || {};

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="rounded-2xl border overflow-hidden"
      style={{
        borderColor: `${color}40`,
        background: 'rgba(12, 20, 34, 0.95)',
        boxShadow: `0 0 30px ${color}15, inset 0 1px 0 ${color}20`,
      }}
    >
      {/* Header */}
      <div className="flex items-center gap-4 p-4 border-b" style={{ borderColor: `${color}20` }}>
        <ScoreGauge score={verdict.final_score} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span
              className="text-xs font-bold px-2 py-0.5 rounded-full tracking-wider"
              style={{ background: `${color}20`, color, border: `1px solid ${color}40` }}
            >
              {verdict.severity?.toUpperCase()}
            </span>
            <span className="text-xs text-text-muted">{verdict.threat_type_label}</span>
            {verdict.indicator_type === 'ip' && geo.country_code && (
              <span className="text-base" title={geo.country}>{countryFlag(geo.country_code)}</span>
            )}
          </div>
          <div className="font-mono text-sm text-text-primary truncate">{verdict.indicator}</div>
          <div className="flex flex-wrap gap-3 mt-2 text-xs text-text-muted">
            {geo.city && <span><MapPin className="inline w-3 h-3 mr-1" />{geo.city}, {geo.country}</span>}
            {geo.isp && <span><Server className="inline w-3 h-3 mr-1" />{geo.isp}</span>}
            {geo.asn && <span className="font-mono">{geo.asn}</span>}
          </div>
        </div>

        {/* Action buttons */}
        {verdict.indicator_type === 'ip' && (
          <div className="flex gap-2 shrink-0">
            {verdict.threat_type === 'blocked' ? (
              <button
                onClick={() => onUnblock(verdict.indicator)}
                disabled={isLoading}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-success/10 text-success border border-success/20 hover:bg-success/20 transition-colors"
              >
                <Unlock className="w-3.5 h-3.5" /> Unblock
              </button>
            ) : (
              <button
                onClick={() => onBlock(verdict.indicator)}
                disabled={isLoading}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-danger/10 text-danger border border-danger/20 hover:bg-danger/20 transition-colors"
              >
                <Lock className="w-3.5 h-3.5" /> Block
              </button>
            )}
          </div>
        )}
      </div>

      {/* Score breakdown */}
      <div className="grid grid-cols-2 gap-6 p-4 border-b" style={{ borderColor: `${color}10` }}>
        <div className="space-y-3">
          <div className="text-xs font-semibold text-text-muted uppercase tracking-widest mb-2">Score Breakdown</div>
          {scores.local > 0 && <ScoreBar score={scores.local} label="Local DB" />}
          {abuse.available !== false && <ScoreBar score={scores.abuseipdb || 0} label="AbuseIPDB" />}
          {vt.available !== false && <ScoreBar score={scores.virustotal || 0} label="VirusTotal" />}
          {scores.geo_risk > 0 && <ScoreBar score={scores.geo_risk || 0} label="Geo Risk" />}
        </div>

        <div className="space-y-3">
          {/* AbuseIPDB details */}
          {abuse.available && (
            <div>
              <div className="text-xs font-semibold text-text-muted uppercase tracking-widest mb-2">AbuseIPDB</div>
              <div className="space-y-1 text-xs">
                <div className="flex justify-between">
                  <span className="text-text-muted">Reports</span>
                  <span className="text-warning font-mono">{abuse.total_reports || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-text-muted">Distinct Users</span>
                  <span className="font-mono text-text-secondary">{abuse.num_distinct_users || 0}</span>
                </div>
                {abuse.usage_type && (
                  <div className="flex justify-between">
                    <span className="text-text-muted">Usage</span>
                    <span className="text-text-secondary">{abuse.usage_type}</span>
                  </div>
                )}
                {abuse.is_tor && (
                  <div className="text-purple font-semibold">⚡ Tor Exit Node</div>
                )}
              </div>
            </div>
          )}

          {/* VirusTotal details */}
          {vt.available && (
            <div>
              <div className="text-xs font-semibold text-text-muted uppercase tracking-widest mb-2">VirusTotal</div>
              <div className="flex gap-4 text-xs">
                <div className="text-center">
                  <div className="text-danger font-bold font-mono text-base">{vt.malicious_detections || 0}</div>
                  <div className="text-text-muted">Malicious</div>
                </div>
                <div className="text-center">
                  <div className="text-warning font-bold font-mono text-base">{vt.suspicious_detections || 0}</div>
                  <div className="text-text-muted">Suspicious</div>
                </div>
                <div className="text-center">
                  <div className="text-success font-bold font-mono text-base">{vt.harmless_detections || 0}</div>
                  <div className="text-text-muted">Clean</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Tags */}
      {verdict.tags && Object.keys(verdict.tags).length > 0 && (
        <div className="px-4 py-3 flex flex-wrap gap-2">
          {Object.entries(verdict.tags).map(([k, v]) => (
            <span
              key={k}
              className="text-xs px-2 py-0.5 rounded-full font-mono"
              style={{ background: 'rgba(179,136,255,0.1)', color: '#b388ff', border: '1px solid rgba(179,136,255,0.2)' }}
            >
              {k}: {String(v)}
            </span>
          ))}
        </div>
      )}
    </motion.div>
  );
}

// ─── Stats Bar ───────────────────────────────────────────────────────────────

function StatsBar({ stats }) {
  if (!stats) return null;
  const types = stats.by_type || {};
  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      {[
        { label: 'Total IOCs', value: stats.total, color: '#00d4ff', icon: Database },
        { label: 'IP Addresses', value: types.ip?.count ?? 0, color: '#b388ff', icon: Wifi },
        { label: 'Domains', value: types.domain?.count ?? 0, color: '#00e676', icon: Globe },
        { label: 'File Hashes', value: types.hash?.count ?? 0, color: '#ffab00', icon: Hash },
        { label: 'New (24h)', value: stats.recent_24h ?? 0, color: '#ff6b35', icon: Zap },
      ].map(({ label, value, color, icon: Icon }) => (
        <motion.div
          key={label}
          whileHover={{ scale: 1.02 }}
          className="rounded-xl p-3 border flex items-center gap-3"
          style={{ background: `${color}08`, borderColor: `${color}20` }}
        >
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: `${color}15` }}>
            <Icon className="w-4 h-4" style={{ color }} />
          </div>
          <div>
            <div className="text-lg font-bold font-mono" style={{ color }}>{value?.toLocaleString()}</div>
            <div className="text-[10px] text-text-muted uppercase tracking-wider">{label}</div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

// ─── Add IOC Modal ────────────────────────────────────────────────────────────

function AddIocModal({ onClose, onAdd }) {
  const [form, setForm] = useState({
    indicator_type: 'ip',
    indicator_value: '',
    threat_score: 50,
    threat_type: '',
    source: 'manual',
    country: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    if (!form.indicator_value.trim()) { setError('Indicator value is required'); return; }
    setLoading(true);
    setError('');
    try {
      const result = await api.addIntelIoc(form);
      onAdd(result);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(6,11,20,0.85)', backdropFilter: 'blur(8px)' }}>
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="w-full max-w-md rounded-2xl border border-border-default p-6"
        style={{ background: '#0c1422' }}
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="font-orbitron text-sm font-bold text-accent">Add IOC</h3>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-text-muted mb-1.5 block">Type</label>
              <select
                value={form.indicator_type}
                onChange={(e) => setForm({ ...form, indicator_type: e.target.value })}
                className="w-full px-3 py-2 rounded-lg text-sm bg-bg-tertiary border border-border-default text-text-primary"
              >
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="hash">File Hash</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-text-muted mb-1.5 block">Threat Score (0-100)</label>
              <input
                type="number" min="0" max="100"
                value={form.threat_score}
                onChange={(e) => setForm({ ...form, threat_score: Number(e.target.value) })}
                className="w-full px-3 py-2 rounded-lg text-sm bg-bg-tertiary border border-border-default text-text-primary font-mono"
              />
            </div>
          </div>

          <div>
            <label className="text-xs text-text-muted mb-1.5 block">Indicator Value</label>
            <input
              value={form.indicator_value}
              onChange={(e) => setForm({ ...form, indicator_value: e.target.value })}
              placeholder={form.indicator_type === 'ip' ? '185.220.101.1' : form.indicator_type === 'domain' ? 'evil.example.com' : 'sha256:...'}
              className="w-full px-3 py-2 rounded-lg text-sm bg-bg-tertiary border border-border-default text-text-primary font-mono"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-text-muted mb-1.5 block">Threat Type</label>
              <input
                value={form.threat_type}
                onChange={(e) => setForm({ ...form, threat_type: e.target.value })}
                placeholder="botnet, scanner…"
                className="w-full px-3 py-2 rounded-lg text-sm bg-bg-tertiary border border-border-default text-text-primary"
              />
            </div>
            <div>
              <label className="text-xs text-text-muted mb-1.5 block">Country (ISO)</label>
              <input
                value={form.country}
                onChange={(e) => setForm({ ...form, country: e.target.value })}
                placeholder="RU, CN…"
                className="w-full px-3 py-2 rounded-lg text-sm bg-bg-tertiary border border-border-default text-text-primary font-mono"
              />
            </div>
          </div>

          {error && <div className="text-danger text-xs py-2 px-3 rounded-lg bg-danger/10">{error}</div>}

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="flex-1 py-2 rounded-lg text-sm border border-border-default text-text-secondary hover:text-text-primary transition-colors">
              Cancel
            </button>
            <button type="submit" disabled={loading}
              className="flex-1 py-2 rounded-lg text-sm font-semibold bg-accent text-bg-primary hover:bg-accent-dark transition-colors disabled:opacity-50">
              {loading ? 'Adding…' : 'Add IOC'}
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}

// ─── Feed Status Cards ────────────────────────────────────────────────────────

function FeedStatusCards({ feeds, onSync, syncingFeeds }) {
  const statusColors = { synced: '#00e676', error: '#ff3b5c', pending: '#ffab00' };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
      {feeds.map((feed) => {
        const color = statusColors[feed.status] || '#8aa4c8';
        const syncing = syncingFeeds.has(feed.id);

        return (
          <motion.div
            key={feed.id}
            whileHover={{ y: -2 }}
            className="rounded-xl border p-4 flex flex-col gap-3"
            style={{ borderColor: `${color}25`, background: `${color}05` }}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{
                    background: color,
                    boxShadow: `0 0 6px ${color}`,
                    animation: syncing ? 'pulse 1s infinite' : 'none',
                  }} />
                  <span className="text-sm font-semibold text-text-primary truncate">{feed.name}</span>
                </div>
                <p className="text-xs text-text-muted line-clamp-2">{feed.description}</p>
              </div>
              <button
                onClick={() => onSync(feed.id)}
                disabled={syncing}
                className="shrink-0 p-1.5 rounded-lg text-text-muted hover:text-accent transition-colors"
                title={syncing ? 'Syncing…' : 'Sync now'}
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin text-accent' : ''}`} />
              </button>
            </div>

            <div className="grid grid-cols-3 gap-2 text-center">
              <div>
                <div className="text-xs font-bold font-mono text-text-primary">{feed.total_imported.toLocaleString()}</div>
                <div className="text-[9px] text-text-muted uppercase tracking-wider">Imported</div>
              </div>
              <div>
                <div className="text-xs font-bold font-mono text-text-primary">{feed.last_count.toLocaleString()}</div>
                <div className="text-[9px] text-text-muted uppercase tracking-wider">Last Batch</div>
              </div>
              <div>
                <div className="text-xs font-bold font-mono truncate" style={{ color }}>
                  {feed.status.toUpperCase()}
                </div>
                <div className="text-[9px] text-text-muted uppercase tracking-wider">Status</div>
              </div>
            </div>

            <div className="text-[10px] text-text-muted flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {feed.last_sync ? `Last sync: ${timeAgo(feed.last_sync)}` : 'Never synced'}
            </div>

            {feed.last_error && (
              <div className="text-[10px] text-danger bg-danger/10 rounded-lg px-2 py-1 truncate">
                {feed.last_error}
              </div>
            )}
          </motion.div>
        );
      })}
    </div>
  );
}

// ─── IOC Table ────────────────────────────────────────────────────────────────

function IocTable({ iocs, onDelete, onLookup, isLoading }) {
  const [expandedId, setExpandedId] = useState(null);

  return (
    <div className="rounded-xl border border-border-default overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-bg-tertiary text-text-muted text-left">
            <th className="px-4 py-3 text-xs uppercase tracking-wider">Type</th>
            <th className="px-4 py-3 text-xs uppercase tracking-wider">Indicator</th>
            <th className="px-4 py-3 text-xs uppercase tracking-wider">Score</th>
            <th className="px-4 py-3 text-xs uppercase tracking-wider">Threat Type</th>
            <th className="px-4 py-3 text-xs uppercase tracking-wider">Source</th>
            <th className="px-4 py-3 text-xs uppercase tracking-wider">Country</th>
            <th className="px-4 py-3 text-xs uppercase tracking-wider">Last Seen</th>
            <th className="px-4 py-3 text-xs uppercase tracking-wider w-24">Actions</th>
          </tr>
        </thead>
        <tbody>
          {iocs.length === 0 && (
            <tr>
              <td colSpan={8} className="px-4 py-12 text-center text-text-muted">
                <Database className="w-8 h-8 mx-auto mb-3 opacity-30" />
                <div>No IOCs found</div>
              </td>
            </tr>
          )}
          {iocs.map((ioc) => {
            const color = scoreColor(ioc.threat_score);
            const isExpanded = expandedId === ioc.id;

            return [
              <tr
                key={ioc.id}
                className="border-t border-border-default hover:bg-bg-tertiary/50 transition-colors cursor-pointer"
                onClick={() => setExpandedId(isExpanded ? null : ioc.id)}
              >
                <td className="px-4 py-3">
                  <span className="flex items-center gap-1.5 text-text-secondary">
                    {typeIcon(ioc.indicator_type)}
                    <span className="text-xs uppercase">{ioc.indicator_type}</span>
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="font-mono text-xs text-text-primary">{ioc.indicator_value}</span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 rounded-full bg-bg-quaternary overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${ioc.threat_score}%`,
                          background: color,
                          boxShadow: `0 0 6px ${color}80`,
                        }}
                      />
                    </div>
                    <span className="text-xs font-mono font-bold" style={{ color }}>
                      {Math.round(ioc.threat_score)}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs px-2 py-0.5 rounded-full" style={{
                    background: `${color}15`, color, border: `1px solid ${color}30`,
                  }}>
                    {ioc.threat_type || '—'}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-text-muted">{ioc.source || '—'}</td>
                <td className="px-4 py-3 text-base">
                  {ioc.country ? countryFlag(ioc.country) : '—'}
                  {ioc.country && <span className="text-xs text-text-muted ml-1">{ioc.country}</span>}
                </td>
                <td className="px-4 py-3 text-xs text-text-muted">{timeAgo(ioc.last_seen)}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                    {ioc.indicator_type === 'ip' && (
                      <button
                        onClick={() => onLookup('ip', ioc.indicator_value)}
                        className="p-1.5 rounded-lg text-text-muted hover:text-accent transition-colors"
                        title="Enrich"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      onClick={() => onDelete(ioc.id)}
                      className="p-1.5 rounded-lg text-text-muted hover:text-danger transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </td>
              </tr>,
              isExpanded && (
                <tr key={`${ioc.id}-exp`} className="bg-bg-secondary border-t border-border-default">
                  <td colSpan={8} className="px-6 py-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                      <div>
                        <div className="text-text-muted mb-1">ISP</div>
                        <div className="text-text-primary font-mono">{ioc.isp || '—'}</div>
                      </div>
                      <div>
                        <div className="text-text-muted mb-1">First Seen</div>
                        <div className="text-text-primary font-mono">{ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : '—'}</div>
                      </div>
                      <div>
                        <div className="text-text-muted mb-1">Tags</div>
                        <div className="flex flex-wrap gap-1">
                          {ioc.tags && Object.entries(ioc.tags).slice(0, 4).map(([k, v]) => (
                            <span key={k} className="px-1.5 py-0.5 rounded-full text-purple" style={{ background: 'rgba(179,136,255,0.1)', border: '1px solid rgba(179,136,255,0.2)' }}>
                              {k}
                            </span>
                          ))}
                          {(!ioc.tags || Object.keys(ioc.tags).length === 0) && <span className="text-text-muted">—</span>}
                        </div>
                      </div>
                      <div>
                        <div className="text-text-muted mb-1">ID</div>
                        <div className="text-text-primary font-mono">#{ioc.id}</div>
                      </div>
                    </div>
                  </td>
                </tr>
              ),
            ].filter(Boolean);
          })}
        </tbody>
      </table>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'lookup', label: 'Lookup', icon: Search },
  { id: 'iocs', label: 'IOC Database', icon: Database },
  { id: 'feeds', label: 'Feed Status', icon: Activity },
];

const INDICATOR_TYPES = [
  { value: 'ip', label: 'IP Address', placeholder: '185.220.101.1' },
  { value: 'domain', label: 'Domain', placeholder: 'evil-site.ru' },
  { value: 'hash', label: 'File Hash', placeholder: 'sha256 or md5 hash' },
];

export default function ThreatIntelPage() {
  const [activeTab, setActiveTab] = useState('lookup');

  // Lookup state
  const [lookupType, setLookupType] = useState('ip');
  const [lookupValue, setLookupValue] = useState('');
  const [verdict, setVerdict] = useState(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState('');

  // IOC table state
  const [iocs, setIocs] = useState([]);
  const [iocSearch, setIocSearch] = useState('');
  const [iocType, setIocType] = useState('');
  const [iocMinScore, setIocMinScore] = useState(0);
  const [iocLoading, setIocLoading] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);

  // Feed state
  const [feeds, setFeeds] = useState([]);
  const [syncingFeeds, setSyncingFeeds] = useState(new Set());
  const [isSyncingAll, setIsSyncingAll] = useState(false);

  // Stats
  const [stats, setStats] = useState(null);

  // Load stats once
  useEffect(() => {
    api.getIntelStats().then(setStats).catch(console.error);
    api.getFeedStatus().then(setFeeds).catch(console.error);
  }, []);

  // Load IOCs when tab/filter changes
  useEffect(() => {
    if (activeTab !== 'iocs') return;
    loadIocs();
  }, [activeTab, iocType, iocMinScore]);

  const loadIocs = useCallback(async () => {
    setIocLoading(true);
    try {
      const params = { limit: 200 };
      if (iocType) params.indicator_type = iocType;
      if (iocMinScore > 0) params.min_score = iocMinScore;
      if (iocSearch) params.search = iocSearch;
      const data = await api.getIntel(params);
      setIocs(data || []);
    } catch (e) {
      console.error(e);
    } finally {
      setIocLoading(false);
    }
  }, [iocType, iocMinScore, iocSearch]);

  const doLookup = async () => {
    if (!lookupValue.trim()) return;
    setLookupLoading(true);
    setLookupError('');
    setVerdict(null);
    try {
      const result = await api.enrichIndicator(lookupType, lookupValue.trim());
      setVerdict(result);
      // Refresh stats
      api.getIntelStats().then(setStats).catch(console.error);
    } catch (e) {
      setLookupError(e.message);
    } finally {
      setLookupLoading(false);
    }
  };

  const handleLookupFromTable = (type, value) => {
    setLookupType(type);
    setLookupValue(value);
    setActiveTab('lookup');
    // auto-trigger
    setTimeout(doLookup, 100);
  };

  const handleBlock = async (ip) => {
    try {
      await api.blockIP(ip);
      setVerdict((v) => v ? { ...v, threat_type: 'blocked', final_score: 99 } : v);
      api.getIntelStats().then(setStats);
    } catch (e) {
      console.error(e);
    }
  };

  const handleUnblock = async (ip) => {
    try {
      await api.unblockIP(ip);
      doLookup();
    } catch (e) {
      console.error(e);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this IOC?')) return;
    try {
      await api.deleteIntelIoc(id);
      setIocs((prev) => prev.filter((x) => x.id !== id));
      api.getIntelStats().then(setStats);
    } catch (e) {
      console.error(e);
    }
  };

  const handleSyncFeed = async (feedKey) => {
    setSyncingFeeds((s) => new Set(s).add(feedKey));
    try {
      await api.syncSingleFeed(feedKey);
      const updated = await api.getFeedStatus();
      setFeeds(updated);
      api.getIntelStats().then(setStats);
    } catch (e) {
      console.error(e);
    } finally {
      setSyncingFeeds((s) => { const n = new Set(s); n.delete(feedKey); return n; });
    }
  };

  const handleSyncAll = async () => {
    setIsSyncingAll(true);
    try {
      await api.syncFeeds();
      // Poll status after a delay
      setTimeout(async () => {
        const updated = await api.getFeedStatus();
        setFeeds(updated);
        api.getIntelStats().then(setStats);
        setIsSyncingAll(false);
      }, 3000);
    } catch (e) {
      console.error(e);
      setIsSyncingAll(false);
    }
  };

  const handleSearchIoc = (e) => {
    e.preventDefault();
    loadIocs();
  };

  const handleIocAdded = (newIoc) => {
    setIocs((prev) => [newIoc, ...prev]);
    api.getIntelStats().then(setStats);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="font-orbitron text-2xl font-bold text-text-primary flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent to-purple flex items-center justify-center">
              <Globe className="w-4 h-4 text-bg-primary" />
            </div>
            Threat Intelligence
          </h1>
          <p className="text-text-muted text-sm mt-1">IOC enrichment, feed management, and IP reputation</p>
        </div>
        {activeTab === 'iocs' && (
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-accent text-bg-primary text-sm font-semibold hover:bg-accent-dark transition-colors"
          >
            <Plus className="w-4 h-4" /> Add IOC
          </button>
        )}
        {activeTab === 'feeds' && (
          <button
            onClick={handleSyncAll}
            disabled={isSyncingAll}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-bg-tertiary border border-border-default text-sm text-text-primary hover:border-accent/40 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isSyncingAll ? 'animate-spin text-accent' : ''}`} />
            {isSyncingAll ? 'Syncing…' : 'Sync All'}
          </button>
        )}
      </div>

      {/* Stats Bar */}
      <StatsBar stats={stats} />

      {/* Tab Bar */}
      <div className="flex gap-1 p-1 rounded-xl bg-bg-secondary border border-border-default w-fit">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
              activeTab === id
                ? 'bg-accent/10 text-accent'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">

        {/* ── Lookup Tab ─────────────────────────────────────────────────── */}
        {activeTab === 'lookup' && (
          <motion.div
            key="lookup"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-6"
          >
            {/* Input */}
            <div className="rounded-2xl border border-border-default p-5 bg-bg-secondary">
              <div className="text-xs font-semibold text-text-muted uppercase tracking-widest mb-4">
                Indicator Enrichment
              </div>

              {/* Type selector */}
              <div className="flex gap-2 mb-4">
                {INDICATOR_TYPES.map(({ value, label }) => (
                  <button
                    key={value}
                    onClick={() => { setLookupType(value); setVerdict(null); }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                      lookupType === value
                        ? 'bg-accent text-bg-primary'
                        : 'bg-bg-tertiary text-text-secondary hover:text-text-primary border border-border-default'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              <div className="flex gap-3">
                <input
                  value={lookupValue}
                  onChange={(e) => setLookupValue(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && doLookup()}
                  placeholder={INDICATOR_TYPES.find((t) => t.value === lookupType)?.placeholder}
                  className="flex-1 px-4 py-2.5 rounded-xl bg-bg-tertiary border border-border-default font-mono text-sm text-text-primary placeholder-text-muted focus:border-accent/50"
                />
                <button
                  onClick={doLookup}
                  disabled={lookupLoading || !lookupValue.trim()}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-accent to-accent-dark text-bg-primary font-semibold text-sm hover:opacity-90 transition-opacity disabled:opacity-50"
                >
                  {lookupLoading ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4" />
                  )}
                  {lookupLoading ? 'Enriching…' : 'Enrich'}
                </button>
              </div>

              {/* Quick IPs */}
              <div className="flex flex-wrap gap-2 mt-3">
                <span className="text-xs text-text-muted">Quick test:</span>
                {['8.8.8.8', '185.220.101.1', '1.1.1.1'].map((ip) => (
                  <button
                    key={ip}
                    onClick={() => { setLookupType('ip'); setLookupValue(ip); }}
                    className="text-xs font-mono text-accent hover:underline"
                  >
                    {ip}
                  </button>
                ))}
              </div>
            </div>

            {lookupError && (
              <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-danger/10 border border-danger/20 text-danger text-sm">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                {lookupError}
              </div>
            )}

            {lookupLoading && (
              <div className="rounded-2xl border border-border-default p-8 bg-bg-secondary flex items-center justify-center gap-4">
                <RefreshCw className="w-5 h-5 text-accent animate-spin" />
                <div className="text-sm text-text-secondary">Querying external threat feeds…</div>
              </div>
            )}

            <AnimatePresence>
              {verdict && !lookupLoading && (
                <VerdictCard
                  verdict={verdict}
                  onBlock={handleBlock}
                  onUnblock={handleUnblock}
                  isLoading={false}
                />
              )}
            </AnimatePresence>
          </motion.div>
        )}

        {/* ── IOC Database Tab ───────────────────────────────────────────── */}
        {activeTab === 'iocs' && (
          <motion.div
            key="iocs"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-4"
          >
            {/* Filters */}
            <form onSubmit={handleSearchIoc} className="flex flex-wrap gap-3 items-center">
              <div className="relative flex-1 min-w-48">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
                <input
                  value={iocSearch}
                  onChange={(e) => setIocSearch(e.target.value)}
                  placeholder="Search indicators…"
                  className="w-full pl-9 pr-4 py-2 rounded-lg text-sm bg-bg-secondary border border-border-default text-text-primary placeholder-text-muted focus:border-accent/50"
                />
              </div>
              <select
                value={iocType}
                onChange={(e) => setIocType(e.target.value)}
                className="px-3 py-2 rounded-lg text-sm bg-bg-secondary border border-border-default text-text-primary"
              >
                <option value="">All Types</option>
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="hash">Hash</option>
              </select>
              <select
                value={iocMinScore}
                onChange={(e) => setIocMinScore(Number(e.target.value))}
                className="px-3 py-2 rounded-lg text-sm bg-bg-secondary border border-border-default text-text-primary"
              >
                <option value={0}>All Scores</option>
                <option value={15}>Low+</option>
                <option value={40}>Medium+</option>
                <option value={65}>High+</option>
                <option value={85}>Critical</option>
              </select>
              <button
                type="submit"
                className="px-4 py-2 rounded-lg text-sm bg-accent text-bg-primary font-medium hover:bg-accent-dark transition-colors"
              >
                Filter
              </button>
              <button
                type="button"
                onClick={loadIocs}
                className="p-2 rounded-lg border border-border-default text-text-muted hover:text-accent transition-colors"
              >
                <RefreshCw className={`w-4 h-4 ${iocLoading ? 'animate-spin text-accent' : ''}`} />
              </button>
            </form>

            <IocTable
              iocs={iocs}
              onDelete={handleDelete}
              onLookup={handleLookupFromTable}
              isLoading={iocLoading}
            />

            <div className="text-xs text-text-muted text-right">
              Showing {iocs.length.toLocaleString()} IOCs
            </div>
          </motion.div>
        )}

        {/* ── Feed Status Tab ────────────────────────────────────────────── */}
        {activeTab === 'feeds' && (
          <motion.div
            key="feeds"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-4"
          >
            <div className="flex items-center justify-between">
              <p className="text-sm text-text-secondary">
                Automatic threat intelligence feeds from trusted open-source sources.
              </p>
            </div>

            {feeds.length === 0 ? (
              <div className="rounded-xl border border-border-default p-8 text-center text-text-muted">
                <Activity className="w-8 h-8 mx-auto mb-3 opacity-30" />
                <div>Loading feed status…</div>
              </div>
            ) : (
              <FeedStatusCards
                feeds={feeds}
                onSync={handleSyncFeed}
                syncingFeeds={syncingFeeds}
              />
            )}

            {/* Feed warning */}
            <div className="rounded-xl border border-warning/20 bg-warning/5 px-4 py-3 flex gap-3 items-start">
              <AlertTriangle className="w-4 h-4 text-warning shrink-0 mt-0.5" />
              <div className="text-xs text-text-secondary">
                <strong className="text-warning">Note:</strong> Syncing imports from external feeds. First sync may import thousands of IOCs.
                This runs as a background task — check back in a moment after triggering.
              </div>
            </div>
          </motion.div>
        )}

      </AnimatePresence>

      {/* Add IOC Modal */}
      <AnimatePresence>
        {showAddModal && (
          <AddIocModal onClose={() => setShowAddModal(false)} onAdd={handleIocAdded} />
        )}
      </AnimatePresence>
    </div>
  );
}
