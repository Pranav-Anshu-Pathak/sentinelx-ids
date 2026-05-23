const BASE_URL = '/api';

function getToken() {
  return localStorage.getItem('sentinelx_token');
}

async function request(endpoint, options = {}) {
  const token = getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (res.status === 401) {
      localStorage.removeItem('sentinelx_token');
      window.location.href = '/login';
      return null;
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || 'Request failed');
    }

    return await res.json();
  } catch (err) {
    console.error(`API Error [${endpoint}]:`, err);
    throw err;
  }
}

export const api = {
  login: (username, password) =>
    request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  getLogs: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/logs${query ? `?${query}` : ''}`);
  },

  getAlerts: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/alerts${query ? `?${query}` : ''}`);
  },

  getAlertById: (id) => request(`/alerts/${id}`),

  updateAlert: (id, data) =>
    request(`/alerts/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  getRules: () => request('/rules'),

  toggleRule: (id, enabled) =>
    request(`/rules/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    }),

  // ── Threat Intel ─────────────────────────────────────────────────────
  getIntel: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/intel/iocs${query ? `?${query}` : ''}`);
  },

  getIntelStats: () => request('/intel/stats'),

  lookupIP: (ip) => request(`/intel/lookup/${ip}`),

  enrichIndicator: (indicator_type, value) =>
    request('/intel/enrich', {
      method: 'POST',
      body: JSON.stringify({ indicator_type, value }),
    }),

  getIntelIocById: (id) => request(`/intel/iocs/${id}`),

  deleteIntelIoc: (id) =>
    request(`/intel/iocs/${id}`, { method: 'DELETE' }),

  addIntelIoc: (data) =>
    request('/intel/iocs', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updateIntelIoc: (id, data) =>
    request(`/intel/iocs/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  blockIP: (ip) =>
    request('/intel/block', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    }),

  unblockIP: (ip) =>
    request('/intel/unblock', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    }),

  geoLookup: (ip) => request(`/intel/geo/${ip}`),

  getFeedStatus: () => request('/intel/feeds/status'),

  syncFeeds: () =>
    request('/intel/feeds/sync', { method: 'POST' }),

  syncSingleFeed: (feedKey) =>
    request(`/intel/feeds/sync/${feedKey}`, { method: 'POST' }),

  getHealth: () => request('/health'),

  getMetrics: () => request('/metrics'),

  getDashboard: () => request('/dashboard'),

  chat: (message, alertId = null) =>
    request('/copilot/chat', {
      method: 'POST',
      body: JSON.stringify({ message, ...(alertId ? { alert_id: alertId } : {}) }),
    }),

  // ── AI / LLM ─────────────────────────────────────────────────────────
  getAiStatus: () => request('/ai/status'),

  aiChat: (message, alertId = null) =>
    request('/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ message, ...(alertId ? { alert_id: alertId } : {}) }),
    }),

  aiAnalyzeAlert: (alertId) => request(`/ai/analyze-alert/${alertId}`, { method: 'POST' }),

  aiExplainAttack: (attackType) =>
    request('/ai/explain-attack', {
      method: 'POST',
      body: JSON.stringify({ attack_type: attackType }),
    }),

  aiRemediate: (alertId) => request(`/ai/remediate/${alertId}`, { method: 'POST' }),

  aiScoreEvent: (payload) =>
    request('/ai/score-event', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  aiScoreAlert: (alertId) => request(`/ai/score-alert/${alertId}`, { method: 'POST' }),

  aiNlpSearch: (query) =>
    request('/ai/nlp-search', {
      method: 'POST',
      body: JSON.stringify({ query }),
    }),

  nlpSearch: (query) =>
    request('/search/query', {
      method: 'POST',
      body: JSON.stringify({ query }),
    }),

  getSearchSuggestions: () => request('/search/suggestions'),

  // ── Notifications ─────────────────────────────────────────────────────
  getNotificationConfig: () => request('/notifications/config'),

  getNotificationHistory: () => request('/notifications/history'),

  testNotifications: () =>
    request('/notifications/test', { method: 'POST' }),

  testNotificationChannel: (channel) =>
    request(`/notifications/test/${channel}`, { method: 'POST' }),

  // ── Audit Log ─────────────────────────────────────────────────────────
  getAuditLogs: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/audit${q ? `?${q}` : ''}`);
  },

  getAuditStats: (days = 7) => request(`/audit/stats?days=${days}`),

  getAuditActions: () => request('/audit/actions'),
};

export function createWebSocket(channel) {
  const token = getToken();
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  return new WebSocket(
    `${protocol}//${host}/ws/${channel}?token=${token || 'demo'}`
  );
}

export default api;
