import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const severityColors = {
  INFO: 'text-accent',
  DEBUG: 'text-text-muted',
  WARNING: 'text-warning',
  ERROR: 'text-danger',
  CRITICAL: 'text-danger font-bold',
};

const sourceColors = {
  NETWORK: 'text-accent',
  AUTH: 'text-purple',
  SYSTEM: 'text-warning',
  FIREWALL: 'text-danger',
  DNS: 'text-success',
  IDS: 'text-accent',
  WEB: 'text-purple',
};

const mockLogs = [
  { id: 1, timestamp: '01:14:22.331', severity: 'INFO', source: 'NETWORK', message: 'TCP connection established from 192.168.1.105:44382 → 10.0.0.1:443', ip: '192.168.1.105' },
  { id: 2, timestamp: '01:14:22.445', severity: 'WARNING', source: 'AUTH', message: 'Failed login attempt for user "admin" from 203.0.113.15 (attempt 3/5)', ip: '203.0.113.15' },
  { id: 3, timestamp: '01:14:22.892', severity: 'ERROR', source: 'FIREWALL', message: 'Blocked inbound connection from 45.33.32.156:8080 - rule: BLOCK_SUSPICIOUS', ip: '45.33.32.156' },
  { id: 4, timestamp: '01:14:23.102', severity: 'INFO', source: 'DNS', message: 'DNS query: malware-c2.evil.com → NXDOMAIN (blocked by threat intel)', ip: '10.0.0.44' },
  { id: 5, timestamp: '01:14:23.338', severity: 'CRITICAL', source: 'IDS', message: 'ALERT: Signature match ET MALWARE Win32/Emotet CnC Activity (POST)', ip: '192.168.2.201' },
  { id: 6, timestamp: '01:14:23.556', severity: 'INFO', source: 'NETWORK', message: 'SSL/TLS handshake completed with 172.16.0.1:8443 (TLS 1.3)', ip: '172.16.0.1' },
  { id: 7, timestamp: '01:14:23.891', severity: 'WARNING', source: 'SYSTEM', message: 'CPU usage spike detected: 89% on node web-prod-01', ip: '10.0.0.5' },
  { id: 8, timestamp: '01:14:24.102', severity: 'INFO', source: 'WEB', message: 'HTTP 200 GET /api/health from 10.0.1.88 (12ms)', ip: '10.0.1.88' },
  { id: 9, timestamp: '01:14:24.445', severity: 'ERROR', source: 'AUTH', message: 'Account lockout triggered for user "jsmith" after 5 failed attempts', ip: '172.16.1.5' },
  { id: 10, timestamp: '01:14:24.667', severity: 'INFO', source: 'FIREWALL', message: 'Geo-IP block: Connection from 185.220.101.1 (TOR exit node) rejected', ip: '185.220.101.1' },
];

export default function LogStream({ logs: externalLogs, maxItems = 50 }) {
  const [logs, setLogs] = useState(externalLogs || mockLogs);
  const [isPaused, setIsPaused] = useState(false);
  const containerRef = useRef(null);
  const logIdRef = useRef(100);

  // Simulate streaming logs
  useEffect(() => {
    if (externalLogs) return;
    const templates = [
      { severity: 'INFO', source: 'NETWORK', msg: 'TCP SYN from {ip}:${port} → 10.0.0.1:443' },
      { severity: 'WARNING', source: 'AUTH', msg: 'Failed SSH login from {ip} as root' },
      { severity: 'INFO', source: 'DNS', msg: 'DNS query resolved: cdn.example.com → 104.18.22.{n}' },
      { severity: 'ERROR', source: 'FIREWALL', msg: 'Rate limit exceeded for {ip} (150 req/min)' },
      { severity: 'INFO', source: 'WEB', msg: 'HTTP 200 POST /api/auth/login from {ip} (45ms)' },
      { severity: 'WARNING', source: 'IDS', msg: 'Anomaly detected: unusual outbound traffic volume from {ip}' },
      { severity: 'INFO', source: 'SYSTEM', msg: 'Service health check passed for detection-engine' },
      { severity: 'CRITICAL', source: 'IDS', msg: 'ALERT: Possible data exfiltration detected from {ip}' },
    ];

    const interval = setInterval(() => {
      if (isPaused) return;
      const tmpl = templates[Math.floor(Math.random() * templates.length)];
      const ip = `${Math.floor(Math.random() * 200) + 10}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      const now = new Date();
      const ts = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}.${String(now.getMilliseconds()).padStart(3, '0')}`;

      const newLog = {
        id: logIdRef.current++,
        timestamp: ts,
        severity: tmpl.severity,
        source: tmpl.source,
        message: tmpl.msg.replace('{ip}', ip).replace('{n}', Math.floor(Math.random() * 255)).replace('${port}', String(30000 + Math.floor(Math.random() * 35000))),
        ip,
      };

      setLogs((prev) => [...prev.slice(-maxItems), newLog]);
    }, 1500);

    return () => clearInterval(interval);
  }, [isPaused, externalLogs, maxItems]);

  // Auto-scroll
  useEffect(() => {
    if (!isPaused && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, isPaused]);

  return (
    <div
      ref={containerRef}
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      className="space-y-0 max-h-[400px] overflow-y-auto font-mono text-[11px] leading-relaxed"
    >
      <AnimatePresence initial={false}>
        {logs.map((log) => (
          <motion.div
            key={log.id}
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="flex gap-3 px-2 py-1 hover:bg-bg-quaternary/50 rounded transition-colors group cursor-default"
          >
            <span className="text-text-muted shrink-0 w-[90px]">{log.timestamp}</span>
            <span className={`shrink-0 w-[72px] font-semibold ${severityColors[log.severity] || 'text-text-secondary'}`}>
              {log.severity}
            </span>
            <span className={`shrink-0 w-[72px] ${sourceColors[log.source] || 'text-text-secondary'}`}>
              [{log.source}]
            </span>
            <span className="text-text-secondary flex-1 truncate group-hover:text-text-primary transition-colors">
              {log.message}
            </span>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
