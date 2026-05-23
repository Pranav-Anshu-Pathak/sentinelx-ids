import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import SeverityBadge from './SeverityBadge';

const mockAlerts = [
  { id: 1, title: 'Brute Force SSH Detected', severity: 'critical', source_ip: '192.168.1.105', timestamp: '2 min ago', hostname: 'web-prod-01' },
  { id: 2, title: 'Suspicious DNS Exfiltration', severity: 'high', source_ip: '10.0.0.44', timestamp: '5 min ago', hostname: 'dns-resolver' },
  { id: 3, title: 'Port Scan Detected', severity: 'high', source_ip: '172.16.0.33', timestamp: '8 min ago', hostname: 'firewall-01' },
  { id: 4, title: 'SQL Injection Attempt', severity: 'critical', source_ip: '203.0.113.15', timestamp: '12 min ago', hostname: 'api-gateway' },
  { id: 5, title: 'Anomalous Login Pattern', severity: 'medium', source_ip: '10.0.1.88', timestamp: '15 min ago', hostname: 'auth-server' },
  { id: 6, title: 'Malware C2 Communication', severity: 'critical', source_ip: '192.168.2.201', timestamp: '18 min ago', hostname: 'endpoint-42' },
  { id: 7, title: 'Privilege Escalation Attempt', severity: 'high', source_ip: '10.0.0.12', timestamp: '22 min ago', hostname: 'db-master' },
  { id: 8, title: 'Failed Login Spike', severity: 'medium', source_ip: '172.16.1.5', timestamp: '30 min ago', hostname: 'vpn-gateway' },
];

export default function AlertFeed({ alerts = mockAlerts, maxItems = 8 }) {
  const navigate = useNavigate();

  return (
    <div className="space-y-1.5 max-h-[400px] overflow-y-auto pr-1">
      {alerts.slice(0, maxItems).map((alert, i) => (
        <motion.div
          key={alert.id}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.05 }}
          whileHover={{ x: 4, backgroundColor: 'rgba(0, 212, 255, 0.03)' }}
          onClick={() => navigate('/alerts')}
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer group transition-colors border border-transparent hover:border-border-default"
        >
          {/* Severity Dot */}
          <div className={`w-2 h-2 rounded-full shrink-0 ${
            alert.severity === 'critical' ? 'bg-danger animate-pulse' :
            alert.severity === 'high' ? 'bg-warning' :
            alert.severity === 'medium' ? 'bg-yellow-400' : 'bg-success'
          }`} />

          {/* Content */}
          <div className="flex-1 min-w-0">
            <p className="text-[12px] text-text-primary font-medium truncate group-hover:text-accent transition-colors">
              {alert.title}
            </p>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-[10px] text-text-muted">{alert.hostname}</span>
              <span className="text-[10px] text-text-muted">•</span>
              <span className="text-[10px] text-text-muted font-mono">{alert.source_ip}</span>
            </div>
          </div>

          {/* Time */}
          <span className="text-[10px] text-text-muted shrink-0">{alert.timestamp}</span>
        </motion.div>
      ))}
    </div>
  );
}
