import { useState } from 'react';
import { motion } from 'framer-motion';

const mitreTactics = [
  {
    name: 'Initial Access',
    id: 'TA0001',
    techniques: [
      { id: 'T1190', name: 'Exploit Public App', count: 23, active: true },
      { id: 'T1133', name: 'External Remote Svc', count: 8, active: true },
      { id: 'T1566', name: 'Phishing', count: 15, active: true },
      { id: 'T1078', name: 'Valid Accounts', count: 5, active: false },
    ],
  },
  {
    name: 'Execution',
    id: 'TA0002',
    techniques: [
      { id: 'T1059', name: 'Command & Script', count: 31, active: true },
      { id: 'T1203', name: 'Exploit for Exec', count: 12, active: true },
      { id: 'T1204', name: 'User Execution', count: 3, active: false },
      { id: 'T1047', name: 'WMI', count: 0, active: false },
    ],
  },
  {
    name: 'Persistence',
    id: 'TA0003',
    techniques: [
      { id: 'T1053', name: 'Scheduled Task', count: 7, active: true },
      { id: 'T1136', name: 'Create Account', count: 2, active: false },
      { id: 'T1098', name: 'Account Manip.', count: 0, active: false },
      { id: 'T1547', name: 'Boot Autostart', count: 4, active: false },
    ],
  },
  {
    name: 'Priv Escalation',
    id: 'TA0004',
    techniques: [
      { id: 'T1068', name: 'Exploit for Priv Esc', count: 9, active: true },
      { id: 'T1548', name: 'Abuse Elevation', count: 3, active: false },
      { id: 'T1134', name: 'Token Manip.', count: 0, active: false },
      { id: 'T1055', name: 'Process Injection', count: 6, active: true },
    ],
  },
  {
    name: 'Defense Evasion',
    id: 'TA0005',
    techniques: [
      { id: 'T1027', name: 'Obfuscated Files', count: 18, active: true },
      { id: 'T1070', name: 'Indicator Removal', count: 4, active: false },
      { id: 'T1036', name: 'Masquerading', count: 11, active: true },
      { id: 'T1562', name: 'Impair Defenses', count: 2, active: false },
    ],
  },
  {
    name: 'Lateral Movement',
    id: 'TA0008',
    techniques: [
      { id: 'T1021', name: 'Remote Services', count: 14, active: true },
      { id: 'T1570', name: 'Lateral Tool Xfer', count: 1, active: false },
      { id: 'T1080', name: 'Taint Shared', count: 0, active: false },
      { id: 'T1563', name: 'Remote Svc Hijack', count: 0, active: false },
    ],
  },
  {
    name: 'Collection',
    id: 'TA0009',
    techniques: [
      { id: 'T1005', name: 'Local Data', count: 6, active: true },
      { id: 'T1114', name: 'Email Collection', count: 0, active: false },
      { id: 'T1119', name: 'Auto Collection', count: 2, active: false },
      { id: 'T1074', name: 'Data Staged', count: 3, active: false },
    ],
  },
  {
    name: 'Exfiltration',
    id: 'TA0010',
    techniques: [
      { id: 'T1041', name: 'Exfil Over C2', count: 8, active: true },
      { id: 'T1048', name: 'Exfil Over Alt', count: 5, active: true },
      { id: 'T1567', name: 'Exfil Over Web', count: 1, active: false },
      { id: 'T1020', name: 'Auto Exfiltration', count: 0, active: false },
    ],
  },
];

function getHeatColor(count, active) {
  if (count >= 20) return { bg: 'bg-danger/70', border: 'border-danger/50', glow: 'shadow-danger/20' };
  if (count >= 10) return { bg: 'bg-warning/50', border: 'border-warning/40', glow: 'shadow-warning/20' };
  if (count >= 1) return { bg: 'bg-accent/30', border: 'border-accent/30', glow: 'shadow-accent/10' };
  return { bg: 'bg-bg-quaternary/40', border: 'border-border-default', glow: '' };
}

export default function MitreHeatmap() {
  const [hoveredTechnique, setHoveredTechnique] = useState(null);

  return (
    <div className="space-y-1">
      {mitreTactics.map((tactic, ti) => (
        <div key={tactic.id}>
          <div className="text-[9px] text-text-muted font-semibold tracking-wider mb-1 uppercase">
            {tactic.name}
          </div>
          <div className="grid grid-cols-4 gap-1 mb-2">
            {tactic.techniques.map((tech, i) => {
              const colors = getHeatColor(tech.count, tech.active);
              return (
                <motion.div
                  key={tech.id}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: (ti * 4 + i) * 0.02 }}
                  whileHover={{ scale: 1.08, zIndex: 10 }}
                  onMouseEnter={() => setHoveredTechnique(tech)}
                  onMouseLeave={() => setHoveredTechnique(null)}
                  className={`relative px-1.5 py-1.5 rounded text-center cursor-pointer border ${colors.bg} ${colors.border} transition-all ${colors.glow ? `shadow-md ${colors.glow}` : ''}`}
                >
                  <div className="text-[8px] text-text-primary/80 font-medium truncate">{tech.name}</div>
                  <div className="text-[9px] text-text-muted mt-0.5">{tech.id}</div>
                  {tech.count > 0 && (
                    <div className="text-[9px] font-bold text-text-primary mt-0.5">{tech.count}</div>
                  )}
                </motion.div>
              );
            })}
          </div>
        </div>
      ))}

      {/* Tooltip */}
      {hoveredTechnique && (
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          className="fixed bottom-4 right-4 p-3 bg-bg-tertiary border border-border-light rounded-lg shadow-2xl z-50 max-w-xs"
        >
          <div className="text-[11px] font-bold text-accent">{hoveredTechnique.id}</div>
          <div className="text-[12px] text-text-primary font-medium">{hoveredTechnique.name}</div>
          <div className="text-[10px] text-text-muted mt-1">
            Detections: <span className="text-text-primary font-bold">{hoveredTechnique.count}</span>
          </div>
          <div className="text-[10px] text-text-muted">
            Status: <span className={hoveredTechnique.active ? 'text-danger' : 'text-text-muted'}>{hoveredTechnique.active ? 'Active Threat' : 'Monitored'}</span>
          </div>
        </motion.div>
      )}
    </div>
  );
}
