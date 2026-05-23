import { motion } from 'framer-motion';

const severityConfig = {
  critical: { bg: 'bg-danger/15', text: 'text-danger', border: 'border-danger/30', dot: 'bg-danger' },
  high: { bg: 'bg-warning/15', text: 'text-warning', border: 'border-warning/30', dot: 'bg-warning' },
  medium: { bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/30', dot: 'bg-yellow-400' },
  low: { bg: 'bg-success/15', text: 'text-success', border: 'border-success/30', dot: 'bg-success' },
  info: { bg: 'bg-accent/15', text: 'text-accent', border: 'border-accent/30', dot: 'bg-accent' },
};

export default function SeverityBadge({ severity, showDot = true, className = '' }) {
  const sev = (severity || 'info').toLowerCase();
  const config = severityConfig[sev] || severityConfig.info;

  return (
    <motion.span
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider uppercase border ${config.bg} ${config.text} ${config.border} ${className}`}
    >
      {showDot && (
        <span className={`w-1.5 h-1.5 rounded-full ${config.dot} ${sev === 'critical' ? 'animate-pulse' : ''}`} />
      )}
      {severity}
    </motion.span>
  );
}
