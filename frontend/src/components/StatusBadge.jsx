import { motion } from 'framer-motion';

const statusConfig = {
  open: { bg: 'bg-accent/15', text: 'text-accent', border: 'border-accent/30', dot: 'bg-accent' },
  new: { bg: 'bg-accent/15', text: 'text-accent', border: 'border-accent/30', dot: 'bg-accent' },
  investigating: { bg: 'bg-purple/15', text: 'text-purple', border: 'border-purple/30', dot: 'bg-purple' },
  in_progress: { bg: 'bg-purple/15', text: 'text-purple', border: 'border-purple/30', dot: 'bg-purple' },
  resolved: { bg: 'bg-success/15', text: 'text-success', border: 'border-success/30', dot: 'bg-success' },
  closed: { bg: 'bg-text-muted/15', text: 'text-text-muted', border: 'border-text-muted/30', dot: 'bg-text-muted' },
  blocked: { bg: 'bg-danger/15', text: 'text-danger', border: 'border-danger/30', dot: 'bg-danger' },
};

export default function StatusBadge({ status, className = '' }) {
  const st = (status || 'open').toLowerCase().replace(' ', '_');
  const config = statusConfig[st] || statusConfig.open;

  return (
    <motion.span
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider uppercase border ${config.bg} ${config.text} ${config.border} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {status}
    </motion.span>
  );
}
