import { motion, AnimatePresence } from 'framer-motion';
import { X, Cpu, Sparkles } from 'lucide-react';

export default function AIModal({ open, title, subtitle, provider, loading, onClose, children }) {
  if (!open) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          className="w-full max-w-2xl max-h-[85vh] flex flex-col rounded-xl border border-border-default bg-bg-secondary shadow-2xl"
        >
          <div className="flex items-center justify-between px-5 py-4 border-b border-border-default">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple/20">
                <Sparkles className="w-5 h-5 text-purple" />
              </div>
              <div>
                <h2 className="font-semibold text-text-primary">{title}</h2>
                {subtitle && <p className="text-xs text-text-muted mt-0.5">{subtitle}</p>}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {provider && (
                <span className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-bg-tertiary text-text-muted">
                  <Cpu className="w-3 h-3" />
                  {provider}
                </span>
              )}
              <button onClick={onClose} className="p-1.5 rounded hover:bg-bg-tertiary text-text-muted">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-5">
            {loading ? (
              <p className="text-sm text-text-muted animate-pulse">AI analyzing...</p>
            ) : (
              <div className="text-sm text-text-secondary whitespace-pre-wrap font-mono leading-relaxed">
                {children}
              </div>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
