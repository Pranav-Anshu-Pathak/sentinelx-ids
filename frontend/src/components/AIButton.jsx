/** Compact AI action button with loading state. */
export default function AIButton({ label, onClick, loading, disabled, variant = 'default' }) {
  const styles = {
    default: 'bg-accent/10 text-accent border-accent/30 hover:bg-accent/20',
    purple: 'bg-purple/10 text-purple border-purple/30 hover:bg-purple/20',
    warning: 'bg-warning/10 text-warning border-warning/30 hover:bg-warning/20',
    danger: 'bg-danger/10 text-danger border-danger/30 hover:bg-danger/20',
  };

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || loading}
      className={`px-2.5 py-1 rounded text-[11px] font-medium border transition-colors disabled:opacity-40 ${styles[variant] || styles.default}`}
    >
      {loading ? '...' : label}
    </button>
  );
}
