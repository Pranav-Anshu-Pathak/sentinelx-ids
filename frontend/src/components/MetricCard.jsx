import { useEffect, useState, useRef } from 'react';
import { motion, useSpring, useTransform } from 'framer-motion';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

const colorMap = {
  cyan: {
    gradient: 'from-accent/20 to-accent/5',
    border: 'border-accent/20',
    text: 'text-accent',
    glow: 'shadow-[0_0_20px_rgba(0,212,255,0.1)]',
    icon: 'text-accent',
  },
  red: {
    gradient: 'from-danger/20 to-danger/5',
    border: 'border-danger/20',
    text: 'text-danger',
    glow: 'shadow-[0_0_20px_rgba(255,59,92,0.1)]',
    icon: 'text-danger',
  },
  green: {
    gradient: 'from-success/20 to-success/5',
    border: 'border-success/20',
    text: 'text-success',
    glow: 'shadow-[0_0_20px_rgba(0,230,118,0.1)]',
    icon: 'text-success',
  },
  amber: {
    gradient: 'from-warning/20 to-warning/5',
    border: 'border-warning/20',
    text: 'text-warning',
    glow: 'shadow-[0_0_20px_rgba(255,171,0,0.1)]',
    icon: 'text-warning',
  },
  purple: {
    gradient: 'from-purple/20 to-purple/5',
    border: 'border-purple/20',
    text: 'text-purple',
    glow: 'shadow-[0_0_20px_rgba(179,136,255,0.1)]',
    icon: 'text-purple',
  },
};

function AnimatedNumber({ value }) {
  const spring = useSpring(0, { stiffness: 50, damping: 20 });
  const display = useTransform(spring, (v) => {
    if (typeof value === 'string' && value.includes('%')) {
      return v.toFixed(1) + '%';
    }
    if (v >= 1000000) return (v / 1000000).toFixed(1) + 'M';
    if (v >= 1000) return (v / 1000).toFixed(1) + 'K';
    return Math.floor(v).toLocaleString();
  });

  useEffect(() => {
    const numVal = parseFloat(String(value).replace(/[%,KMkm]/g, ''));
    spring.set(numVal);
  }, [value, spring]);

  return <motion.span>{display}</motion.span>;
}

export default function MetricCard({
  label,
  value,
  change,
  changeLabel,
  color = 'cyan',
  icon: Icon,
}) {
  const colors = colorMap[color] || colorMap.cyan;
  const changeDir = change > 0 ? 'up' : change < 0 ? 'down' : 'flat';

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -2, transition: { duration: 0.2 } }}
      className={`relative overflow-hidden rounded-xl bg-gradient-to-br ${colors.gradient} border ${colors.border} p-5 ${colors.glow} group`}
    >
      {/* Background glow effect */}
      <div className="absolute -top-12 -right-12 w-32 h-32 rounded-full bg-gradient-to-br from-current to-transparent opacity-5 group-hover:opacity-10 transition-opacity" />

      <div className="relative z-10">
        {/* Header */}
        <div className="flex items-center justify-between mb-3">
          <span className="text-[10px] font-semibold text-text-muted tracking-[0.15em] uppercase">
            {label}
          </span>
          {Icon && (
            <div className={`p-1.5 rounded-lg bg-bg-primary/40 ${colors.icon}`}>
              <Icon className="w-4 h-4" />
            </div>
          )}
        </div>

        {/* Value */}
        <div className={`text-3xl font-bold ${colors.text} font-mono leading-none mb-2`}>
          <AnimatedNumber value={value} />
        </div>

        {/* Change Indicator */}
        {change !== undefined && (
          <div className="flex items-center gap-1.5">
            {changeDir === 'up' && <TrendingUp className="w-3 h-3 text-danger" />}
            {changeDir === 'down' && <TrendingDown className="w-3 h-3 text-success" />}
            {changeDir === 'flat' && <Minus className="w-3 h-3 text-text-muted" />}
            <span
              className={`text-[11px] font-medium ${
                changeDir === 'up' ? 'text-danger' : changeDir === 'down' ? 'text-success' : 'text-text-muted'
              }`}
            >
              {change > 0 ? '+' : ''}{change}%
            </span>
            {changeLabel && (
              <span className="text-[10px] text-text-muted ml-1">{changeLabel}</span>
            )}
          </div>
        )}
      </div>
    </motion.div>
  );
}
