import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Bell, User, LogOut, ChevronDown, Search } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useWebSocket } from '../context/WebSocketContext';

export default function Topbar() {
  const { user, logout } = useAuth();
  const { connected } = useWebSocket();
  const [eventsPerSec, setEventsPerSec] = useState(1247);
  const [threatLevel, setThreatLevel] = useState('ELEVATED');
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showSearch, setShowSearch] = useState(false);

  // Simulate events/sec counter
  useEffect(() => {
    const interval = setInterval(() => {
      setEventsPerSec((prev) => prev + Math.floor(Math.random() * 20) - 8);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const threatColors = {
    LOW: 'text-success bg-success/10 border-success/30',
    MODERATE: 'text-warning bg-warning/10 border-warning/30',
    ELEVATED: 'text-warning bg-warning/10 border-warning/30',
    HIGH: 'text-danger bg-danger/10 border-danger/30',
    CRITICAL: 'text-danger bg-danger/10 border-danger/30',
  };

  return (
    <header className="relative h-14 bg-bg-secondary border-b border-border-default flex items-center justify-between px-6 shrink-0 z-10">
      {/* Scan Line */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="animate-scanline absolute top-0 left-0 w-1/3 h-[1px] bg-gradient-to-r from-transparent via-accent/40 to-transparent" />
      </div>

      {/* Left Side - Brand */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="font-orbitron text-[15px] font-bold text-text-primary tracking-wider leading-none">
            SENTINEL<span className="text-accent">X</span> IDS
          </h1>
          <p className="text-[8px] text-text-muted tracking-[0.25em] mt-0.5">
            AI-POWERED INTRUSION DETECTION
          </p>
        </div>

        {/* Status */}
        <div className="flex items-center gap-2 ml-4 pl-4 border-l border-border-default">
          <div className="relative">
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-success' : 'bg-danger'}`} />
            <div className={`absolute inset-0 w-2 h-2 rounded-full animate-pulse-ring ${connected ? 'bg-success' : 'bg-danger'}`} />
          </div>
          <span className={`text-[10px] font-semibold tracking-wider ${connected ? 'text-success' : 'text-danger'}`}>
            {connected ? 'SYSTEMS NOMINAL' : 'CONNECTING...'}
          </span>
        </div>
      </div>

      {/* Right Side */}
      <div className="flex items-center gap-4">
        {/* Search */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setShowSearch(!showSearch)}
          className="p-2 text-text-muted hover:text-text-primary transition-colors"
        >
          <Search className="w-4 h-4" />
        </motion.button>

        {/* Events/sec */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg-tertiary border border-border-default">
          <div className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
          <span className="text-[11px] text-text-secondary">
            <span className="text-accent font-bold">{eventsPerSec.toLocaleString()}</span> evt/s
          </span>
        </div>

        {/* Threat Level */}
        <div className={`hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg border text-[11px] font-bold tracking-wider ${threatColors[threatLevel]}`}>
          <div className="w-1.5 h-1.5 rounded-full bg-current animate-pulse-glow" />
          {threatLevel}
        </div>

        {/* Notifications */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          className="relative p-2 text-text-muted hover:text-text-primary transition-colors"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-danger rounded-full text-[8px] font-bold text-white flex items-center justify-center">
            3
          </span>
        </motion.button>

        {/* User Menu */}
        <div className="relative">
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg-tertiary border border-border-default hover:border-border-light transition-colors"
          >
            <div className="w-6 h-6 rounded-full bg-gradient-to-br from-accent to-purple flex items-center justify-center">
              <User className="w-3.5 h-3.5 text-bg-primary" />
            </div>
            <span className="text-[12px] text-text-primary font-medium hidden sm:block">
              {user?.username || 'Admin'}
            </span>
            <ChevronDown className="w-3 h-3 text-text-muted" />
          </button>

          {/* Dropdown */}
          {showUserMenu && (
            <motion.div
              initial={{ opacity: 0, y: -8, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.95 }}
              className="absolute right-0 top-full mt-2 w-48 py-2 bg-bg-tertiary border border-border-default rounded-xl shadow-2xl z-50"
            >
              <div className="px-4 py-2 border-b border-border-default">
                <p className="text-[12px] text-text-primary font-medium">{user?.name || user?.username || 'Admin'}</p>
                <p className="text-[10px] text-text-muted">{user?.role || 'analyst'}</p>
              </div>
              <button
                onClick={logout}
                className="flex items-center gap-2 w-full px-4 py-2.5 text-[12px] text-danger hover:bg-danger/10 transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out
              </button>
            </motion.div>
          )}
        </div>
      </div>
    </header>
  );
}
