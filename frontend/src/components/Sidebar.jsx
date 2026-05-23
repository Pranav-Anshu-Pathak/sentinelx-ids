import { NavLink, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Zap,
  List,
  Crosshair,
  Globe,
  Hexagon,
  Sparkles,
  Settings,
  Activity,
  Shield,
  ChevronLeft,
  ChevronRight,
  ClipboardList,
} from 'lucide-react';
import { useState } from 'react';

const navSections = [
  {
    title: 'OPERATIONS',
    items: [
      { path: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
      { path: '/alerts', icon: Zap, label: 'Alerts', badge: 12 },
      { path: '/logs', icon: List, label: 'Live Logs' },
      { path: '/rules', icon: Crosshair, label: 'Det. Rules' },
    ],
  },
  {
    title: 'INTELLIGENCE',
    items: [
      { path: '/intel', icon: Globe, label: 'Threat Intel' },
      { path: '/investigations', icon: Sparkles, label: 'AI Copilot' },
    ],
  },
  {
    title: 'SYSTEM',
    items: [
      { path: '/audit',    icon: ClipboardList, label: 'Audit Log' },
      { path: '/settings', icon: Settings,      label: 'Settings' },
      { path: '/health',   icon: Activity,      label: 'Sys Health' },
    ],
  },
];

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <motion.aside
      animate={{ width: collapsed ? 72 : 240 }}
      transition={{ duration: 0.25, ease: 'easeInOut' }}
      className="relative flex flex-col h-full bg-bg-secondary border-r border-border-default overflow-hidden z-20"
    >
      {/* Brand */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-border-default shrink-0">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-accent to-accent-dark flex items-center justify-center shrink-0">
          <Shield className="w-5 h-5 text-bg-primary" />
        </div>
        {!collapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div className="font-orbitron text-sm font-bold text-accent tracking-wider leading-none">
              SENTINELX
            </div>
            <div className="text-[9px] text-text-muted tracking-widest mt-0.5">
              IDS PLATFORM
            </div>
          </motion.div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-6">
        {navSections.map((section) => (
          <div key={section.title}>
            {!collapsed && (
              <div className="px-3 mb-2 text-[10px] font-semibold text-text-muted tracking-[0.2em] uppercase">
                {section.title}
              </div>
            )}
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const isActive = item.exact
                  ? location.pathname === item.path
                  : location.pathname.startsWith(item.path);

                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className="block"
                  >
                    <motion.div
                      whileHover={{ x: 2, backgroundColor: 'rgba(0, 212, 255, 0.05)' }}
                      whileTap={{ scale: 0.98 }}
                      className={`relative flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors duration-200 group ${
                        isActive
                          ? 'bg-accent/10 text-accent'
                          : 'text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      {/* Active indicator */}
                      {isActive && (
                        <motion.div
                          layoutId="sidebar-active"
                          className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 bg-accent rounded-r-full"
                          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                        />
                      )}

                      <item.icon
                        className={`w-[18px] h-[18px] shrink-0 ${
                          isActive ? 'text-accent drop-shadow-[0_0_6px_rgba(0,212,255,0.5)]' : ''
                        }`}
                      />

                      {!collapsed && (
                        <span className="text-[13px] font-medium truncate">
                          {item.label}
                        </span>
                      )}

                      {/* Badge */}
                      {item.badge && !collapsed && (
                        <span className="ml-auto text-[10px] font-bold bg-danger/20 text-danger px-2 py-0.5 rounded-full min-w-[20px] text-center">
                          {item.badge}
                        </span>
                      )}
                      {item.badge && collapsed && (
                        <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-danger rounded-full" />
                      )}
                    </motion.div>
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Collapse Toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-center h-12 border-t border-border-default text-text-muted hover:text-text-primary transition-colors"
      >
        {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
      </button>
    </motion.aside>
  );
}
