import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, LogIn } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function LoginPage() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('sentinelx');
  const { login, loading, error } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const ok = await login(username, password);
    if (ok) navigate('/');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-primary p-6">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md rounded-2xl border border-border-default bg-bg-secondary p-8 shadow-xl"
      >
        <div className="flex items-center gap-3 mb-8">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-accent to-accent-dark flex items-center justify-center">
            <Shield className="w-7 h-7 text-bg-primary" />
          </div>
          <div>
            <h1 className="font-orbitron text-xl font-bold text-accent">SENTINELX</h1>
            <p className="text-xs text-text-muted">Intrusion Detection System</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs text-text-muted uppercase tracking-wider">Username</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-1 w-full px-4 py-2.5 rounded-lg bg-bg-primary border border-border-default text-text-primary focus:border-accent outline-none"
            />
          </div>
          <div>
            <label className="text-xs text-text-muted uppercase tracking-wider">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full px-4 py-2.5 rounded-lg bg-bg-primary border border-border-default text-text-primary focus:border-accent outline-none"
            />
          </div>
          {error && <p className="text-sm text-danger">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-accent text-bg-primary font-semibold hover:bg-accent-dark transition-colors disabled:opacity-50"
          >
            <LogIn className="w-4 h-4" />
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        <p className="mt-6 text-center text-xs text-text-muted">
          Demo: admin / sentinelx
        </p>
      </motion.div>
    </div>
  );
}
