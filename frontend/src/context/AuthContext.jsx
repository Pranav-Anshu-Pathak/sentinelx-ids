import { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { api } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem('sentinelx_token'));
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('sentinelx_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const login = useCallback(async (username, password) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.login(username, password);
      const tkn = data.access_token || data.token || 'demo-token-' + Date.now();
      const usr = data.user || { username, role: 'analyst' };

      localStorage.setItem('sentinelx_token', tkn);
      localStorage.setItem('sentinelx_user', JSON.stringify(usr));
      setToken(tkn);
      setUser(usr);
      return true;
    } catch (err) {
      // Demo mode fallback
      if (username === 'admin' && password === 'sentinelx') {
        const tkn = 'demo-token-' + Date.now();
        const usr = { username: 'admin', role: 'admin', name: 'Admin User' };
        localStorage.setItem('sentinelx_token', tkn);
        localStorage.setItem('sentinelx_user', JSON.stringify(usr));
        setToken(tkn);
        setUser(usr);
        return true;
      }
      setError(err.message || 'Authentication failed');
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('sentinelx_token');
    localStorage.removeItem('sentinelx_user');
    setToken(null);
    setUser(null);
  }, []);

  const value = {
    token,
    user,
    loading,
    error,
    isAuthenticated: !!token,
    login,
    logout,
    setError,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export default AuthContext;
