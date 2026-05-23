import { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';
import { useAuth } from './AuthContext';
import { createWebSocket } from '../api/client';

const WebSocketContext = createContext(null);

export function WebSocketProvider({ children }) {
  const { isAuthenticated } = useAuth();
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState(null);
  const subscribersRef = useRef(new Map());
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const reconnectAttemptRef = useRef(0);

  const connect = useCallback(() => {
    if (!isAuthenticated) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = createWebSocket('events');
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        reconnectAttemptRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);

          const channel = data.channel || data.type || 'default';
          const subs = subscribersRef.current.get(channel);
          if (subs) {
            subs.forEach((cb) => cb(data));
          }

          const allSubs = subscribersRef.current.get('*');
          if (allSubs) {
            allSubs.forEach((cb) => cb(data));
          }
        } catch (e) {
          console.warn('WS parse error:', e);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        const attempt = reconnectAttemptRef.current;
        const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
        reconnectAttemptRef.current = attempt + 1;

        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch (err) {
      console.error('WS connection error:', err);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [connect]);

  const subscribe = useCallback((channel, callback) => {
    if (!subscribersRef.current.has(channel)) {
      subscribersRef.current.set(channel, new Set());
    }
    subscribersRef.current.get(channel).add(callback);

    return () => {
      const subs = subscribersRef.current.get(channel);
      if (subs) {
        subs.delete(callback);
        if (subs.size === 0) subscribersRef.current.delete(channel);
      }
    };
  }, []);

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  return (
    <WebSocketContext.Provider value={{ connected, lastMessage, subscribe, send }}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocket() {
  const ctx = useContext(WebSocketContext);
  if (!ctx) throw new Error('useWebSocket must be used within WebSocketProvider');
  return ctx;
}

export default WebSocketContext;
