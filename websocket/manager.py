"""WebSocket connection manager for real-time event broadcasting."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("sentinelx.websocket")


class ConnectionManager:
    """Manages WebSocket clients grouped by channel."""

    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, channel: str) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.setdefault(channel, set()).add(websocket)
        logger.debug("WS client joined channel=%s (total=%d)", channel, len(self._connections.get(channel, [])))

    async def disconnect(self, websocket: WebSocket, channel: str) -> None:
        async with self._lock:
            clients = self._connections.get(channel)
            if clients:
                clients.discard(websocket)
                if not clients:
                    del self._connections[channel]

    async def broadcast(self, channel: str, payload: dict[str, Any]) -> None:
        """Send JSON payload to all clients on *channel*."""
        message = json.dumps(
            {
                **payload,
                "channel": channel,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            default=str,
        )
        async with self._lock:
            clients = list(self._connections.get(channel, set()))

        dead: list[WebSocket] = []
        for ws in clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        for ws in dead:
            await self.disconnect(ws, channel)

    @property
    def connection_count(self) -> int:
        return sum(len(v) for v in self._connections.values())
