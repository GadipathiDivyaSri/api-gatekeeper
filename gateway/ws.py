"""
WebSocket Connection Manager (Module M5).
Manages live client WebSocket connections at /_gk/ws,
handles broadcasting of real-time security events, and drops dead sockets.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket, status

logger = logging.getLogger("api_gatekeeper.ws")


class WebSocketManager:
    """Manages active WebSocket connections and broadcasts security events."""

    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept incoming WebSocket connection and register it."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.debug("WebSocket client connected. Total clients: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove disconnected WebSocket from active pool."""
        self.active_connections.discard(websocket)
        logger.debug("WebSocket client disconnected. Total clients: %d", len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """
        Broadcast message dictionary to all connected clients.
        Dead or failed sockets are caught and removed without throwing.
        """
        dead_connections: list[WebSocket] = []

        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as exc:
                logger.debug("Failed sending to WebSocket client: %s", exc)
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


_DEFAULT_WS_MANAGER: WebSocketManager | None = None


def get_ws_manager() -> WebSocketManager:
    """Return globally cached WebSocketManager instance."""
    global _DEFAULT_WS_MANAGER
    if _DEFAULT_WS_MANAGER is None:
        _DEFAULT_WS_MANAGER = WebSocketManager()
    return _DEFAULT_WS_MANAGER
