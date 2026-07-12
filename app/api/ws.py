"""WebSocket live feed: pushes risk scores and alerts to connected dashboards."""
import asyncio
import json

from fastapi import WebSocket, WebSocketDisconnect


class ConnectionManager:
    """Tracks connected dashboard clients and broadcasts JSON messages."""

    def __init__(self) -> None:
        self._clients: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            if ws in self._clients:
                self._clients.remove(ws)

    async def broadcast(self, message: dict) -> None:
        data = json.dumps(message, default=str)
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_text(data)
            except Exception:
                await self.disconnect(ws)


manager = ConnectionManager()


async def feed_endpoint(ws: WebSocket) -> None:
    """Keep the socket open; we only push, clients don't need to send."""
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # ignore pings/any client chatter
    except WebSocketDisconnect:
        await manager.disconnect(ws)
