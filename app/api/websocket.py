"""WebSocket broadcaster for live dashboard updates.

A single background task polls the engine ~2x/second, drains new events and
alerts, and pushes a compact JSON frame to every connected client. If no
client is connected the poll still runs cheaply (drains buffers so they
don't grow unbounded). Clients that fall behind are dropped.
"""
from __future__ import annotations

import asyncio
import contextlib
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.engine import get_engine
from app.utils.logging_setup import get_logger

log = get_logger("ws")
ws_router = APIRouter()


class Hub:
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.task: asyncio.Task | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)
        e = get_engine()
        await ws.send_text(json.dumps({"type": "hello", "status": e.status(),
                                       "stats": e.stats.snapshot()}))

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, payload: dict) -> None:
        if not self.clients:
            return
        msg = json.dumps(payload, default=str)
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def run(self) -> None:
        e = get_engine()
        while True:
            try:
                events, alerts = e.drain_updates()
                if events or alerts or self.clients:
                    await self.broadcast({
                        "type": "update",
                        "status": e.status(),
                        "stats": e.stats.snapshot(),
                        "series": e.stats.series(60),
                        "events": events[-60:],
                        "alerts": alerts[-30:],
                    })
            except Exception as exc:
                log.warning(f"ws broadcast error: {exc}")
            await asyncio.sleep(0.5)


hub = Hub()


def start_hub() -> None:
    if hub.task is None:
        hub.task = asyncio.create_task(hub.run())


async def stop_hub() -> None:
    if hub.task:
        hub.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await hub.task
        hub.task = None


@ws_router.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            # client may send ping/control; we just keep the socket open
            await asyncio.wait_for(ws.receive_text(), timeout=3600)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    except Exception as exc:
        log.info(f"ws client closed: {exc}")
    finally:
        hub.disconnect(ws)
