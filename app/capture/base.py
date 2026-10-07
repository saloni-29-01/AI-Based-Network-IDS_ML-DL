"""Common controls for traffic sources (start / pause / resume / stop / speed)."""
from __future__ import annotations

import threading
import time

from app.utils.logging_setup import get_logger

log = get_logger("source")

SPEEDS = [0.5, 1.0, 2.0, 5.0, 10.0]


class SourceBase:
    mode = "idle"
    label = "Idle"

    def __init__(self, engine, speed: float = 1.0):
        self.engine = engine
        self.speed = float(speed)
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._thread: threading.Thread | None = None
        self.state = "created"     # created | running | paused | finished | stopped | error
        self.error: str | None = None
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.progress: dict = {}

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_safe, name=f"source-{self.mode}", daemon=True)
        self.state = "running"
        self.started_at = time.time()
        self._thread.start()

    def _run_safe(self) -> None:
        try:
            self.run()
            if self.state == "running":
                self.state = "finished"
        except Exception as exc:  # surface errors to UI instead of dying silently
            self.state = "error"
            self.error = f"{type(exc).__name__}: {exc}"
            log.exception(f"{self.mode} source failed: {exc}")
        finally:
            self.finished_at = time.time()
            self.engine.on_source_finished(self)

    def run(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def stop(self) -> None:
        self._stop.set()
        self._pause.clear()
        if self.state in ("running", "paused"):
            self.state = "stopped"

    def pause(self) -> None:
        if self.state == "running":
            self._pause.set()
            self.state = "paused"

    def resume(self) -> None:
        if self.state == "paused":
            self._pause.clear()
            self.state = "running"

    def set_speed(self, speed: float) -> None:
        if speed <= 0 or speed > 100:
            raise ValueError("speed must be in (0, 100]")
        self.speed = float(speed)

    def join(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def _wait(self, seconds: float) -> bool:
        """Sleep honouring pause/stop. Returns False if stopped."""
        end = time.time() + max(0.0, seconds)
        while True:
            if self._stop.is_set():
                return False
            if self._pause.is_set():
                time.sleep(0.1)
                end += 0.1
                continue
            remaining = end - time.time()
            if remaining <= 0:
                return True
            time.sleep(min(remaining, 0.1))

    def info(self) -> dict:
        return {"mode": self.mode, "label": self.label, "state": self.state, "speed": self.speed,
                "error": self.error, "started_at": self.started_at,
                "finished_at": self.finished_at, "progress": self.progress}
