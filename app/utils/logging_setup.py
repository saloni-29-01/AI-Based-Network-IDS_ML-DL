"""Structured (key=value) logging with a rotating file handler."""
from __future__ import annotations

import logging
import logging.handlers
from collections import deque

from app.config import settings

_RECENT: deque[dict] = deque(maxlen=500)
_CONFIGURED = False


class _KVFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"{self.formatTime(record, '%Y-%m-%dT%H:%M:%S')} level={record.levelname} logger={record.name} msg=\"{record.getMessage()}\""
        extra = getattr(record, "kv", None)
        if extra:
            base += " " + " ".join(f"{k}={v}" for k, v in extra.items())
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


class _MemoryHandler(logging.Handler):
    """Keeps the most recent log lines so the System page can show them."""

    def emit(self, record: logging.LogRecord) -> None:
        _RECENT.append({
            "ts": record.created,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            **(getattr(record, "kv", None) or {}),
        })


def setup_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("ids")
    root.setLevel(settings.log_level.upper())
    fmt = _KVFormatter()
    fh = logging.handlers.RotatingFileHandler(
        settings.log_dir / "ids.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)
    root.addHandler(_MemoryHandler())
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(f"ids.{name}")


def log_kv(logger: logging.Logger, level: int, msg: str, **kv) -> None:
    logger.log(level, msg, extra={"kv": kv})


def recent_logs(limit: int = 200) -> list[dict]:
    return list(_RECENT)[-limit:]
