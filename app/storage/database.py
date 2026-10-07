"""SQLite persistence layer (stdlib ``sqlite3``; WAL mode for concurrent
reads from the API while the detection worker writes)."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    mode TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
    protocol TEXT, service TEXT, flag TEXT,
    duration REAL, src_bytes INTEGER, dst_bytes INTEGER, packets INTEGER,
    predicted_class TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    attack_probability REAL NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    engine TEXT NOT NULL,
    ground_truth TEXT,
    record_ref TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_class ON events(predicted_class);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_uid TEXT UNIQUE NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    mode TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
    protocol TEXT, service TEXT,
    predicted_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk_score INTEGER NOT NULL,
    model_used TEXT NOT NULL,
    explanation TEXT,
    risk_factors TEXT,
    status TEXT NOT NULL DEFAULT 'New',
    event_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_alerts_last ON alerts(last_seen);

CREATE TABLE IF NOT EXISTS model_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    name TEXT, task TEXT, feature_set TEXT,
    dataset TEXT, trained_at TEXT,
    accuracy REAL, f1 REAL, metrics_json TEXT
);

CREATE TABLE IF NOT EXISTS system_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    level TEXT NOT NULL,
    category TEXT NOT NULL,
    message TEXT NOT NULL
);
"""

_local = threading.local()
_init_lock = threading.Lock()
_initialised: set[str] = set()


def _db_file() -> str:
    return str(settings.db_path)


def init_db() -> None:
    with _init_lock:
        path = _db_file()
        settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()
        _initialised.add(path)


def get_conn() -> sqlite3.Connection:
    """One connection per thread (sqlite3 connections are not thread-safe)."""
    path = _db_file()
    if path not in _initialised:
        init_db()
    conns = getattr(_local, "conns", None)
    if conns is None:
        conns = _local.conns = {}
    conn = conns.get(path)
    if conn is None:
        conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=NORMAL")
        conns[path] = conn
    return conn


@contextmanager
def transaction():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def db_health() -> dict:
    try:
        conn = get_conn()
        n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        a = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        size = settings.db_path.stat().st_size if settings.db_path.exists() else 0
        return {"ok": True, "path": str(settings.db_path), "events": n, "alerts": a,
                "size_bytes": size}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
