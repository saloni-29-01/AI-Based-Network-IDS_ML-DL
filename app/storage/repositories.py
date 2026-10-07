"""Data-access functions for events, alerts, model runs and system events."""
from __future__ import annotations

import json
import time

from app.storage.database import get_conn, transaction

EVENT_COLS = ["ts", "mode", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "service",
              "flag", "duration", "src_bytes", "dst_bytes", "packets", "predicted_class",
              "verdict", "confidence", "attack_probability", "risk_score", "risk_level",
              "engine", "ground_truth", "record_ref"]

ALERT_STATUSES = ["New", "Investigating", "Resolved", "Ignored"]


def insert_events(events: list[dict]) -> list[int]:
    if not events:
        return []
    ids = []
    with transaction() as conn:
        sql = f"INSERT INTO events ({','.join(EVENT_COLS)}) VALUES ({','.join('?' * len(EVENT_COLS))})"
        for e in events:
            cur = conn.execute(sql, [e.get(c) for c in EVENT_COLS])
            ids.append(cur.lastrowid)
    return ids


def _where(filters: dict) -> tuple[str, list]:
    clauses, args = [], []
    for key, col, op in [("severity", "severity", "="), ("risk_level", "risk_level", "="),
                         ("predicted_class", "predicted_class", "="), ("protocol", "protocol", "="),
                         ("status", "status", "="), ("mode", "mode", "="), ("verdict", "verdict", "=")]:
        v = filters.get(key)
        if v:
            clauses.append(f"{col} {op} ?")
            args.append(v)
    for key, col in [("src_ip", "src_ip"), ("dst_ip", "dst_ip")]:
        v = filters.get(key)
        if v:
            clauses.append(f"{col} LIKE ?")
            args.append(f"%{v}%")
    if filters.get("since"):
        clauses.append(filters.get("_ts_col", "ts") + " >= ?")
        args.append(float(filters["since"]))
    if filters.get("until"):
        clauses.append(filters.get("_ts_col", "ts") + " <= ?")
        args.append(float(filters["until"]))
    if filters.get("q"):
        q = f"%{filters['q']}%"
        clauses.append("(src_ip LIKE ? OR dst_ip LIKE ? OR service LIKE ? OR predicted_class LIKE ?)")
        args += [q, q, q, q]
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def query_events(filters: dict | None = None, limit: int = 200, offset: int = 0) -> list[dict]:
    w, args = _where(filters or {})
    rows = get_conn().execute(
        f"SELECT * FROM events{w} ORDER BY id DESC LIMIT ? OFFSET ?", args + [limit, offset]).fetchall()
    return [dict(r) for r in rows]


def count_events(filters: dict | None = None) -> int:
    w, args = _where(filters or {})
    return get_conn().execute(f"SELECT COUNT(*) FROM events{w}", args).fetchone()[0]


def get_event(event_id: int) -> dict | None:
    r = get_conn().execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    return dict(r) if r else None


# ---------------------------------------------------------------- alerts
def insert_alert(a: dict) -> int:
    cols = ["alert_uid", "first_seen", "last_seen", "count", "mode", "severity", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "service", "predicted_class", "confidence",
            "risk_score", "model_used", "explanation", "risk_factors", "status", "event_id"]
    vals = [a.get(c) for c in cols]
    vals[cols.index("explanation")] = json.dumps(a.get("explanation")) if a.get("explanation") else None
    vals[cols.index("risk_factors")] = json.dumps(a.get("risk_factors") or [])
    with transaction() as conn:
        cur = conn.execute(f"INSERT INTO alerts ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
        return cur.lastrowid


def bump_alert(alert_id: int, last_seen: float, risk_score: int, confidence: float, severity: str) -> None:
    with transaction() as conn:
        conn.execute(
            "UPDATE alerts SET count=count+1, last_seen=?, risk_score=MAX(risk_score, ?), "
            "confidence=MAX(confidence, ?), severity=CASE WHEN ? > risk_score THEN ? ELSE severity END "
            "WHERE id=?", (last_seen, risk_score, confidence, risk_score, severity, alert_id))


def _alert_row(r) -> dict:
    d = dict(r)
    d["explanation"] = json.loads(d["explanation"]) if d.get("explanation") else None
    d["risk_factors"] = json.loads(d["risk_factors"]) if d.get("risk_factors") else []
    return d


def query_alerts(filters: dict | None = None, limit: int = 200, offset: int = 0) -> list[dict]:
    f = dict(filters or {})
    f["_ts_col"] = "last_seen"
    w, args = _where(f)
    rows = get_conn().execute(
        f"SELECT * FROM alerts{w} ORDER BY last_seen DESC LIMIT ? OFFSET ?", args + [limit, offset]).fetchall()
    return [_alert_row(r) for r in rows]


def count_alerts(filters: dict | None = None) -> int:
    f = dict(filters or {})
    f["_ts_col"] = "last_seen"
    w, args = _where(f)
    return get_conn().execute(f"SELECT COUNT(*) FROM alerts{w}", args).fetchone()[0]


def get_alert(alert_id: int) -> dict | None:
    r = get_conn().execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    return _alert_row(r) if r else None


def update_alert_status(alert_id: int, status: str) -> dict | None:
    if status not in ALERT_STATUSES:
        raise ValueError(f"status must be one of {ALERT_STATUSES}")
    with transaction() as conn:
        conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
    return get_alert(alert_id)


def alert_severity_counts() -> dict:
    rows = get_conn().execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity").fetchall()
    return {r["severity"]: r["c"] for r in rows}


# ------------------------------------------------------------ model runs
def record_model_run(md: dict) -> None:
    test = (md.get("metrics") or {}).get("test", {})
    with transaction() as conn:
        conn.execute(
            "INSERT INTO model_runs (model_id, version, name, task, feature_set, dataset, trained_at, "
            "accuracy, f1, metrics_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (md["id"], md["version"], md.get("name"), md.get("task"), md.get("feature_set"),
             md.get("dataset"), md.get("trained_at"), test.get("accuracy"), test.get("f1"),
             json.dumps(md.get("metrics"))))


def list_model_runs(limit: int = 100) -> list[dict]:
    rows = get_conn().execute(
        "SELECT id, model_id, version, name, task, feature_set, dataset, trained_at, accuracy, f1 "
        "FROM model_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------- system events
def system_event(level: str, category: str, message: str) -> None:
    try:
        with transaction() as conn:
            conn.execute("INSERT INTO system_events (ts, level, category, message) VALUES (?,?,?,?)",
                         (time.time(), level, category, message))
    except Exception:
        pass  # never let audit logging break the caller


def list_system_events(limit: int = 100) -> list[dict]:
    rows = get_conn().execute("SELECT * FROM system_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def clear_runtime_data() -> None:
    with transaction() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM alerts")
