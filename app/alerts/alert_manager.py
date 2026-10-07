"""Alert creation with de-duplication and rate limiting.

* De-duplication: detections with the same (source, destination, class)
  inside ``ALERT_DEDUP_WINDOW`` seconds update one alert (count, last_seen,
  max risk) instead of creating new rows. In dataset simulation, where
  records carry no IPs, the key is (class, service, flag).
* Rate limiting: at most ``ALERT_RATE_LIMIT`` new alerts per second; the
  excess is counted as ``suppressed`` (never silently dropped from stats -
  the underlying events are still stored).
"""
from __future__ import annotations

import threading
import time
import uuid

from app.alerts.notifications import notify
from app.config import settings
from app.storage import repositories as repo
from app.utils.logging_setup import get_logger

log = get_logger("alerts")


class AlertManager:
    def __init__(self):
        self.dedup_window = settings.alert_dedup_window
        self.rate_limit = settings.alert_rate_limit_per_sec
        self.min_risk = settings.alert_min_risk
        self._open: dict[tuple, tuple[int, float]] = {}
        self._sec = 0
        self._sec_count = 0
        self.suppressed = 0
        self.created = 0
        self.deduplicated = 0
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._open.clear()
            self.suppressed = self.created = self.deduplicated = 0

    def _key(self, ev: dict) -> tuple:
        if ev.get("src_ip"):
            return ("ip", ev["src_ip"], ev.get("dst_ip"), ev["predicted_class"])
        return ("rec", ev["predicted_class"], ev.get("service"), ev.get("flag"))

    def process(self, ev: dict, explanation, factors: list[str]) -> dict | None:
        """Return the new alert dict, or None if no new alert was created.

        ``explanation`` may be a dict or a zero-argument callable; a callable is
        only invoked when a NEW alert is created (dedup/rate-limited detections
        never pay the attribution cost)."""
        if ev["verdict"] == "Normal" or ev["risk_score"] < self.min_risk:
            return None
        now = ev["ts"]
        key = self._key(ev)
        with self._lock:
            open_ = self._open.get(key)
            if open_ and now - open_[1] <= self.dedup_window:
                alert_id = open_[0]
                self._open[key] = (alert_id, now)
                self.deduplicated += 1
                repo.bump_alert(alert_id, now, ev["risk_score"], ev["confidence"], ev["risk_level"])
                return None
            sec = int(time.time())
            if sec != self._sec:
                self._sec, self._sec_count = sec, 0
            if self._sec_count >= self.rate_limit:
                self.suppressed += 1
                return None
            self._sec_count += 1
            if callable(explanation):
                explanation = explanation()
            alert = {
                "alert_uid": "ALR-" + uuid.uuid4().hex[:10].upper(),
                "first_seen": now, "last_seen": now, "count": 1,
                "mode": ev["mode"], "severity": ev["risk_level"],
                "src_ip": ev.get("src_ip"), "dst_ip": ev.get("dst_ip"),
                "src_port": ev.get("src_port"), "dst_port": ev.get("dst_port"),
                "protocol": ev.get("protocol"), "service": ev.get("service"),
                "predicted_class": ev["predicted_class"] if ev["verdict"] == "Attack" else f"Suspicious ({ev['predicted_class']})",
                "confidence": ev["confidence"], "risk_score": ev["risk_score"],
                "model_used": ev["engine"], "explanation": explanation,
                "risk_factors": factors, "status": "New", "event_id": ev.get("id"),
            }
            alert["id"] = repo.insert_alert(alert)
            self._open[key] = (alert["id"], now)
            self.created += 1
            # forget stale dedup keys
            if len(self._open) > 5000:
                cutoff = now - self.dedup_window
                self._open = {k: v for k, v in self._open.items() if v[1] >= cutoff}
        log.info(f"alert {alert['alert_uid']} severity={alert['severity']} class={alert['predicted_class']} "
                 f"src={alert['src_ip']} dst={alert['dst_ip']} risk={alert['risk_score']}")
        notify(alert)
        return alert

    def stats(self) -> dict:
        return {"created": self.created, "deduplicated": self.deduplicated,
                "suppressed": self.suppressed, "dedup_window_s": self.dedup_window,
                "rate_limit_per_s": self.rate_limit}
