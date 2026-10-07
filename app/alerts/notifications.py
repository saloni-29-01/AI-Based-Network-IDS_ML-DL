"""Alert notifications: always logged; CRITICAL alerts are additionally
POSTed as JSON to ``ALERT_WEBHOOK_URL`` when one is configured (e.g. a
Slack/Teams/Discord incoming webhook). No webhook is configured by default."""
from __future__ import annotations

import json
import threading
import urllib.request

from app.config import settings
from app.utils.logging_setup import get_logger

log = get_logger("notify")


def _post(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as exc:
        log.warning(f"webhook delivery failed: {exc}")


def notify(alert: dict) -> None:
    if alert.get("severity") == "CRITICAL" and settings.alert_webhook_url:
        payload = {"text": f"[IDS] CRITICAL {alert['predicted_class']} {alert.get('src_ip') or ''} -> "
                           f"{alert.get('dst_ip') or ''} risk={alert['risk_score']} ({alert['alert_uid']})"}
        threading.Thread(target=_post, args=(settings.alert_webhook_url, payload), daemon=True).start()
