"""Application-level risk scoring.

IMPORTANT: this score is a transparent, rule-based *triage* number derived
from the model's output (class + confidence) and simple contextual signals.
It is NOT a calibrated probability of compromise. Every contributing factor
is returned so the analyst can see exactly why a score was given. Class
severities and thresholds are configurable via SEVERITY_MAP / .env.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from app.config import settings

LEVELS = [(80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW")]
SENSITIVE_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900}


def level_for(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "LOW"


class RiskEngine:
    def __init__(self, severity: dict[str, float] | None = None,
                 suspicious_threshold: float | None = None):
        self.severity = severity or settings.parsed_severity()
        self.suspicious_threshold = suspicious_threshold if suspicious_threshold is not None \
            else settings.suspicious_threshold
        self._recent_by_src: dict[str, deque] = defaultdict(deque)

    def verdict(self, predicted_class: str, attack_probability: float) -> str:
        if predicted_class != "normal" and attack_probability >= 0.5:
            return "Attack"
        if attack_probability >= self.suspicious_threshold:
            return "Suspicious"
        return "Normal"

    def score(self, result: dict, meta: dict, now: float | None = None) -> dict:
        now = now or time.time()
        cls = result["predicted_class"]
        conf = result["confidence"]
        p_att = result["attack_probability"]
        verdict = self.verdict(cls, p_att)
        factors: list[str] = []
        if verdict == "Attack":
            base = self.severity.get(cls, 60)
            score = base * (0.6 + 0.4 * conf)
            factors.append(f"{cls} severity {base:.0f} x confidence {conf:.2f}")
        elif verdict == "Suspicious":
            thr = self.suspicious_threshold
            span = max(1e-6, 0.5 - thr) if p_att < 0.5 else 1.0
            score = 30 + min(29.0, 29.0 * (p_att - thr) / span)
            likely = max((c for c in result["probabilities"] if c != "normal"),
                         key=lambda c: result["probabilities"][c])
            factors.append(f"attack probability {p_att:.2f} >= suspicious threshold {thr:.2f} (most likely {likely})")
        else:
            score = 30 * p_att
        if verdict != "Normal":
            src = meta.get("src_ip")
            if src:
                dq = self._recent_by_src[src]
                dq.append(now)
                while dq and now - dq[0] > 60:
                    dq.popleft()
                if len(dq) >= 20:
                    score += 15
                    factors.append(f"repeated: {len(dq)} flagged flows from {src} in 60 s")
                elif len(dq) >= 5:
                    score += 10
                    factors.append(f"repeated: {len(dq)} flagged flows from {src} in 60 s")
            port = meta.get("dst_port")
            if port in SENSITIVE_PORTS:
                score += 5
                factors.append(f"sensitive destination port {port}")
            cnt = (meta.get("features") or {}).get("count", 0) or 0
            if cnt >= 100:
                score += 5
                factors.append(f"high connection frequency ({cnt} conns to host in 2 s)")
        if verdict == "Suspicious":
            # an uncertain verdict should never outrank a confident detection:
            # context bonuses may raise it, but only up to the top of MEDIUM
            score = min(score, 59)
        score_i = int(max(0, min(100, round(score))))
        return {"verdict": verdict, "risk_score": score_i, "risk_level": level_for(score_i),
                "risk_factors": factors}
