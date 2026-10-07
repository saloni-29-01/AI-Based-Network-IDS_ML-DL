import time

from app.alerts.alert_manager import AlertManager
from app.detection.risk_engine import RiskEngine, level_for
from app.storage import repositories as repo
from app.storage.database import db_health, init_db

PROBS_DOS = {"normal": 0.02, "DoS": 0.95, "Probe": 0.02, "R2L": 0.005, "U2R": 0.005}


def _res(cls, conf, p_att, probs=None):
    return {"predicted_class": cls, "confidence": conf, "attack_probability": p_att,
            "probabilities": probs or PROBS_DOS}


def test_levels():
    assert level_for(0) == "LOW" and level_for(29) == "LOW"
    assert level_for(30) == "MEDIUM" and level_for(60) == "HIGH" and level_for(80) == "CRITICAL"


def test_verdicts_and_scores():
    r = RiskEngine(severity={"normal": 0, "DoS": 70, "Probe": 50, "R2L": 85, "U2R": 95},
                   suspicious_threshold=0.35)
    att = r.score(_res("DoS", 0.95, 0.98), {})
    assert att["verdict"] == "Attack" and att["risk_level"] == "HIGH"
    normal = r.score(_res("normal", 0.9, 0.1), {})
    assert normal["verdict"] == "Normal" and normal["risk_level"] == "LOW"
    susp = r.score(_res("normal", 0.55, 0.45,
                        {"normal": .55, "DoS": .3, "Probe": .1, "R2L": .03, "U2R": .02}), {})
    assert susp["verdict"] == "Suspicious" and susp["risk_level"] == "MEDIUM"
    u2r = r.score(_res("U2R", 0.99, 0.99), {})
    assert u2r["risk_level"] == "CRITICAL"


def test_risk_factors_are_explained_and_bounded():
    r = RiskEngine(severity={"DoS": 70}, suspicious_threshold=0.35)
    out = None
    for _ in range(25):
        out = r.score(_res("DoS", 1.0, 1.0), {"src_ip": "1.2.3.4", "dst_port": 22,
                                                "features": {"count": 300}})
    assert out["risk_score"] <= 100
    joined = " ".join(out["risk_factors"])
    assert "repeated" in joined and "sensitive destination port 22" in joined and "frequency" in joined


def _event(i, src="10.9.9.9", ts=None):
    return {"ts": ts or time.time(), "mode": "pcap", "src_ip": src, "dst_ip": "10.0.0.1",
            "src_port": 1000 + i, "dst_port": 80, "protocol": "tcp", "service": "http", "flag": "S0",
            "predicted_class": "DoS", "verdict": "Attack", "confidence": 0.9,
            "attack_probability": 0.95, "risk_score": 70, "risk_level": "HIGH",
            "engine": "test-engine", "ground_truth": None, "record_ref": None}


def test_database_roundtrip():
    init_db()
    ids = repo.insert_events([_event(1), _event(2, src="10.8.8.8")])
    assert len(ids) == 2
    assert repo.get_event(ids[0])["src_ip"] == "10.9.9.9"
    assert repo.count_events({"src_ip": "10.8.8"}) >= 1
    assert db_health()["ok"]


def test_alert_dedup_status_and_rate_limit():
    init_db()
    am = AlertManager()
    am.rate_limit = 1000
    calls = []
    first = am.process(_event(1, src="172.16.0.5"), lambda: calls.append(1) or {"x": 1}, ["f"])
    assert first and first["status"] == "New" and calls == [1]
    # same (src, dst, class) inside the window -> merged, explanation NOT recomputed
    assert am.process(_event(2, src="172.16.0.5"), lambda: calls.append(2), ["f"]) is None
    assert calls == [1]
    stored = repo.get_alert(first["id"])
    assert stored["count"] == 2 and am.deduplicated == 1
    upd = repo.update_alert_status(first["id"], "Investigating")
    assert upd["status"] == "Investigating"
    # normal / low-risk events never alert
    low = dict(_event(3, src="172.16.0.6"), verdict="Normal", risk_score=5, risk_level="LOW")
    assert am.process(low, None, []) is None
    # rate limit
    am2 = AlertManager()
    am2.rate_limit = 2
    made = [am2.process(_event(i, src=f"192.0.2.{i}"), None, []) for i in range(6)]
    assert sum(a is not None for a in made) == 2 and am2.suppressed == 4


def test_suspicious_never_exceeds_medium():
    r = RiskEngine(severity={"DoS": 70, "Probe": 50}, suspicious_threshold=0.35)
    probs = {"normal": .52, "DoS": .3, "Probe": .1, "R2L": .05, "U2R": .03}
    out = None
    for _ in range(30):   # repeated source + sensitive port + high count bonuses
        out = r.score(_res("normal", 0.52, 0.48, probs),
                      {"src_ip": "10.0.12.163", "dst_port": 22, "features": {"count": 300}})
    assert out["verdict"] == "Suspicious"
    assert out["risk_score"] <= 59 and out["risk_level"] == "MEDIUM"
