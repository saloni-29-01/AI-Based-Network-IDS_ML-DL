"""API + GUI smoke tests (in-process FastAPI TestClient)."""
import time

import pytest
from fastapi.testclient import TestClient

from tests.conftest import models_trained


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_status_and_stats(client):
    s = client.get("/api/status").json()
    assert "engine" in s and "stats" in s
    assert s["engine"]["banner"]
    assert "packets" in client.get("/api/stats").json()


def test_gui_index_and_assets(client):
    html = client.get("/").text
    for view in ("dashboard", "live", "threats", "analytics", "models", "gan", "alerts", "system"):
        assert f'id="view-{view}"' in html
    assert client.get("/static/js/app.js").status_code == 200
    assert client.get("/static/js/charts.js").status_code == 200
    assert client.get("/static/css/app.css").status_code == 200
    assert client.get("/favicon.svg").status_code == 200


def test_capability_reports_without_crashing(client):
    cap = client.get("/api/capture/capability").json()
    assert "available" in cap


def test_predict_validation_errors(client):
    assert client.post("/api/predict", json={"records": []}).status_code == 400
    assert client.post("/api/predict", json={"records": [{}], "feature_set": "bogus"}).status_code == 422


@pytest.mark.skipif(not models_trained(), reason="models not trained")
def test_predict(client, full_record):
    r = client.post("/api/predict", json={"records": [full_record], "feature_set": "full"})
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["ok"] and res["predicted_class"] in ("normal", "DoS", "Probe", "R2L", "U2R")
    bad = client.post("/api/predict", json={"records": [{"duration": 1}], "feature_set": "full"}).json()
    assert bad["results"][0]["ok"] is False


@pytest.mark.skipif(not models_trained(), reason="models not trained")
def test_start_stop_dataset_and_alerts(client):
    client.post("/api/reset")
    r = client.post("/api/capture/dataset/start", json={"rate": 3000, "limit": 300})
    assert r.status_code == 200 and r.json()["mode"] == "dataset"
    t = time.time()
    while client.get("/api/stats").json()["events"] < 300 and time.time() - t < 40:
        time.sleep(0.3)
    stats = client.get("/api/stats").json()
    assert stats["events"] == 300 and stats["simulation"]["total"] == 300
    alerts = client.get("/api/alerts").json()
    assert alerts["total"] > 0
    aid = alerts["alerts"][0]["id"]
    assert client.get(f"/api/alerts/{aid}").status_code == 200
    assert client.post(f"/api/alerts/{aid}/status", json={"status": "Resolved"}).json()["status"] == "Resolved"
    assert client.post(f"/api/alerts/{aid}/status", json={"status": "Bogus"}).status_code == 422
    assert client.get("/api/alerts/999999").status_code == 404
    assert client.post("/api/source/stop").json()["stopped"]


def test_replay_missing_file_is_400(client):
    r = client.post("/api/replay/start", json={"file": "nope.pcap"})
    assert r.status_code == 400 and "not found" in r.json()["detail"]


def test_exports(client):
    r = client.get("/api/export/alerts.csv")
    assert r.status_code == 200 and r.text.startswith("alert_uid")
    assert client.get("/api/export/events.csv").status_code == 200
    rep = client.get("/api/export/report.html")
    assert rep.status_code == 200 and "Limitations" in rep.text


def test_models_drift_gan_system(client):
    assert client.get("/api/models").status_code == 200
    assert "engines" in client.get("/api/drift").json()
    assert "status" in client.get("/api/gan/status").json()
    sysd = client.get("/api/system").json()
    assert sysd["health"]["database"]["ok"]


def test_websocket_live(client):
    with client.websocket_connect("/ws/live") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        upd = ws.receive_json()
        assert upd["type"] == "update" and "stats" in upd
