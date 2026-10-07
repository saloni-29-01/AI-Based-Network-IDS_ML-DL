"""REST API routes."""
from __future__ import annotations

import csv
import io
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.api.schemas import (AlertStatusRequest, CaptureStartRequest, FlowReplayStartRequest,
                             GanTrainRequest, PredictRequest, ReplayStartRequest, SimStartRequest,
                             SpeedRequest)
from app.config import APP_VERSION, settings
from app.core.engine import default_demo_pcap, get_engine
from app.gan.augment import current_job as gan_job
from app.gan.augment import last_report as gan_report
from app.gan.augment import start_gan_job
from app.gan.tabular_wgan import gan_available
from app.models.model_registry import list_models, load_metadata
from app.monitoring.health import system_health
from app.storage import repositories as repo
from app.utils.logging_setup import recent_logs

router = APIRouter(prefix="/api")


def engine():
    return get_engine()


@router.get("/health")
def health():
    tf_ok, tf_info = gan_available()
    return {"status": "ok", "version": APP_VERSION, "time": time.time(),
            "tensorflow": {"available": tf_ok, "info": tf_info},
            "system": system_health()}


@router.get("/status")
def status():
    e = engine()
    return {"engine": e.status(), "stats": e.stats.snapshot(),
            "modes": ["dataset", "pcap", "flow_replay", "live"]}


@router.get("/stats")
def stats():
    return engine().stats.snapshot()


@router.get("/series")
def series(seconds: int = Query(120, ge=10, le=300)):
    return {"series": engine().stats.series(seconds)}


@router.get("/events")
def events(limit: int = Query(100, le=1000), offset: int = 0, verdict: str | None = None,
           predicted_class: str | None = None, protocol: str | None = None,
           src_ip: str | None = None, dst_ip: str | None = None, q: str | None = None):
    f = {k: v for k, v in dict(verdict=verdict, predicted_class=predicted_class, protocol=protocol,
                               src_ip=src_ip, dst_ip=dst_ip, q=q).items() if v}
    return {"total": repo.count_events(f), "events": repo.query_events(f, limit, offset)}


@router.get("/events/recent")
def recent_events(limit: int = Query(50, le=300)):
    e = engine()
    return {"events": list(e.recent_events)[-limit:][::-1]}


@router.get("/packets/recent")
def recent_packets(limit: int = Query(60, le=60)):
    """Latest packets seen by live capture / PCAP replay (empty in record-based modes)."""
    e = engine()
    with e.stats.lock:
        pk = list(e.stats.recent_packets)[-limit:][::-1]
    return {"packets": pk}


@router.get("/alerts")
def alerts(limit: int = Query(100, le=1000), offset: int = 0, severity: str | None = None,
           status: str | None = None, predicted_class: str | None = None,
           src_ip: str | None = None, q: str | None = None):
    f = {k: v for k, v in dict(severity=severity, status=status, predicted_class=predicted_class,
                               src_ip=src_ip, q=q).items() if v}
    return {"total": repo.count_alerts(f), "severity_counts": repo.alert_severity_counts(),
            "alerts": repo.query_alerts(f, limit, offset)}


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: int):
    a = repo.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    return a


@router.post("/alerts/{alert_id}/status")
def set_alert_status(alert_id: int, body: AlertStatusRequest):
    a = repo.update_alert_status(alert_id, body.status)
    if not a:
        raise HTTPException(404, "alert not found")
    return a


@router.get("/threats")
def threats():
    s = engine().stats.snapshot()
    return {"levels": s["levels"], "classes": s["classes"],
            "attack_src": s["attack_src"], "services_attacked": s["services_attacked"],
            "severity_counts": repo.alert_severity_counts()}


@router.get("/models")
def models():
    return {"models": list_models(), "runs": repo.list_model_runs(50)}


@router.get("/models/{model_id}")
def model_detail(model_id: str):
    md = load_metadata(model_id)
    if not md:
        raise HTTPException(404, "model not found")
    return md


@router.get("/metrics")
def metrics():
    out = {}
    for md in list_models():
        out[md["id"]] = {"name": md["name"], "task": md["task"], "feature_set": md["feature_set"],
                         "test": md["metrics"]["test"], "trained_at": md.get("trained_at")}
    return {"metrics": out}


@router.get("/drift")
def drift():
    return engine().drift.report()


@router.post("/predict")
def predict(body: PredictRequest):
    if not body.records:
        raise HTTPException(400, "no records supplied")
    results = engine().detector.detect(body.records, body.feature_set, body.explain)
    return {"feature_set": body.feature_set, "count": len(results), "results": results}


# ------------------------------------------------------------ source control
@router.post("/capture/dataset/start")
def start_dataset(body: SimStartRequest):
    from app.capture.dataset_sim import DatasetSimulationSource
    e = engine()
    try:
        src = DatasetSimulationSource(e, rate=body.rate, speed=body.speed, split=body.split,
                                      shuffle=body.shuffle, limit=body.limit)
    except Exception as exc:
        raise HTTPException(400, str(exc))
    e.start_source(src)
    return {"started": True, "mode": "dataset", "source": src.info()}


@router.post("/replay/start")
def start_replay(body: ReplayStartRequest):
    from app.capture.pcap_reader import PcapError, PcapReplaySource
    e = engine()
    path = Path(body.file) if body.file and Path(body.file).is_absolute() else \
        settings.pcap_dir / (body.file or default_demo_pcap().name)
    try:
        src = PcapReplaySource(e, path, speed=body.speed, max_gap=body.max_gap)
    except PcapError as exc:
        raise HTTPException(400, str(exc))
    e.start_source(src)
    return {"started": True, "mode": "pcap", "source": src.info()}


@router.post("/flow-replay/start")
def start_flow_replay(body: FlowReplayStartRequest):
    from app.capture.flow_replay import FlowReplayError, FlowReplaySource
    e = engine()
    path = Path(body.file) if body.file and Path(body.file).is_absolute() else \
        settings.data_dir / (body.file or "flow_replay_nslkdd.jsonl")
    try:
        src = FlowReplaySource(e, path, rate=body.rate, speed=body.speed, limit=body.limit)
    except FlowReplayError as exc:
        raise HTTPException(400, str(exc))
    e.start_source(src)
    return {"started": True, "mode": "flow_replay", "source": src.info()}


@router.post("/capture/start")
def start_capture(body: CaptureStartRequest):
    from app.capture.packet_capture import CaptureUnavailable, LiveCaptureSource
    e = engine()
    try:
        src = LiveCaptureSource(e, interface=body.interface or settings.capture_interface or None,
                                bpf_filter=body.bpf_filter)
    except CaptureUnavailable as exc:
        raise HTTPException(400, {"error": str(exc), "capability": capture_capability_dict()})
    e.start_source(src)
    return {"started": True, "mode": "live", "source": src.info()}


@router.get("/capture/capability")
def capture_capability_route():
    return capture_capability_dict()


def capture_capability_dict():
    from app.capture.packet_capture import capture_capability, list_interfaces
    cap = capture_capability()
    cap["interfaces"] = list_interfaces() if cap["available"] else []
    return cap


@router.post("/source/stop")
def stop_source():
    engine().stop_source()
    return {"stopped": True, "mode": engine().mode}


@router.post("/source/pause")
def pause_source():
    e = engine()
    if e.source:
        e.source.pause()
    return {"mode": e.mode, "source": e.source.info() if e.source else None}


@router.post("/source/resume")
def resume_source():
    e = engine()
    if e.source:
        e.source.resume()
    return {"mode": e.mode, "source": e.source.info() if e.source else None}


@router.post("/source/speed")
def set_speed(body: SpeedRequest):
    e = engine()
    if not e.source:
        raise HTTPException(400, "no active source")
    e.source.set_speed(body.speed)
    return {"source": e.source.info()}


@router.post("/demo/start")
def start_demo():
    """One-click demo: dataset simulation on a shuffled slice of KDDTest+."""
    from app.capture.dataset_sim import DatasetSimulationSource
    e = engine()
    e.warm_up()
    src = DatasetSimulationSource(e, rate=settings.simulation_rate, speed=2.0, split="test", limit=1500)
    e.start_source(src)
    return {"started": True, "mode": "dataset", "banner": e.status()["banner"], "source": src.info()}


@router.get("/pcaps")
def list_pcaps():
    files = sorted(p.name for p in settings.pcap_dir.glob("*.pcap")) if settings.pcap_dir.exists() else []
    return {"pcaps": files, "default": default_demo_pcap().name}


# ------------------------------------------------------------------- GAN
@router.get("/gan/status")
def gan_status():
    j = gan_job()
    ok, info = gan_available()
    return {"available": ok, "info": info, "status": j.status, "message": j.message,
            "error": j.error, "progress": j.progress[-20:], "report": gan_report()}


@router.post("/gan/train")
def gan_train(body: GanTrainRequest):
    ok, info = gan_available()
    if not ok:
        raise HTTPException(400, f"TensorFlow unavailable: {info}")
    j = start_gan_job(body.classes, body.per_class, body.epochs, body.retrain)
    return {"started": j.status == "running", "status": j.status, "error": j.error}


@router.get("/gan/report")
def gan_report_route():
    r = gan_report()
    if not r:
        raise HTTPException(404, "no GAN report yet - run GAN training first")
    return r


# --------------------------------------------------------------- system
@router.get("/system")
def system():
    e = engine()
    from app.capture.packet_capture import capture_capability
    return {"health": system_health(), "engine": e.status(), "capture": capture_capability(),
            "detector": e.detector.status(), "logs": recent_logs(80)}


@router.get("/logs")
def logs(limit: int = Query(100, le=500)):
    return {"logs": recent_logs(limit)}


@router.post("/reset")
def reset(clear_db: bool = False):
    engine().reset_runtime(clear_db=clear_db)
    return {"reset": True, "cleared_db": clear_db}


# ------------------------------------------------------------- exports
def _csv_response(rows: list[dict], cols: list[str], filename: str) -> StreamingResponse:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})


@router.get("/export/alerts.csv")
def export_alerts():
    rows = repo.query_alerts({}, limit=100000)
    cols = ["alert_uid", "first_seen", "last_seen", "count", "severity", "status", "predicted_class",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "service", "confidence",
            "risk_score", "model_used"]
    return _csv_response(rows, cols, "alerts.csv")


@router.get("/export/events.csv")
def export_events():
    rows = repo.query_events({}, limit=100000)
    from app.storage.repositories import EVENT_COLS
    return _csv_response(rows, EVENT_COLS, "events.csv")


@router.get("/export/report.html", response_class=None)
def export_report():
    from app.reporting.report import build_html_report
    html = build_html_report()
    return StreamingResponse(iter([html]), media_type="text/html",
                             headers={"Content-Disposition": "attachment; filename=ids_report.html"})
