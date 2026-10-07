"""IDS engine: wires sources -> flows -> features -> detection -> risk ->
alerts -> storage -> live update buffer.

Threads:
  * source thread (live sniffer / PCAP replay / dataset simulation) produces
    packets or records;
  * one detection worker consumes a bounded queue in micro-batches so the
    models run on batches (not one call per packet) and the capture thread is
    never blocked by inference;
  * the FastAPI event loop pulls ``drain_updates()`` every second for the
    WebSocket broadcast.
"""
from __future__ import annotations

import queue
import threading
import time
from collections import deque
from pathlib import Path

from app.alerts.alert_manager import AlertManager
from app.capture.base import SourceBase
from app.capture.flow_tracker import Flow, FlowTracker
from app.capture.packet import PacketInfo
from app.config import settings
from app.detection.detector import Detector
from app.detection.risk_engine import RiskEngine
from app.features.flow_features import (TrafficFeatureExtractor, flow_metadata,
                                         is_broadcast_or_multicast)
from app.models.model_registry import load_metadata, model_id
from app.monitoring.drift import DriftMonitor
from app.monitoring.metrics import LiveStats
from app.storage import repositories as repo
from app.utils.logging_setup import get_logger

log = get_logger("engine")

MODE_BANNERS = {
    "idle": "IDLE - no traffic source running",
    "dataset": "DATASET SIMULATION ACTIVE",
    "pcap": "PCAP REPLAY ACTIVE",
    "live": "LIVE NETWORK MONITORING ACTIVE",
    "flow_replay": "FLOW REPLAY ACTIVE (NSL-KDD flow records)",
}


class IDSEngine:
    def __init__(self):
        self.detector = Detector()
        self.risk = RiskEngine()
        self.alerts = AlertManager()
        self.stats = LiveStats()
        self.drift = DriftMonitor()
        self.source: SourceBase | None = None
        self.mode = "idle"
        self.queue: queue.Queue = queue.Queue(maxsize=20_000)
        self._updates_lock = threading.Lock()
        self._new_events: deque = deque(maxlen=200)
        self._new_alerts: deque = deque(maxlen=100)
        self.recent_events: deque = deque(maxlen=300)
        self._worker: threading.Thread | None = None
        self._running = False
        self.on_finished_hooks: list = []
        self._new_tracker()

    # ------------------------------------------------------------ lifecycle
    def start_worker(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._running = True
        self._worker = threading.Thread(target=self._work_loop, name="detection-worker", daemon=True)
        self._worker.start()
        log.info("detection worker started")

    def shutdown(self) -> None:
        self.stop_source()
        self._running = False
        if self._worker:
            self._worker.join(timeout=3)

    def _new_tracker(self) -> None:
        self.extractor = TrafficFeatureExtractor()
        self.tracker = FlowTracker(on_flow_start=self.extractor.register_start,
                                   on_flow_end=self._on_flow_end,
                                   idle_timeout=settings.flow_idle_timeout,
                                   active_timeout=settings.flow_active_timeout,
                                   tcp_close_grace=settings.flow_tcp_close_grace)

    def warm_up(self) -> dict:
        """Load both engines once at startup (models stay in memory)."""
        out = {}
        for fs in ("full", "flow"):
            ens = self.detector.load(fs)
            out[fs] = ens.name if ens else None
            md = load_metadata(model_id(fs, "multiclass", "ensemble")) or \
                load_metadata(model_id(fs, "multiclass", "rf"))
            self.drift.set_reference(fs, md)
        return out

    # ---------------------------------------------------------- sources
    def start_source(self, source: SourceBase, reset: bool = True) -> None:
        self.stop_source()
        if reset:
            self.reset_runtime(clear_db=False)
        self._new_tracker()
        self.source = source
        self.mode = source.mode
        self.start_worker()
        source.start()
        repo.system_event("INFO", "source", f"started {source.label}")
        log.info(f"source started mode={source.mode} label={source.label}")

    def stop_source(self) -> None:
        src = self.source
        if src is not None and src.state in ("running", "paused"):
            src.stop()
            src.join(timeout=5)
            repo.system_event("INFO", "source", f"stopped {src.label}")
        self.mode = "idle" if src is None or src.state != "running" else self.mode

    def on_source_finished(self, src: SourceBase) -> None:
        if src is self.source:
            self.mode = "idle"
            level = "ERROR" if src.state == "error" else "INFO"
            repo.system_event(level, "source", f"{src.label} {src.state}" + (f": {src.error}" if src.error else ""))
            for hook in list(self.on_finished_hooks):
                try:
                    hook(src)
                except Exception as exc:
                    log.warning(f"finish hook failed: {exc}")

    def reset_runtime(self, clear_db: bool = False) -> None:
        self.stats.reset()
        self.alerts.reset()
        self.drift.reset()
        self.recent_events.clear()
        with self._updates_lock:
            self._new_events.clear()
            self._new_alerts.clear()
        if clear_db:
            repo.clear_runtime_data()

    # ----------------------------------------------------- packet ingest
    def ingest_packet(self, p: PacketInfo) -> None:
        sample = {"ts": p.ts, "src": p.src, "dst": p.dst, "proto": p.proto, "sport": p.sport,
                  "dport": p.dport, "len": p.length, "flags": p.tcp_flags}
        self.stats.add_packet(p.proto, p.length, sample)
        self.tracker.process(p)
        if p.proto not in ("tcp", "udp", "icmp"):
            self.stats.unsupported_packets += 1

    def tick(self, now: float) -> None:
        self.tracker.expire(now)

    def flush_flows(self) -> None:
        self.tracker.flush()

    def _on_flow_end(self, flow: Flow) -> None:
        self.stats.add_flow()
        if settings.skip_broadcast and is_broadcast_or_multicast(flow.dst):
            # counted and shown on the dashboard, but not scored (out of the
            # NSL-KDD domain -> would be mislabelled as Probe)
            self.stats.add_skipped_broadcast()
            return
        features = self.extractor.extract(flow)
        meta = flow_metadata(flow)
        self.submit_record(self.mode if self.mode in ("pcap", "live") else "pcap", "flow", features, meta)

    def submit_record(self, mode: str, feature_set: str, features: dict, meta: dict) -> None:
        try:
            self.queue.put_nowait((time.perf_counter(), mode, feature_set, features, meta))
        except queue.Full:
            self.stats.dropped += 1   # surfaced in the UI; never silently ignored

    # ---------------------------------------------------- detection loop
    def _work_loop(self) -> None:
        while self._running:
            try:
                first = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            batch = [first]
            deadline = time.perf_counter() + 0.05
            while len(batch) < 256 and time.perf_counter() < deadline:
                try:
                    batch.append(self.queue.get_nowait())
                except queue.Empty:
                    time.sleep(0.005)
            try:
                self._process_batch(batch)
            except Exception as exc:
                log.exception(f"detection batch failed: {exc}")
                repo.system_event("ERROR", "detection", str(exc))

    def process_now(self, items: list[tuple]) -> list[dict]:
        """Synchronous processing (used by tests and /api/predict-style calls)."""
        return self._process_batch([(time.perf_counter(), *it) for it in items])

    def _process_batch(self, batch: list[tuple]) -> list[dict]:
        by_fs: dict[str, list] = {}
        for item in batch:
            by_fs.setdefault(item[2], []).append(item)
        produced = []
        for fs, items in by_fs.items():
            results = self.detector.detect([it[3] for it in items], fs, explain_attacks=False)
            events = []
            for (t_in, mode, _fs, feats, meta), res in zip(items, results):
                if not res.get("ok"):
                    self.stats.invalid += 1
                    log.warning(f"record rejected: {res.get('error')}")
                    continue
                now = time.time()
                rs = self.risk.score(res, {**meta, "features": feats}, now)
                ev = {
                    "ts": now, "mode": mode,
                    "src_ip": meta.get("src_ip"), "dst_ip": meta.get("dst_ip"),
                    "src_port": meta.get("src_port"), "dst_port": meta.get("dst_port"),
                    "protocol": meta.get("protocol") or feats.get("protocol_type"),
                    "service": feats.get("service"), "flag": feats.get("flag"),
                    "duration": feats.get("duration"), "src_bytes": feats.get("src_bytes"),
                    "dst_bytes": feats.get("dst_bytes"), "packets": meta.get("packets"),
                    "predicted_class": res["predicted_class"], "verdict": rs["verdict"],
                    "confidence": round(res["confidence"], 4),
                    "attack_probability": round(res["attack_probability"], 4),
                    "risk_score": rs["risk_score"], "risk_level": rs["risk_level"],
                    "engine": res["engine"], "ground_truth": meta.get("ground_truth"),
                    "record_ref": meta.get("record_ref"),
                }
                ev["_extra"] = {"probabilities": res["probabilities"], "members": res["members"],
                                "explanation": res.get("explanation"), "explain_fn": res.get("explain_fn"),
                                "factors": rs["risk_factors"],
                                "features": feats, "warnings": res.get("warnings", []),
                                "raw_label": meta.get("raw_label")}
                events.append(ev)
                self.stats.add_latency((time.perf_counter() - t_in) * 1000)
                pre_services = res.get("warnings") or []
                self.drift.observe(fs, res["predicted_class"], res["confidence"],
                                   unseen=any("unseen" in w for w in pre_services),
                                   out_of_range=self._out_of_range(fs, feats))
            if not events:
                continue
            ids = repo.insert_events([{k: v for k, v in e.items() if k != "_extra"} for e in events])
            for ev, eid in zip(events, ids):
                ev["id"] = eid
                # record-based modes have no packets, so count protocol per record
                self.stats.add_event(ev, count_protocol=ev["mode"] in ("dataset", "flow_replay"))
                extra = ev.pop("_extra")
                alert = self.alerts.process(ev, extra["explain_fn"] or extra["explanation"], extra["factors"])
                expl = alert["explanation"] if alert else extra["explanation"]
                ev_view = {**ev, "explanation": expl,
                           **{k: extra[k] for k in ("probabilities", "factors", "raw_label")}}
                self.recent_events.append({**ev_view, "features": extra["features"]})
                with self._updates_lock:
                    self._new_events.append(ev_view)
                    if alert:
                        self._new_alerts.append(alert)
                produced.append({**ev_view, "alert": alert})
        return produced

    def _out_of_range(self, fs: str, feats: dict) -> bool:
        ens = self.detector.load(fs)
        if not ens:
            return False
        mx = ens.members[0][0].preprocessor.numeric_max
        return any(isinstance(v, (int, float)) and k in mx and v > mx[k] for k, v in feats.items())

    # ------------------------------------------------------- live views
    def drain_updates(self) -> tuple[list, list]:
        with self._updates_lock:
            ev, al = list(self._new_events), list(self._new_alerts)
            self._new_events.clear()
            self._new_alerts.clear()
        return ev, al

    def status(self) -> dict:
        src = self.source.info() if self.source else None
        return {
            "mode": self.mode,
            "banner": MODE_BANNERS.get(self.mode, self.mode),
            "source": src,
            "engine": self.engine_label(),
            "queue_depth": self.queue.qsize(),
            "active_flows": self.tracker.active_count,
            "detector": self.detector.status(),
            "alerts": self.alerts.stats(),
        }

    def engine_label(self) -> str | None:
        fs = "full" if self.mode == "dataset" else "flow" if self.mode in ("pcap", "live", "flow_replay") else None
        if fs is None:
            return None
        ens = self.detector.load(fs)
        from app.detection.detector import ENGINE_LABELS
        return f"{ENGINE_LABELS[fs]} | {ens.name}" if ens else f"{ENGINE_LABELS[fs]} | NOT AVAILABLE"


_engine: IDSEngine | None = None


def get_engine() -> IDSEngine:
    global _engine
    if _engine is None:
        _engine = IDSEngine()
    return _engine


def default_demo_pcap() -> Path:
    return settings.pcap_dir / "demo_benign_traffic.pcap"
