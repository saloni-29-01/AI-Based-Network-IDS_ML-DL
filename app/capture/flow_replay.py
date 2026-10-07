"""Flow-record replay.

Replays pre-computed *flow-feature* records (the 28 packet-derivable
NSL-KDD features) one by one through the flow detection engine - the same
engine used by live capture and PCAP replay. Records are read from a JSONL
file built by ``scripts/build_flow_replay.py`` directly from the genuine
NSL-KDD benchmark, so the attack-category examples are real benchmark data,
not synthesized traffic.

This exists so the live/flow detection path can be demonstrated on
attack-shaped records without capturing or generating any network attack.
Each record keeps its NSL-KDD ground-truth category, so a running accuracy
can be shown exactly as in dataset simulation.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.capture.base import SourceBase
from app.features.schema import FLOW_FEATURES
from app.utils.logging_setup import get_logger

log = get_logger("flowreplay")


class FlowReplayError(RuntimeError):
    pass


class FlowReplaySource(SourceBase):
    mode = "flow_replay"
    label = "Flow Replay (NSL-KDD flow records)"

    def __init__(self, engine, path: Path, rate: float = 25.0, speed: float = 1.0,
                 limit: int | None = None):
        super().__init__(engine, speed)
        self.path = Path(path)
        self.rate = rate
        self.limit = limit
        if not self.path.is_file():
            raise FlowReplayError(f"flow replay file not found: {self.path} "
                                  f"(build it with: python scripts/build_flow_replay.py)")
        self.label = f"Flow Replay: {self.path.name}"

    def run(self) -> None:
        records = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        if self.limit:
            records = records[: self.limit]
        total = len(records)
        self.progress = {"file": self.path.name, "total_records": total, "processed": 0, "percent": 0.0}
        log.info(f"flow replay start file={self.path.name} records={total} rate={self.rate}/s x{self.speed}")
        group = max(1, int(self.rate * self.speed / 10))
        batch = []
        for i, rec in enumerate(records, 1):
            if self._stop.is_set():
                break
            feats = {c: rec[c] for c in FLOW_FEATURES}
            meta = {
                "src_ip": rec.get("src_ip"), "dst_ip": rec.get("dst_ip"),
                "src_port": rec.get("src_port"), "dst_port": rec.get("dst_port"),
                "protocol": rec.get("protocol_type"), "packets": rec.get("packets"),
                "record_ref": rec.get("record_ref"), "ground_truth": rec.get("ground_truth"),
                "raw_label": rec.get("raw_label"),
            }
            batch.append((feats, meta))
            if len(batch) >= group:
                for feats_, meta_ in batch:
                    self.engine.submit_record("flow_replay", "flow", feats_, meta_)
                batch.clear()
                if not self._wait(group / (self.rate * self.speed)):
                    break
            self.progress.update(processed=i, percent=round(100 * i / total, 2))
        for feats_, meta_ in batch:
            self.engine.submit_record("flow_replay", "flow", feats_, meta_)
        log.info(f"flow replay end processed={self.progress['processed']}")
