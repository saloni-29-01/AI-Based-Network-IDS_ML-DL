"""In-memory live statistics (the real-time source of truth for the
dashboard; the database is used for history, filtering and export).

Every counter here is incremented by real processing code - packets by the
capture/replay source, events by the detection worker. Nothing is synthesised.
"""
from __future__ import annotations

import threading
import time
from collections import Counter, deque

HISTORY_SECONDS = 300


class LiveStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "lock", threading.Lock()):
            self.started_at = time.time()
            self.packets = 0
            self.bytes = 0
            self.flows = 0
            self.events = 0
            self.attacks = 0
            self.suspicious = 0
            self.invalid = 0
            self.dropped = 0
            self.broadcast_skipped = 0
            self.unsupported_packets = 0
            self.protocols: Counter = Counter()
            self.classes: Counter = Counter()
            self.levels: Counter = Counter()
            self.services_attacked: Counter = Counter()
            self.top_src: Counter = Counter()
            self.top_dst: Counter = Counter()
            self.attack_src: Counter = Counter()
            self.sim_correct = 0
            self.sim_total = 0
            self.sim_confusion: Counter = Counter()
            self.latency_ms: deque = deque(maxlen=500)
            self._series: dict[int, dict] = {}
            self.recent_packets: deque = deque(maxlen=60)

    def _bucket(self, now: float | None = None) -> dict:
        sec = int(now or time.time())
        b = self._series.get(sec)
        if b is None:
            b = self._series[sec] = {"t": sec, "packets": 0, "bytes": 0, "flows": 0,
                                     "events": 0, "attacks": 0, "suspicious": 0}
            cutoff = sec - HISTORY_SECONDS
            for k in [k for k in self._series if k < cutoff]:
                del self._series[k]
        return b

    # -------- updates
    def add_packet(self, proto: str, length: int, sample: dict | None = None) -> None:
        with self.lock:
            self.packets += 1
            self.bytes += length
            self.protocols[proto.split(":")[0].upper()] += 1
            b = self._bucket()
            b["packets"] += 1
            b["bytes"] += length
            if sample is not None:
                self.recent_packets.append(sample)

    def add_flow(self) -> None:
        with self.lock:
            self.flows += 1
            self._bucket()["flows"] += 1

    def add_event(self, ev: dict, count_protocol: bool) -> None:
        with self.lock:
            self.events += 1
            b = self._bucket()
            b["events"] += 1
            if count_protocol and ev.get("protocol"):
                self.protocols[ev["protocol"].upper()] += 1
            self.classes[ev["predicted_class"]] += 1
            self.levels[ev["risk_level"]] += 1
            if ev.get("src_ip"):
                self.top_src[ev["src_ip"]] += 1
            if ev.get("dst_ip"):
                self.top_dst[ev["dst_ip"]] += 1
            if ev["verdict"] == "Attack":
                self.attacks += 1
                b["attacks"] += 1
                if ev.get("service"):
                    self.services_attacked[ev["service"]] += 1
                if ev.get("src_ip"):
                    self.attack_src[ev["src_ip"]] += 1
            elif ev["verdict"] == "Suspicious":
                self.suspicious += 1
                b["suspicious"] += 1
            gt = ev.get("ground_truth")
            if gt:
                self.sim_total += 1
                self.sim_correct += int(gt == ev["predicted_class"])
                self.sim_confusion[(gt, ev["predicted_class"])] += 1

    def add_skipped_broadcast(self) -> None:
        with self.lock:
            self.broadcast_skipped += 1

    def add_latency(self, ms: float) -> None:
        with self.lock:
            self.latency_ms.append(ms)

    # -------- views
    def series(self, seconds: int = 120) -> list[dict]:
        with self.lock:
            now = int(time.time())
            return [self._series.get(t, {"t": t, "packets": 0, "bytes": 0, "flows": 0, "events": 0,
                                         "attacks": 0, "suspicious": 0})
                    for t in range(now - seconds + 1, now + 1)]

    def snapshot(self) -> dict:
        with self.lock:
            lat = sorted(self.latency_ms)
            last = self._series.get(int(time.time()) - 1, {})
            return {
                "packets": self.packets, "bytes": self.bytes, "flows": self.flows,
                "events": self.events, "attacks": self.attacks, "suspicious": self.suspicious,
                "invalid": self.invalid, "dropped": self.dropped,
                "broadcast_skipped": self.broadcast_skipped,
                "unsupported_packets": self.unsupported_packets,
                "uptime_s": round(time.time() - self.started_at, 1),
                "pps": last.get("packets", 0), "bps": last.get("bytes", 0),
                "eps": last.get("events", 0),
                "protocols": dict(self.protocols),
                "classes": dict(self.classes),
                "levels": dict(self.levels),
                "top_src": self.top_src.most_common(8),
                "top_dst": self.top_dst.most_common(8),
                "attack_src": self.attack_src.most_common(8),
                "services_attacked": self.services_attacked.most_common(8),
                "latency_ms_p50": round(lat[len(lat) // 2], 2) if lat else None,
                "latency_ms_p95": round(lat[int(len(lat) * 0.95)], 2) if lat else None,
                "simulation": {
                    "total": self.sim_total,
                    "correct": self.sim_correct,
                    "accuracy": round(self.sim_correct / self.sim_total, 4) if self.sim_total else None,
                    "confusion": [[a, b, c] for (a, b), c in self.sim_confusion.items()],
                },
            }
