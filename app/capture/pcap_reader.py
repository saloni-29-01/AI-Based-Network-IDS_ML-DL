"""PCAP replay: packets from a capture file are fed, in timestamp order,
through exactly the same flow -> feature -> detection pipeline as live capture.

Replay pacing follows the capture's inter-packet gaps divided by ``speed``.
Gaps longer than ``max_gap`` seconds (wall clock) are shortened so a demo
doesn't stall on idle periods; packet timestamps - and therefore every flow
feature - are unchanged.
"""
from __future__ import annotations

from pathlib import Path

from app.capture.base import SourceBase
from app.capture.packet import from_scapy
from app.utils.logging_setup import get_logger

log = get_logger("pcap")


class PcapError(RuntimeError):
    pass


def count_packets(path: Path) -> int:
    from scapy.utils import PcapReader
    n = 0
    with PcapReader(str(path)) as r:
        for _ in r:
            n += 1
    return n


class PcapReplaySource(SourceBase):
    mode = "pcap"
    label = "PCAP Replay"

    def __init__(self, engine, path: Path, speed: float = 1.0, max_gap: float = 1.0):
        super().__init__(engine, speed)
        self.path = Path(path)
        self.max_gap = max_gap
        if not self.path.is_file():
            raise PcapError(f"PCAP file not found: {self.path}")
        try:
            from scapy.utils import PcapReader  # noqa: F401
        except ImportError as exc:
            raise PcapError("scapy is not installed (pip install scapy)") from exc
        self.label = f"PCAP Replay: {self.path.name}"

    def run(self) -> None:
        from scapy.utils import PcapReader

        try:
            total = count_packets(self.path)
        except Exception as exc:
            raise PcapError(f"cannot read {self.path.name}: {exc}") from exc
        self.progress = {"file": self.path.name, "total_packets": total, "processed": 0, "percent": 0.0}
        log.info(f"replay start file={self.path.name} packets={total} speed={self.speed}")
        prev_ts = None
        last_tick = None
        with PcapReader(str(self.path)) as reader:
            for i, pkt in enumerate(reader, 1):
                ts = float(pkt.time)
                if prev_ts is not None:
                    gap = max(0.0, ts - prev_ts) / self.speed
                    if gap > 0.0005 and not self._wait(min(gap, self.max_gap)):
                        break
                    if self._stop.is_set():
                        break
                elif self._stop.is_set():
                    break
                prev_ts = ts
                info = from_scapy(pkt)
                if info is not None:
                    self.engine.ingest_packet(info)
                else:
                    self.engine.stats.unsupported_packets += 1
                if last_tick is None or ts - last_tick >= 0.5:
                    self.engine.tick(ts)
                    last_tick = ts
                self.progress.update(processed=i, percent=round(100 * i / max(1, total), 1))
        # end of file (or stop): finish all open flows so every packet is analysed
        self.engine.flush_flows()
        log.info(f"replay end file={self.path.name} processed={self.progress.get('processed')}")
