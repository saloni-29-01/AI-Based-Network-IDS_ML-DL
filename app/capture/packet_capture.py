"""Live packet capture with Scapy.

Requirements:
  * Windows: Npcap (https://npcap.com) installed - tick "WinPcap API-compatible
    mode" during setup - and the app started from an Administrator terminal
    (or Npcap installed without the "admin-only" restriction).
  * Linux: root or CAP_NET_RAW (e.g. ``sudo``).
  * macOS: root, or read access to /dev/bpf*.

Every failure (Scapy missing, Npcap missing, no permission, bad interface)
is turned into a clear message; the rest of the app keeps running.
"""
from __future__ import annotations

import platform
import time

from app.capture.base import SourceBase
from app.capture.packet import from_scapy
from app.utils.logging_setup import get_logger

log = get_logger("capture")


class CaptureUnavailable(RuntimeError):
    pass


def capture_capability() -> dict:
    """Describe whether live capture can work on this machine (no capture is started)."""
    info = {"platform": platform.system(), "scapy": False, "pcap_driver": None,
            "available": False, "reason": None}
    try:
        import scapy  # noqa: F401
        from scapy.config import conf
        info["scapy"] = True
    except Exception as exc:
        info["reason"] = f"scapy not importable: {exc}. Install with: pip install scapy"
        return info
    if platform.system() == "Windows":
        try:
            info["pcap_driver"] = "Npcap" if conf.use_pcap else None
        except Exception:
            info["pcap_driver"] = None
        if not info["pcap_driver"]:
            info["reason"] = ("Npcap not detected. Install Npcap from https://npcap.com "
                              "(enable 'WinPcap API-compatible Mode'), then restart the app.")
            return info
    info["available"] = True
    return info


def list_interfaces() -> list[dict]:
    try:
        from scapy.interfaces import get_working_ifaces
        out = []
        for iface in get_working_ifaces():
            out.append({
                "name": str(iface.name),
                "description": str(getattr(iface, "description", "") or iface.name),
                "ip": str(getattr(iface, "ip", "") or ""),
                "mac": str(getattr(iface, "mac", "") or ""),
            })
        return out
    except Exception as exc:
        log.warning(f"interface listing failed: {exc}")
        return []


class LiveCaptureSource(SourceBase):
    mode = "live"
    label = "Live Network Monitoring"

    def __init__(self, engine, interface: str | None = None, bpf_filter: str = "ip"):
        super().__init__(engine, 1.0)
        cap = capture_capability()
        if not cap["available"]:
            raise CaptureUnavailable(cap["reason"])
        names = {i["name"] for i in list_interfaces()}
        if interface and names and interface not in names:
            raise CaptureUnavailable(f"interface '{interface}' not found. Available: {sorted(names)}")
        self.interface = interface or None
        self.bpf_filter = bpf_filter
        self.sniffer = None
        self._last_raw: bytes | None = None
        self._last_ts = 0.0
        self.duplicates_dropped = 0
        self.label = f"Live Network Monitoring ({self.interface or 'default interface'})"

    def _on_packet(self, pkt) -> None:
        if self._pause.is_set():
            return
        # Linux loopback delivers every frame twice to a raw socket (outgoing +
        # incoming copy). Drop a frame byte-identical to the previous one seen
        # within 2 ms; a genuine retransmission always differs (seq/IP id).
        raw = bytes(pkt)
        ts = float(pkt.time)
        if raw == self._last_raw and ts - self._last_ts < 0.002:
            self.duplicates_dropped += 1
            self.progress["duplicate_frames_dropped"] = self.duplicates_dropped
            return
        self._last_raw, self._last_ts = raw, ts
        info = from_scapy(pkt)
        if info is not None:
            self.engine.ingest_packet(info)
        else:
            self.engine.stats.unsupported_packets += 1

    def _start_sniffer(self, bpf: str | None) -> None:
        from scapy.sendrecv import AsyncSniffer
        self.sniffer = AsyncSniffer(iface=self.interface, filter=bpf, prn=self._on_packet, store=False)
        self.sniffer.start()
        time.sleep(0.5)
        # AsyncSniffer reports start-up failures through .exception (scapy>=2.5)
        exc = getattr(self.sniffer, "exception", None)
        if exc is not None:
            raise exc
        if not getattr(self.sniffer, "running", True):
            raise CaptureUnavailable("sniffer stopped immediately (check permissions/interface)")

    def run(self) -> None:
        self.filter_note = None
        try:
            try:
                self._start_sniffer(self.bpf_filter or None)
            except Exception as exc:
                # Kernel BPF filters need libpcap (Npcap provides it on Windows).
                # Without it, capture unfiltered: non-IP frames are dropped in
                # Python by from_scapy(), so detection is unaffected.
                if self.bpf_filter and "filter" in str(exc).lower():
                    self.filter_note = (f"BPF filter {self.bpf_filter!r} ignored (libpcap unavailable); "
                                        "capturing unfiltered, non-IP frames dropped in Python")
                    log.warning(self.filter_note)
                    self._start_sniffer(None)
                else:
                    raise
        except PermissionError as exc:
            raise CaptureUnavailable(
                "Permission denied opening the capture device. Run the terminal as Administrator "
                "(Windows) or use sudo (Linux).") from exc
        except OSError as exc:
            msg = str(exc)
            if "Operation not permitted" in msg or "permission" in msg.lower():
                raise CaptureUnavailable("Permission denied: run as Administrator / root.") from exc
            raise CaptureUnavailable(f"capture failed to start: {msg}") from exc
        log.info(f"live capture started iface={self.interface or 'default'} filter={self.bpf_filter!r}")
        self.progress = {"interface": self.interface or "default"}
        if self.filter_note:
            self.progress["note"] = self.filter_note
        # expire flows in wall-clock time while capturing
        while not self._stop.is_set():
            self.engine.tick(time.time())
            time.sleep(0.5)
        try:
            self.sniffer.stop()
        except Exception:
            pass
        self.engine.flush_flows()
        log.info("live capture stopped")

