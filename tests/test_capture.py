"""Live-capture packet handling (no NIC needed)."""
import threading

import pytest

scapy = pytest.importorskip("scapy")


class _Stats:
    unsupported_packets = 0


class _Engine:
    def __init__(self):
        self.got = []
        self.stats = _Stats()

    def ingest_packet(self, info):
        self.got.append(info)


def _source(engine):
    from app.capture.packet_capture import LiveCaptureSource
    src = object.__new__(LiveCaptureSource)          # skip NIC/permission checks
    src.engine, src._pause, src.progress = engine, threading.Event(), {}
    src._last_raw, src._last_ts, src.duplicates_dropped = None, 0.0, 0
    return src


def _pkt(t, sport=40000, seq=1):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2", id=seq) / TCP(sport=sport, dport=80, flags="S", seq=seq)
    p = Ether(bytes(p))
    p.time = t
    return p


def test_loopback_duplicate_frames_are_dropped():
    eng = _Engine()
    src = _source(eng)
    a = _pkt(1.0000)
    dup = _pkt(1.0001)                 # byte-identical copy 0.1 ms later (Linux lo)
    src._on_packet(a)
    src._on_packet(dup)
    assert len(eng.got) == 1 and src.duplicates_dropped == 1


def test_retransmission_and_late_identical_frames_are_kept():
    eng = _Engine()
    src = _source(eng)
    src._on_packet(_pkt(1.0, seq=1))
    src._on_packet(_pkt(1.0005, seq=2))  # different bytes -> kept
    src._on_packet(_pkt(1.0005 + 0.5, seq=2))  # identical but 500 ms later -> kept
    assert len(eng.got) == 3 and src.duplicates_dropped == 0


def test_non_ip_frames_counted_as_unsupported():
    from scapy.layers.l2 import ARP, Ether
    eng = _Engine()
    src = _source(eng)
    p = Ether() / ARP()
    p.time = 1.0
    src._on_packet(p)
    assert eng.got == [] and eng.stats.unsupported_packets == 1
