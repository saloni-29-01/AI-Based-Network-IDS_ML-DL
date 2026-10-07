"""Broadcast/multicast flows are counted but not scored (outside the NSL-KDD domain)."""
import time

from app.capture.packet import PacketInfo
from app.features.flow_features import is_broadcast_or_multicast
from tests.conftest import requires_models


def test_broadcast_multicast_detection():
    for ip in ("255.255.255.255", "10.0.255.255", "192.168.1.255", "239.255.255.250", "224.0.0.251"):
        assert is_broadcast_or_multicast(ip), ip
    for ip in ("10.0.12.163", "8.8.8.8", "192.168.1.10", "not-an-ip"):
        assert not is_broadcast_or_multicast(ip), ip


@requires_models
def test_engine_skips_broadcast_but_scores_unicast():
    from app.core.engine import IDSEngine
    eng = IDSEngine()
    eng.mode = "live"
    eng.start_worker()
    # SSDP multicast + subnet broadcast from many hosts, plus one unicast DNS exchange
    for i in range(20):
        eng.ingest_packet(PacketInfo(float(i) * 0.05, f"10.0.11.{i}", "239.255.255.250", "udp", 50000 + i, 1900, 200, 172))
        eng.ingest_packet(PacketInfo(float(i) * 0.05, f"10.0.11.{i}", "10.0.255.255", "udp", 137, 137, 78, 50))
    eng.ingest_packet(PacketInfo(0.0, "10.0.12.163", "8.8.8.8", "udp", 53000, 53, 60, 32))
    eng.ingest_packet(PacketInfo(0.02, "8.8.8.8", "10.0.12.163", "udp", 53, 53000, 120, 92))
    eng.flush_flows()
    t = time.time()
    while eng.stats.events < 1 and time.time() - t < 20:
        time.sleep(0.1)
    time.sleep(0.5)
    eng.shutdown()
    assert eng.stats.flows == 41
    assert eng.stats.broadcast_skipped == 40
    assert eng.stats.events == 1          # only the unicast DNS flow was scored
