"""Flow tracking + NSL-KDD traffic feature extraction (unit level, no scapy)."""
from app.capture.flow_tracker import FlowTracker
from app.capture.packet import ACK, FIN, RST, SYN, PacketInfo
from app.features.flow_features import TrafficFeatureExtractor
from app.features.services import service_for

C, S = "10.0.0.1", "10.0.0.2"


def _tracker():
    done = []
    ext = TrafficFeatureExtractor()
    tr = FlowTracker(on_flow_start=ext.register_start, on_flow_end=done.append,
                     idle_timeout=5, tcp_close_grace=0.5)
    return tr, ext, done


def tcp(ts, src, dst, sp, dp, flags, payload=0):
    return PacketInfo(ts, src, dst, "tcp", sp, dp, 40 + payload, payload, flags)


def full_session(tr, t0, sport=40000, req=300, resp=2000):
    tr.process(tcp(t0, C, S, sport, 80, SYN))
    tr.process(tcp(t0 + .01, S, C, 80, sport, SYN | ACK))
    tr.process(tcp(t0 + .02, C, S, sport, 80, ACK))
    tr.process(tcp(t0 + .03, C, S, sport, 80, ACK, req))
    tr.process(tcp(t0 + .04, S, C, 80, sport, ACK, resp))
    tr.process(tcp(t0 + .05, C, S, sport, 80, FIN | ACK))
    tr.process(tcp(t0 + .06, S, C, 80, sport, FIN | ACK))
    tr.process(tcp(t0 + .07, C, S, sport, 80, ACK))


def test_complete_tcp_session_is_SF_with_directional_bytes():
    tr, ext, done = _tracker()
    full_session(tr, 0.0)
    tr.expire(2.0)
    assert len(done) == 1
    f = done[0]
    assert f.flag == "SF" and f.bytes_fwd == 300 and f.bytes_bwd == 2000
    assert f.packets == 8 and f.service == "http"


def test_unanswered_syn_is_S0_after_timeout():
    tr, _, done = _tracker()
    tr.process(tcp(0.0, C, S, 40001, 80, SYN))
    tr.expire(1.0)
    assert not done            # still waiting
    tr.expire(10.0)
    assert done[0].flag == "S0"


def test_syn_answered_by_rst_is_REJ():
    tr, _, done = _tracker()
    tr.process(tcp(0.0, C, S, 40002, 81, SYN))
    tr.process(tcp(0.01, S, C, 81, 40002, RST | ACK))
    tr.expire(0.02)
    assert done[0].flag == "REJ"


def test_established_then_originator_reset_is_RSTO():
    tr, _, done = _tracker()
    tr.process(tcp(0.0, C, S, 40003, 22, SYN))
    tr.process(tcp(0.01, S, C, 22, 40003, SYN | ACK))
    tr.process(tcp(0.02, C, S, 40003, 22, ACK))
    tr.process(tcp(0.03, C, S, 40003, 22, RST))
    tr.expire(0.04)
    assert done[0].flag == "RSTO" and done[0].service == "ssh"


def test_midstream_traffic_is_OTH():
    tr, _, done = _tracker()
    tr.process(tcp(0.0, C, S, 40004, 80, ACK, 100))
    tr.flush()
    assert done[0].flag == "OTH"


def test_udp_and_icmp_flows_pair_requests_and_replies():
    tr, _, done = _tracker()
    tr.process(PacketInfo(0.0, C, S, "udp", 5353, 53, 60, 32))
    tr.process(PacketInfo(0.01, S, C, "udp", 53, 5353, 120, 92))
    tr.process(PacketInfo(0.0, C, S, "icmp", length=84, payload=56, icmp_type=8, icmp_id=7))
    tr.process(PacketInfo(0.01, S, C, "icmp", length=84, payload=56, icmp_type=0, icmp_id=7))
    tr.flush()
    by = {f.proto: f for f in done}
    assert by["udp"].packets == 2 and by["udp"].service == "domain_u"
    assert by["icmp"].packets == 2 and by["icmp"].service == "eco_i"


def test_unsupported_protocol_is_counted_not_tracked():
    tr, _, done = _tracker()
    tr.process(PacketInfo(0.0, C, S, "other:47", length=100))
    assert tr.unsupported_packets == 1 and tr.active_count == 0


def test_traffic_features_follow_kdd_definitions():
    """10 SYNs to different ports of one host within 2 s -> high count / serror / diff_srv."""
    tr, ext, done = _tracker()
    for i in range(10):
        tr.process(tcp(i * 0.1, C, S, 50000, 1000 + i, SYN))
    tr.expire(20.0)
    last = max(done, key=lambda f: f.start)
    feats = ext.extract(last)
    assert feats["count"] == 10            # same host, last 2 s, incl. current
    assert feats["serror_rate"] == 1.0     # all S0
    assert feats["flag"] == "S0"
    assert feats["dst_host_count"] == 10
    assert feats["dst_host_same_src_port_rate"] == 1.0
    assert feats["src_bytes"] == 0 and feats["protocol_type"] == "tcp"


def test_time_window_excludes_old_connections():
    tr, ext, done = _tracker()
    full_session(tr, 0.0, sport=41000)
    full_session(tr, 5.0, sport=41001)     # > 2 s later
    tr.expire(30.0)
    later = max(done, key=lambda f: f.start)
    feats = ext.extract(later)
    assert feats["count"] == 1             # only itself in the 2 s window
    assert feats["dst_host_count"] == 2    # host window (last 255) sees both


def test_service_mapping():
    assert service_for("tcp", 443) == "http_443"
    assert service_for("tcp", 6001) == "X11"
    assert service_for("tcp", 54321) == "private"
    assert service_for("udp", 123) == "ntp_u"
    assert service_for("icmp", 0, 8) == "eco_i"
