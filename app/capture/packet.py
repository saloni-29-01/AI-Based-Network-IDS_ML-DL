"""Lightweight packet representation shared by live capture and PCAP replay.

Scapy packets are converted once into ``PacketInfo`` so the flow tracker
never depends on a particular capture library.
"""
from __future__ import annotations

from dataclasses import dataclass

# Eagerly import the layers so Scapy registers link-layer types (e.g. EN10MB)
# before any PcapReader is created; otherwise the first reader in a process
# can fall back to Raw packets ("unknown LL type [1]").
try:  # pragma: no cover - import guard
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: F401
    from scapy.layers.l2 import Ether  # noqa: F401
except Exception:  # scapy may be absent; callers handle that separately
    Ether = None  # type: ignore

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


@dataclass(slots=True)
class PacketInfo:
    ts: float
    src: str
    dst: str
    proto: str            # "tcp" | "udp" | "icmp" | "other:<n>"
    sport: int = 0
    dport: int = 0
    length: int = 0       # IP total length
    payload: int = 0      # transport payload bytes
    tcp_flags: int = 0
    icmp_type: int = -1
    icmp_id: int = 0
    wrong_fragment: bool = False
    urgent: bool = False


def from_scapy(pkt) -> PacketInfo | None:
    """Convert a scapy packet; returns None for non-IP frames (ARP, IPv6...)."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    if IP not in pkt:
        # A reader that mis-detected the link type yields Raw frames; try to
        # re-dissect as Ethernet before giving up.
        if Ether is not None and hasattr(pkt, "original"):
            try:
                redis = Ether(bytes(pkt))
                if IP in redis:
                    redis.time = pkt.time
                    pkt = redis
                else:
                    return None
            except Exception:
                return None
        else:
            return None
    ip = pkt[IP]
    ts = float(pkt.time)
    length = int(ip.len or len(ip))
    frag_bad = False
    try:
        # NSL-KDD 'wrong_fragment': fragments with bad offset/size
        # (e.g. teardrop/pod). We flag overlapping/odd-sized fragments and
        # oversize reassembly (offset*8 + len > 65535).
        if ip.frag or (int(ip.flags) & 0x1):
            payload_len = length - ip.ihl * 4
            if (ip.frag * 8 + payload_len) > 65535 or ((int(ip.flags) & 0x1) and payload_len % 8):
                frag_bad = True
    except Exception:
        frag_bad = False
    if TCP in ip:
        t = ip[TCP]
        hdr = ip.ihl * 4 + t.dataofs * 4
        return PacketInfo(ts, ip.src, ip.dst, "tcp", int(t.sport), int(t.dport), length,
                          max(0, length - hdr), int(t.flags), wrong_fragment=frag_bad,
                          urgent=bool(int(t.flags) & URG))
    if UDP in ip:
        u = ip[UDP]
        return PacketInfo(ts, ip.src, ip.dst, "udp", int(u.sport), int(u.dport), length,
                          max(0, length - ip.ihl * 4 - 8), wrong_fragment=frag_bad)
    if ICMP in ip:
        i = ip[ICMP]
        return PacketInfo(ts, ip.src, ip.dst, "icmp", 0, 0, length,
                          max(0, length - ip.ihl * 4 - 8), icmp_type=int(i.type),
                          icmp_id=int(getattr(i, "id", 0) or 0), wrong_fragment=frag_bad)
    return PacketInfo(ts, ip.src, ip.dst, f"other:{ip.proto}", length=length, wrong_fragment=frag_bad)
