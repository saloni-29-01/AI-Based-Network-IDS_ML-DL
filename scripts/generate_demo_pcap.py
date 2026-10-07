"""Generate a small **benign** demo capture file for PCAP-replay mode.

WHAT THIS IS: a scripted, offline capture of ordinary, well-formed traffic
(web, HTTPS, DNS, mail, SSH, ping) between private/documentation addresses
(RFC 1918 / RFC 5737). Packets are assembled in memory with Scapy and
written to disk with ``wrpcap`` - nothing is ever sent on a network.

Purpose: give PCAP-replay mode something to run out of the box so the full
pipeline (parse -> flow -> features -> detection -> dashboard) can be shown
even with no capture file handy. It is intentionally benign; it demonstrates
that the IDS processes normal traffic as normal (a low false-positive rate).

To demonstrate detection on attack-shaped traffic without replaying any real
network attack, use **Dataset Simulation** mode or the **flow replay** file
built by ``scripts/build_flow_replay.py`` - both drive the same detection
pipeline from the genuine NSL-KDD benchmark records.

Usage:  python scripts/generate_demo_pcap.py [--out data/pcaps/demo_benign_traffic.pcap]
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

T0 = 1_760_000_000.0  # fixed base timestamp => reproducible file
RNG = random.Random(2024)
PKTS: list = []

GATEWAY = "192.168.10.1"
CLIENTS = [f"192.168.10.{i}" for i in range(21, 29)]
WEB = ["203.0.113.10", "203.0.113.20", "203.0.113.30"]
MAIL = "203.0.113.25"
SSH_SRV = "192.168.10.5"


def emit(t: float, ip_pkt) -> None:
    p = Ether() / ip_pkt
    p.time = T0 + t
    PKTS.append(p)


def tcp_session(t: float, cli: str, srv: str, dport: int, req: int = 400, resp: int = 4000) -> float:
    """A complete, normal TCP conversation: handshake, request, segmented
    response, graceful FIN close. Returns the end time."""
    sport = RNG.randint(40000, 60000)
    seq_c, seq_s = RNG.randint(1, 2**31), RNG.randint(1, 2**31)
    rtt = RNG.uniform(0.005, 0.04)
    emit(t, IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c))
    emit(t + rtt / 2, IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1))
    t += rtt
    emit(t, IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1))
    if req:
        emit(t + 0.001, IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA",
             seq=seq_c + 1, ack=seq_s + 1) / Raw(b"x" * req))
        seq_c += req
    t += rtt
    sent = 0
    while sent < resp:
        seg = min(1400, resp - sent)
        emit(t, IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="A",
             seq=seq_s + 1 + sent, ack=seq_c + 1) / Raw(b"y" * seg))
        sent += seg
        t += 0.002
    emit(t, IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1 + sent))
    t += RNG.uniform(0.05, 0.3)
    emit(t, IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c + 1, ack=seq_s + 1 + sent))
    emit(t + rtt / 2, IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s + 1 + sent, ack=seq_c + 2))
    emit(t + rtt, IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 2, ack=seq_s + 2 + sent))
    return t + rtt


def dns(t: float, cli: str) -> None:
    sport = RNG.randint(30000, 60000)
    emit(t, IP(src=cli, dst=GATEWAY) / UDP(sport=sport, dport=53) / Raw(b"q" * RNG.randint(28, 45)))
    emit(t + RNG.uniform(0.003, 0.03), IP(src=GATEWAY, dst=cli) / UDP(sport=53, dport=sport) / Raw(b"r" * RNG.randint(60, 180)))


def ping(t: float, src: str, dst: str) -> None:
    ident = RNG.randint(1, 65000)
    emit(t, IP(src=src, dst=dst) / ICMP(type=8, id=ident, seq=1) / Raw(b"p" * 56))
    emit(t + RNG.uniform(0.001, 0.02), IP(src=dst, dst=src) / ICMP(type=0, id=ident, seq=1) / Raw(b"p" * 56))


def build(duration: float) -> None:
    t = 0.0
    while t < duration:
        cli = RNG.choice(CLIENTS)
        r = RNG.random()
        if r < 0.45:
            dns(t, cli)
            tcp_session(t + 0.03, cli, RNG.choice(WEB), RNG.choice([80, 443, 443]),
                        req=RNG.randint(250, 700), resp=RNG.randint(1500, 40000))
        elif r < 0.65:
            dns(t, cli)
        elif r < 0.78:
            tcp_session(t, cli, MAIL, 25, req=RNG.randint(800, 6000), resp=RNG.randint(300, 600))
        elif r < 0.90:
            tcp_session(t, cli, SSH_SRV, 22, req=RNG.randint(2000, 9000), resp=RNG.randint(3000, 20000))
        else:
            ping(t, cli, GATEWAY)
        t += RNG.expovariate(9.0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data/pcaps/demo_benign_traffic.pcap")
    ap.add_argument("--duration", type=float, default=60.0, help="seconds of benign traffic")
    args = ap.parse_args()
    build(args.duration)
    PKTS.sort(key=lambda p: p.time)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), PKTS)
    print(f"Wrote {len(PKTS)} benign packets over {args.duration:.0f}s -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
