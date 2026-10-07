"""Bidirectional 5-tuple flow tracker.

A flow (connection) is keyed by (src IP, dst IP, src port, dst port,
protocol); packets in the reverse direction are matched to the same flow.
The *originator* is the host that sent the first packet (for TCP, the SYN).

Timing uses packet timestamps (not wall clock) so PCAP replay at any speed
produces exactly the same flows as the original capture.

TCP connection state is summarised with the Bro/Zeek-style ``flag`` values
used by NSL-KDD: SF, S0, S1, S2, S3, REJ, RSTO, RSTR, RSTOS0, SH, OTH.
"""
from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from typing import Callable

from app.capture.packet import ACK, FIN, RST, SYN, PacketInfo
from app.features.services import service_for

_seq = itertools.count(1)


@dataclass(slots=True)
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    start: float
    last: float
    service: str
    seq: int = field(default_factory=lambda: next(_seq))
    pkts_fwd: int = 0
    pkts_bwd: int = 0
    bytes_fwd: int = 0        # payload bytes originator -> responder
    bytes_bwd: int = 0
    wire_bytes: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    first_syn: bool = False
    syn_o: bool = False
    synack_r: bool = False
    est: bool = False
    fin_o: bool = False
    fin_r: bool = False
    rst_o: bool = False
    rst_r: bool = False
    rst_before_synack_o: bool = False
    closed_at: float | None = None
    finished: bool = False

    @property
    def key(self):
        return (self.src, self.dst, self.sport, self.dport, self.proto)

    @property
    def packets(self) -> int:
        return self.pkts_fwd + self.pkts_bwd

    @property
    def duration(self) -> float:
        return max(0.0, self.last - self.start)

    @property
    def flag(self) -> str:
        if self.proto != "tcp":
            return "SF"
        if not self.first_syn:
            return "OTH"                       # mid-stream: no SYN observed
        if not self.synack_r:
            if self.rst_r:
                return "REJ"                   # SYN answered with RST
            if self.rst_o:
                return "RSTOS0"                # SYN then originator RST, no SYN-ACK
            if self.fin_o:
                return "SH"                    # SYN then FIN, no SYN-ACK
            return "S0"                        # SYN, no reply
        if self.rst_o:
            return "RSTO"
        if self.rst_r:
            return "RSTR" if self.est or self.pkts_fwd > 1 else "REJ"
        if self.fin_o and self.fin_r:
            return "SF"
        if self.fin_o:
            return "S2"
        if self.fin_r:
            return "S3"
        return "S1"                            # established, not terminated


class FlowTracker:
    def __init__(self, on_flow_start: Callable[[Flow], None] | None = None,
                 on_flow_end: Callable[[Flow], None] | None = None,
                 idle_timeout: float = 10.0, active_timeout: float = 120.0,
                 tcp_close_grace: float = 1.0, udp_timeout: float = 5.0,
                 icmp_timeout: float = 2.0, max_flows: int = 50_000):
        self.flows: dict[tuple, Flow] = {}
        self.on_flow_start = on_flow_start
        self.on_flow_end = on_flow_end
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.tcp_close_grace = tcp_close_grace
        self.udp_timeout = udp_timeout
        self.icmp_timeout = icmp_timeout
        self.max_flows = max_flows
        self.lock = threading.RLock()
        self.unsupported_packets = 0
        self.total_flows = 0

    # ------------------------------------------------------------------
    def _key(self, p: PacketInfo):
        if p.proto == "icmp":
            # echo request/reply share id; type normalised so replies match
            t = 8 if p.icmp_type in (0, 8) else p.icmp_type
            return (p.src, p.dst, p.icmp_id, t, "icmp")
        return (p.src, p.dst, p.sport, p.dport, p.proto)

    @staticmethod
    def _reverse(k):
        if k[4] == "icmp":
            return (k[1], k[0], k[2], k[3], k[4])
        return (k[1], k[0], k[3], k[2], k[4])

    def process(self, p: PacketInfo) -> None:
        if p.proto not in ("tcp", "udp", "icmp"):
            self.unsupported_packets += 1
            return
        with self.lock:
            k = self._key(p)
            flow = self.flows.get(k)
            forward = True
            if flow is None:
                rk = self._reverse(k)
                flow = self.flows.get(rk)
                forward = False if flow is not None else True
            # a fresh SYN on a closed/finished TCP key starts a new connection
            if flow is not None and p.proto == "tcp" and forward and (p.tcp_flags & SYN) \
                    and not (p.tcp_flags & ACK) and (flow.closed_at is not None or flow.rst_o or flow.rst_r):
                self._finish(flow)
                flow = None
            if flow is None:
                flow = self._new_flow(p, k)
                forward = True
            self._update(flow, p, forward)
            if len(self.flows) > self.max_flows:
                self.expire(p.ts, force_oldest=True)

    def _new_flow(self, p: PacketInfo, k) -> Flow:
        f = Flow(src=p.src, dst=p.dst, sport=k[2], dport=k[3], proto=p.proto, start=p.ts,
                 last=p.ts, service=service_for(p.proto, p.dport, p.icmp_type))
        if p.proto == "tcp":
            f.first_syn = bool(p.tcp_flags & SYN) and not (p.tcp_flags & ACK)
        self.flows[k] = f
        self.total_flows += 1
        if self.on_flow_start:
            self.on_flow_start(f)
        return f

    def _update(self, f: Flow, p: PacketInfo, forward: bool) -> None:
        f.last = max(f.last, p.ts)
        f.wire_bytes += p.length
        if forward:
            f.pkts_fwd += 1
            f.bytes_fwd += p.payload
        else:
            f.pkts_bwd += 1
            f.bytes_bwd += p.payload
        f.wrong_fragment += int(p.wrong_fragment)
        f.urgent += int(p.urgent)
        if p.proto != "tcp":
            return
        fl = p.tcp_flags
        if forward:
            if fl & SYN and not fl & ACK:
                f.syn_o = True
            if fl & ACK and f.synack_r:
                f.est = True
            if fl & FIN:
                f.fin_o = True
            if fl & RST:
                f.rst_o = True
        else:
            if fl & SYN and fl & ACK:
                f.synack_r = True
            if fl & FIN:
                f.fin_r = True
            if fl & RST:
                f.rst_r = True
        if f.rst_o or f.rst_r:
            f.closed_at = p.ts if f.closed_at is None else f.closed_at
        elif f.fin_o and f.fin_r and f.closed_at is None:
            f.closed_at = p.ts

    def _finish(self, f: Flow) -> None:
        if f.finished:
            return
        f.finished = True
        if self.flows.get(f.key) is f:
            del self.flows[f.key]
        if self.on_flow_end:
            self.on_flow_end(f)

    def expire(self, now: float, force_oldest: bool = False) -> int:
        """Finish flows that are closed, idle or too long. Returns count."""
        done = []
        with self.lock:
            for f in list(self.flows.values()):
                if f.closed_at is not None and now - f.closed_at >= (0 if (f.rst_o or f.rst_r) else self.tcp_close_grace):
                    done.append(f)
                    continue
                timeout = (self.idle_timeout if f.proto == "tcp" else
                           self.udp_timeout if f.proto == "udp" else self.icmp_timeout)
                if now - f.last >= timeout or now - f.start >= self.active_timeout:
                    done.append(f)
            if force_oldest and not done and self.flows:
                done.append(min(self.flows.values(), key=lambda x: x.last))
            done.sort(key=lambda x: x.start)
            for f in done:
                self._finish(f)
        return len(done)

    def flush(self) -> int:
        with self.lock:
            flows = sorted(self.flows.values(), key=lambda x: x.start)
            for f in flows:
                self._finish(f)
            return len(flows)

    @property
    def active_count(self) -> int:
        return len(self.flows)
