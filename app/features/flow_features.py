"""Compute the 28 packet-derivable NSL-KDD features for finished flows.

Basic features come from the flow itself. Traffic features follow the
KDD'99 definitions (Lee & Stolfo):

* time-based  - connections that *started* in the 2 seconds up to and
  including the current connection's start;
* host-based  - the most recent connections (by start time) up to and
  including the current one. A window of 255 connections is used, which
  matches the value range of NSL-KDD's ``dst_host_*`` counts (0-255).

"Same service" means same destination service (port/ICMP type mapping).
SYN errors = flags S0/S1/S2/S3; REJ errors = flag REJ.
"""
from __future__ import annotations

import threading

from app.capture.flow_tracker import Flow

SERROR_FLAGS = {"S0", "S1", "S2", "S3"}
TIME_WINDOW = 2.0
HOST_WINDOW = 255


def _rate(n: int, d: int) -> float:
    return round(n / d, 2) if d else 0.0


class TrafficFeatureExtractor:
    def __init__(self, max_history: int = 20_000):
        # plain list + amortised trimming => O(1) random access by index
        self.history: list[Flow] = []
        self.max_history = max_history
        self.lock = threading.Lock()

    def register_start(self, flow: Flow) -> None:
        with self.lock:
            self.history.append(flow)
            if len(self.history) > 2 * self.max_history:
                del self.history[: len(self.history) - self.max_history]

    def _index_of(self, flow: Flow) -> int:
        if not self.history:
            return -1
        idx = flow.seq - self.history[0].seq
        if 0 <= idx < len(self.history) and self.history[idx] is flow:
            return idx
        # seq numbers are global; fall back to a scan if trackers interleave
        for i in range(len(self.history) - 1, -1, -1):
            if self.history[i] is flow:
                return i
        return -1

    def extract(self, flow: Flow) -> dict:
        with self.lock:
            idx = self._index_of(flow)
            if idx < 0:
                hist = [flow]
            else:
                # only the slice we need: enough for the host window, plus
                # everything inside the 2 s time window
                lo = max(0, idx - HOST_WINDOW + 1)
                t_lo = flow.start - TIME_WINDOW
                while lo > 0 and self.history[lo - 1].start >= t_lo:
                    lo -= 1
                hist = self.history[lo: idx + 1]
        # ---- time-based (2 s) ----
        same_host = same_srv = 0
        sh_serr = sh_rerr = sh_same_srv = 0
        ss_serr = ss_rerr = ss_diff_host = 0
        t0 = flow.start - TIME_WINDOW
        for c in reversed(hist):
            if c.start < t0:
                break
            fl = c.flag
            if c.dst == flow.dst:
                same_host += 1
                sh_serr += fl in SERROR_FLAGS
                sh_rerr += fl == "REJ"
                sh_same_srv += c.service == flow.service
            if c.service == flow.service:
                same_srv += 1
                ss_serr += fl in SERROR_FLAGS
                ss_rerr += fl == "REJ"
                ss_diff_host += c.dst != flow.dst
        # ---- host-based (last 255 connections) ----
        window = hist[-HOST_WINDOW:]
        dh = dh_srv_same = dh_src_port = dh_serr = dh_rerr = 0
        ds = ds_diff_host = ds_serr = ds_rerr = 0
        for c in window:
            fl = c.flag
            if c.dst == flow.dst:
                dh += 1
                dh_srv_same += c.service == flow.service
                dh_src_port += c.sport == flow.sport
                dh_serr += fl in SERROR_FLAGS
                dh_rerr += fl == "REJ"
            if c.service == flow.service:
                ds += 1
                ds_diff_host += c.dst != flow.dst
                ds_serr += fl in SERROR_FLAGS
                ds_rerr += fl == "REJ"
        return {
            "duration": round(flow.duration, 3),
            "protocol_type": flow.proto,
            "service": flow.service,
            "flag": flow.flag,
            "src_bytes": int(flow.bytes_fwd),
            "dst_bytes": int(flow.bytes_bwd),
            "land": int(flow.src == flow.dst and flow.sport == flow.dport),
            "wrong_fragment": int(min(flow.wrong_fragment, 3)),
            "urgent": int(flow.urgent),
            "count": min(same_host, 511),
            "srv_count": min(same_srv, 511),
            "serror_rate": _rate(sh_serr, same_host),
            "srv_serror_rate": _rate(ss_serr, same_srv),
            "rerror_rate": _rate(sh_rerr, same_host),
            "srv_rerror_rate": _rate(ss_rerr, same_srv),
            "same_srv_rate": _rate(sh_same_srv, same_host),
            "diff_srv_rate": _rate(same_host - sh_same_srv, same_host),
            "srv_diff_host_rate": _rate(ss_diff_host, same_srv),
            "dst_host_count": min(dh, 255),
            "dst_host_srv_count": min(ds, 255),
            "dst_host_same_srv_rate": _rate(dh_srv_same, dh),
            "dst_host_diff_srv_rate": _rate(dh - dh_srv_same, dh),
            "dst_host_same_src_port_rate": _rate(dh_src_port, dh),
            "dst_host_srv_diff_host_rate": _rate(ds_diff_host, ds),
            "dst_host_serror_rate": _rate(dh_serr, dh),
            "dst_host_srv_serror_rate": _rate(ds_serr, ds),
            "dst_host_rerror_rate": _rate(dh_rerr, dh),
            "dst_host_srv_rerror_rate": _rate(ds_rerr, ds),
        }

    def reset(self) -> None:
        with self.lock:
            self.history.clear()


def is_broadcast_or_multicast(ip: str) -> bool:
    """True for IPv4 limited/directed broadcast (x.x.x.255 heuristic) and multicast.

    The directed-broadcast check assumes the last octet 255 marks a broadcast,
    which holds for /24 and wider networks (the common case); the subnet mask
    is not visible in packet headers.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 4:
        return addr.is_multicast or ip == "255.255.255.255" or ip.endswith(".255")
    return addr.is_multicast


def flow_metadata(flow: Flow) -> dict:
    icmp = flow.proto == "icmp"
    return {
        "src_ip": flow.src, "dst_ip": flow.dst,
        "src_port": None if icmp else flow.sport, "dst_port": None if icmp else flow.dport,
        "protocol": flow.proto, "packets": flow.packets, "start": flow.start, "end": flow.last,
        "wire_bytes": flow.wire_bytes,
    }
