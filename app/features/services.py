"""Map (protocol, port / ICMP type) to NSL-KDD 'service' names.

NSL-KDD derives 'service' from the destination port. The well-known port
assignments below follow the IANA registry for the names used in the
dataset. Unknown TCP/UDP ports map to 'private' (the dataset's catch-all
for unassigned ports) - this is an approximation and is documented as such.
"""
from __future__ import annotations

TCP_PORTS = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 43: "whois",
    53: "domain", 57: "mtp", 70: "gopher", 79: "finger", 80: "http", 84: "ctf", 87: "link",
    95: "supdup", 101: "hostnames", 102: "iso_tsap", 105: "csnet_ns", 109: "pop_2",
    110: "pop_3", 111: "sunrpc", 113: "auth", 117: "uucp_path", 119: "nntp", 137: "netbios_ns",
    138: "netbios_dgm", 139: "netbios_ssn", 143: "imap4", 150: "sql_net", 175: "vmnet",
    179: "bgp", 194: "IRC", 210: "Z39_50", 389: "ldap", 433: "nnsp", 443: "http_443",
    512: "exec", 513: "login", 514: "shell", 515: "printer", 520: "efs", 530: "courier",
    540: "uucp", 543: "klogin", 544: "kshell", 5190: "aol", 6667: "IRC", 8001: "http_8001",
    2784: "http_2784", 7: "echo", 9: "discard", 11: "systat", 13: "daytime", 15: "netstat",
    5: "rje", 71: "remote_job", 42: "name",
}
UDP_PORTS = {53: "domain_u", 69: "tftp_u", 123: "ntp_u", 137: "netbios_ns", 138: "netbios_dgm"}
ICMP_TYPES = {8: "eco_i", 0: "ecr_i", 3: "urp_i", 13: "tim_i", 14: "tim_i", 5: "red_i"}


def service_for(proto: str, dport: int, icmp_type: int = -1) -> str:
    if proto == "tcp":
        if 6000 <= dport <= 6063:
            return "X11"
        return TCP_PORTS.get(dport, "private")
    if proto == "udp":
        return UDP_PORTS.get(dport, "private")
    if proto == "icmp":
        return ICMP_TYPES.get(icmp_type, "oth_i")
    return "other"
