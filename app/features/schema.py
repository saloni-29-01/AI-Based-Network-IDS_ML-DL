"""NSL-KDD feature schema and the packet-derivable ("flow") subset.

Two feature spaces are used in this project:

* ``full``  - all 41 NSL-KDD features. Only available for NSL-KDD records
  (dataset simulation / benchmark evaluation).
* ``flow``  - the 28 NSL-KDD features that can be computed honestly from
  packet headers alone (basic connection features + the time-based and
  host-based traffic features). The 13 "content" features (hot,
  num_failed_logins, logged_in, root_shell, ...) need application-layer
  inspection of reassembled sessions and are NOT reconstructed. Models for
  live capture / PCAP replay are trained on this subset only, so the live
  pipeline never has to invent values for features it cannot measure.
"""
from __future__ import annotations

NSL_KDD_COLUMNS: list[str] = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
LABEL_COLUMNS = ["label", "difficulty"]
CATEGORICAL = ["protocol_type", "service", "flag"]

CONTENT_FEATURES = [
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login",
]
FLOW_FEATURES = [c for c in NSL_KDD_COLUMNS if c not in CONTENT_FEATURES]
FULL_FEATURES = list(NSL_KDD_COLUMNS)

FEATURE_SETS = {"full": FULL_FEATURES, "flow": FLOW_FEATURES}

RATE_FEATURES = [c for c in NSL_KDD_COLUMNS if c.endswith("_rate")]
BINARY_FEATURES = ["land", "logged_in", "root_shell", "is_host_login", "is_guest_login"]
INTEGER_FEATURES = [c for c in NSL_KDD_COLUMNS
                    if c not in CATEGORICAL and c not in RATE_FEATURES]

CLASSES_MULTI = ["normal", "DoS", "Probe", "R2L", "U2R"]
CLASSES_BINARY = ["normal", "attack"]

ATTACK_CATEGORY: dict[str, str] = {}
for _k in ["apache2", "back", "land", "neptune", "mailbomb", "pod", "processtable",
           "smurf", "teardrop", "udpstorm", "worm"]:
    ATTACK_CATEGORY[_k] = "DoS"
for _k in ["ftp_write", "guess_passwd", "httptunnel", "imap", "multihop", "named", "phf",
           "sendmail", "snmpgetattack", "snmpguess", "spy", "warezclient", "warezmaster",
           "xlock", "xsnoop"]:
    ATTACK_CATEGORY[_k] = "R2L"
for _k in ["ipsweep", "mscan", "nmap", "portsweep", "saint", "satan"]:
    ATTACK_CATEGORY[_k] = "Probe"
for _k in ["buffer_overflow", "loadmodule", "perl", "ps", "rootkit", "sqlattack", "xterm"]:
    ATTACK_CATEGORY[_k] = "U2R"
ATTACK_CATEGORY["normal"] = "normal"

# Valid categorical vocabularies (from the NSL-KDD training set)
PROTOCOLS = ["tcp", "udp", "icmp"]
FLAGS = ["SF", "S0", "REJ", "RSTR", "RSTO", "S1", "SH", "S2", "RSTOS0", "S3", "OTH"]

FEATURE_DESCRIPTIONS = {
    "duration": "Connection length (s)",
    "protocol_type": "Transport protocol",
    "service": "Destination service (port mapped)",
    "flag": "TCP connection state",
    "src_bytes": "Bytes originator -> responder",
    "dst_bytes": "Bytes responder -> originator",
    "land": "src == dst host and port",
    "wrong_fragment": "Malformed fragments",
    "urgent": "Packets with URG flag",
    "count": "Conns to same host, last 2 s",
    "srv_count": "Conns to same service, last 2 s",
    "serror_rate": "SYN-error rate (same host, 2 s)",
    "srv_serror_rate": "SYN-error rate (same service, 2 s)",
    "rerror_rate": "REJ rate (same host, 2 s)",
    "srv_rerror_rate": "REJ rate (same service, 2 s)",
    "same_srv_rate": "Same-service rate (same host, 2 s)",
    "diff_srv_rate": "Different-service rate (same host, 2 s)",
    "srv_diff_host_rate": "Different-host rate (same service, 2 s)",
    "dst_host_count": "Conns to same host, last 100",
    "dst_host_srv_count": "Conns to same service, last 100",
    "dst_host_same_srv_rate": "Same-service rate, last 100",
    "dst_host_diff_srv_rate": "Different-service rate, last 100",
    "dst_host_same_src_port_rate": "Same source-port rate, last 100",
    "dst_host_srv_diff_host_rate": "Different-host rate (same service), last 100",
    "dst_host_serror_rate": "SYN-error rate, last 100 (host)",
    "dst_host_srv_serror_rate": "SYN-error rate, last 100 (service)",
    "dst_host_rerror_rate": "REJ rate, last 100 (host)",
    "dst_host_srv_rerror_rate": "REJ rate, last 100 (service)",
}
