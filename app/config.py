"""Central configuration.

Values come from (highest priority first): real environment variables,
then a ``.env`` file in the project root, then the defaults below.
A tiny built-in ``.env`` parser is used so no extra dependency is needed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
APP_VERSION = "2.0.0"


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(BASE_DIR / ".env")


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    if not value:
        return default
    p = Path(value)
    return p if p.is_absolute() else (BASE_DIR / p)


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    app_env: str = field(default_factory=lambda: _env("APP_ENV", "development"))
    host: str = field(default_factory=lambda: _env("APP_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _int("APP_PORT", 8000))
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))

    nsl_kdd_dir: Path = field(default_factory=lambda: _path("NSL_KDD_DIR", BASE_DIR / "nsl-kdd"))
    data_dir: Path = field(default_factory=lambda: _path("DATA_DIR", BASE_DIR / "data"))
    model_dir: Path = field(default_factory=lambda: _path("MODEL_PATH", BASE_DIR / "models"))
    report_dir: Path = field(default_factory=lambda: _path("REPORT_DIR", BASE_DIR / "reports"))
    log_dir: Path = field(default_factory=lambda: _path("LOG_DIR", BASE_DIR / "logs"))
    database_url: str = field(default_factory=lambda: _env("DATABASE_URL", "sqlite:///data/ids.db"))

    capture_interface: str = field(default_factory=lambda: _env("CAPTURE_INTERFACE", ""))
    capture_bpf_filter: str = field(default_factory=lambda: _env("CAPTURE_BPF_FILTER", "ip"))

    # Flow tracker timeouts (seconds, in packet time)
    flow_idle_timeout: float = field(default_factory=lambda: _float("FLOW_IDLE_TIMEOUT", 10.0))
    flow_active_timeout: float = field(default_factory=lambda: _float("FLOW_ACTIVE_TIMEOUT", 120.0))
    flow_tcp_close_grace: float = field(default_factory=lambda: _float("FLOW_TCP_CLOSE_GRACE", 1.0))

    # Detection / alerting
    ensemble_weights: str = field(default_factory=lambda: _env("ENSEMBLE_WEIGHTS", "rf=0.6,cnn=0.4"))
    suspicious_threshold: float = field(default_factory=lambda: _float("SUSPICIOUS_THRESHOLD", 0.35))
    alert_min_risk: int = field(default_factory=lambda: _int("ALERT_MIN_RISK", 30))
    alert_dedup_window: float = field(default_factory=lambda: _float("ALERT_DEDUP_WINDOW", 30.0))
    alert_rate_limit_per_sec: int = field(default_factory=lambda: _int("ALERT_RATE_LIMIT", 20))
    alert_webhook_url: str = field(default_factory=lambda: _env("ALERT_WEBHOOK_URL", ""))
    severity_map: str = field(default_factory=lambda: _env(
        "SEVERITY_MAP", "normal=0,Probe=50,DoS=70,R2L=85,U2R=95"))

    # "" = baseline models; "gan" = models retrained on GAN-augmented data
    # (only affects the 41-feature engine used by dataset simulation)
    full_engine_variant: str = field(default_factory=lambda: _env("FULL_ENGINE_VARIANT", ""))

    # Broadcast/multicast flows (SSDP, mDNS, NetBIOS, DHCP discovery...) are
    # counted but not scored: NSL-KDD contains no such traffic, so the flow
    # engine mislabels them as Probe. Set SKIP_BROADCAST=false to score them.
    skip_broadcast: bool = field(default_factory=lambda: _env("SKIP_BROADCAST", "true").lower() != "false")

    # Dataset simulation default rate (records / second at 1x)
    simulation_rate: float = field(default_factory=lambda: _float("SIMULATION_RATE", 25.0))

    @property
    def db_path(self) -> Path:
        url = self.database_url
        if not url.startswith("sqlite:///"):
            raise ValueError("Only sqlite:/// DATABASE_URL values are supported in this build")
        p = Path(url[len("sqlite:///"):])
        return p if p.is_absolute() else BASE_DIR / p

    @property
    def pcap_dir(self) -> Path:
        return self.data_dir / "pcaps"

    @property
    def synthetic_dir(self) -> Path:
        return self.data_dir / "synthetic"

    @property
    def processed_dir(self) -> Path:
        return self.data_dir / "processed"

    def parsed_weights(self) -> dict[str, float]:
        return _parse_kv_floats(self.ensemble_weights)

    def parsed_severity(self) -> dict[str, float]:
        return _parse_kv_floats(self.severity_map)

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.model_dir, self.report_dir, self.log_dir,
                  self.pcap_dir, self.synthetic_dir, self.processed_dir, self.db_path.parent):
            d.mkdir(parents=True, exist_ok=True)


def _parse_kv_floats(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for part in text.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            try:
                out[k.strip()] = float(v)
            except ValueError:
                continue
    return out


settings = Settings()
