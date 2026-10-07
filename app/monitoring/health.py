"""System health snapshot (CPU, memory, database, models, capture)."""
from __future__ import annotations

import platform
import sys
import time

import psutil

from app.config import APP_VERSION, settings
from app.storage.database import db_health

_PROC = psutil.Process()
_START = time.time()


def system_health() -> dict:
    vm = psutil.virtual_memory()
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": vm.percent,
        "process_rss_mb": round(_PROC.memory_info().rss / 1e6, 1),
        "uptime_s": round(time.time() - _START, 1),
        "database": db_health(),
        "app_version": APP_VERSION,
        "environment": settings.app_env,
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()}",
    }
