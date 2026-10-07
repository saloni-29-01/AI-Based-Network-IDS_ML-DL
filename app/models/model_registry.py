"""Versioned model registry + in-memory model cache.

Layout::

    models/
      registry.json                 # index: model id -> active version + history
      <model_id>/v<N>/
          model.joblib | model.keras
          preprocessor.joblib
          metadata.json             # generated from the actual training run

Models are loaded ONCE (``ModelManager.get``) and reused for every
prediction; nothing is re-read from disk per packet/flow.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from app.config import settings
from app.models.cnn import CNNClassifier
from app.utils.logging_setup import get_logger

log = get_logger("registry")
_LOCK = threading.RLock()


def model_id(feature_set: str, task: str, algo: str, variant: str = "") -> str:
    return f"{feature_set}-{task}-{algo}" + (f"-{variant}" if variant else "")


def registry_path() -> Path:
    return settings.model_dir / "registry.json"


def read_registry() -> dict:
    p = registry_path()
    if not p.is_file():
        return {"models": {}}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log.error(f"registry.json is corrupted: {exc}")
        return {"models": {}, "error": f"registry corrupted: {exc}"}


def _write_registry(reg: dict) -> None:
    p = registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, indent=2), encoding="utf-8")
    tmp.replace(p)


def save_model(mid: str, model, preprocessor, metadata: dict) -> dict:
    """Persist a trained model as a new version and make it active."""
    with _LOCK:
        reg = read_registry()
        entry = reg["models"].setdefault(mid, {"versions": []})
        version = (max((v["version"] for v in entry["versions"]), default=0) + 1)
        vdir = settings.model_dir / mid / f"v{version}"
        vdir.mkdir(parents=True, exist_ok=True)
        if model is not None:
            if isinstance(model, CNNClassifier):
                model.save(vdir / "model.keras")
                artifact = "model.keras"
            else:
                joblib.dump(model, vdir / "model.joblib", compress=3)
                artifact = "model.joblib"
        else:
            artifact = None
        if preprocessor is not None:
            joblib.dump(preprocessor, vdir / "preprocessor.joblib", compress=3)
        metadata = {**metadata, "id": mid, "version": version, "artifact": artifact,
                    "path": str(vdir.relative_to(settings.model_dir))}
        (vdir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        entry["versions"].append({"version": version, "trained_at": metadata.get("trained_at")})
        entry["active_version"] = version
        _write_registry(reg)
        ModelManager.instance().invalidate(mid)
        return metadata


def load_metadata(mid: str, version: int | None = None) -> dict | None:
    reg = read_registry()
    entry = reg["models"].get(mid)
    if not entry:
        return None
    version = version or entry.get("active_version")
    p = settings.model_dir / mid / f"v{version}" / "metadata.json"
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def list_models() -> list[dict]:
    out = []
    for mid in sorted(read_registry()["models"]):
        md = load_metadata(mid)
        if md:
            out.append(md)
    return out


@dataclass
class LoadedModel:
    id: str
    metadata: dict
    model: object
    preprocessor: object
    classes: list[str]

    def predict_proba_raw(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)


class ModelLoadError(RuntimeError):
    pass


class ModelManager:
    _inst: "ModelManager | None" = None

    def __init__(self):
        self._cache: dict[str, LoadedModel] = {}
        self._errors: dict[str, str] = {}
        self._lock = threading.RLock()

    @classmethod
    def instance(cls) -> "ModelManager":
        if cls._inst is None:
            cls._inst = ModelManager()
        return cls._inst

    def invalidate(self, mid: str) -> None:
        with self._lock:
            self._cache.pop(mid, None)
            self._errors.pop(mid, None)

    def get(self, mid: str) -> LoadedModel:
        with self._lock:
            if mid in self._cache:
                return self._cache[mid]
            md = load_metadata(mid)
            if md is None:
                raise ModelLoadError(f"model '{mid}' is not trained (run: python scripts/train_models.py)")
            vdir = settings.model_dir / md["path"]
            t0 = time.perf_counter()
            try:
                pre = joblib.load(vdir / "preprocessor.joblib")
                if md["artifact"] == "model.keras":
                    model = CNNClassifier.load(vdir / "model.keras")
                else:
                    model = joblib.load(vdir / "model.joblib")
            except Exception as exc:
                msg = f"failed to load '{mid}': {type(exc).__name__}: {exc}"
                self._errors[mid] = msg
                log.error(msg)
                raise ModelLoadError(msg) from exc
            lm = LoadedModel(mid, md, model, pre, md["classes"])
            self._cache[mid] = lm
            log.info(f"model loaded id={mid} version={md['version']} in {time.perf_counter()-t0:.2f}s")
            return lm

    def try_get(self, mid: str) -> LoadedModel | None:
        try:
            return self.get(mid)
        except ModelLoadError:
            return None

    def status(self) -> dict:
        with self._lock:
            return {"loaded": sorted(self._cache), "errors": dict(self._errors)}
