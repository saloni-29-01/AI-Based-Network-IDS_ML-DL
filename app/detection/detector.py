"""Detection engine: validation -> preprocessing -> ensemble -> explanation.

Two engines exist and are never mixed up:

* ``full`` engine  - 41-feature NSL-KDD models, used for Dataset Simulation
  and for /api/predict with complete NSL-KDD records;
* ``flow`` engine  - 28 packet-derivable-feature models, used for PCAP
  replay and live capture.
"""
from __future__ import annotations

import threading

import numpy as np
import pandas as pd

from app.config import settings
from app.features.validators import validate_record
from app.models.ensemble import EnsembleDetector, build_ensemble
from app.models.explain import explain_tree_prediction
from app.utils.logging_setup import get_logger

log = get_logger("detector")

ENGINE_LABELS = {
    "full": "NSL-KDD 41-feature engine (benchmark domain)"
            + (" [GAN-augmented training]" if settings.full_engine_variant == "gan" else ""),
    "flow": "Flow engine: 28 packet-derivable NSL-KDD features",
}


def _safe_explain(member, row, rec):
    try:
        return explain_tree_prediction(member, row, rec)
    except Exception as exc:
        log.warning(f"explanation failed: {exc}")
        return None


class Detector:
    def __init__(self):
        self._ensembles: dict[str, EnsembleDetector | None] = {}
        self._problems: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def load(self, feature_set: str, variant: str | None = None) -> EnsembleDetector | None:
        if variant is None:
            variant = settings.full_engine_variant if feature_set == "full" else ""
        key = f"{feature_set}:{variant}"
        with self._lock:
            if key not in self._ensembles:
                ens, problems = build_ensemble(feature_set, "multiclass", settings.parsed_weights(), variant)
                self._ensembles[key] = ens
                self._problems[key] = problems
                if ens:
                    log.info(f"detector ready feature_set={feature_set} engine={ens.name}")
                for p in problems:
                    log.warning(f"ensemble member unavailable: {p}")
            return self._ensembles[key]

    def reload(self) -> None:
        with self._lock:
            self._ensembles.clear()
            self._problems.clear()

    def status(self) -> dict:
        out = {}
        for key, ens in self._ensembles.items():
            out[key] = {"ready": ens is not None, "engine": ens.name if ens else None,
                        "members": ens.member_ids if ens else [],
                        "problems": self._problems.get(key, [])}
        return out

    def detect(self, records: list[dict], feature_set: str, explain_attacks: bool = True) -> list[dict]:
        """Run detection on raw feature records. Returns one result per record."""
        ens = self.load(feature_set)
        if ens is None:
            msg = "; ".join(sum(self._problems.values(), [])) or "no models"
            return [{"ok": False, "error": f"detection engine unavailable: {msg}"} for _ in records]
        known_services = set(ens.members[0][0].preprocessor.categories.get("service", []))
        results: list[dict | None] = [None] * len(records)
        valid_idx, valid_recs = [], []
        for i, rec in enumerate(records):
            rep = validate_record(rec, feature_set, known_services)
            if not rep.ok:
                results[i] = {"ok": False, "error": "; ".join(rep.errors)}
            else:
                valid_idx.append(i)
                valid_recs.append((rec, rep.warnings))
        if valid_recs:
            df = pd.DataFrame([r for r, _ in valid_recs])
            proba, per_member, encoded = ens.predict_proba(df)
            normal = ens.classes.index("normal")
            rf_member = next((m for m, _ in ens.members if m.metadata["algo"] in ("rf", "dt")), None)
            for j, (i, (rec, warns)) in enumerate(zip(valid_idx, valid_recs)):
                p = proba[j]
                cls = int(np.argmax(p))
                res = {
                    "ok": True,
                    "predicted_class": ens.classes[cls],
                    "confidence": float(p[cls]),
                    "attack_probability": float(1.0 - p[normal]),
                    "probabilities": {c: round(float(v), 4) for c, v in zip(ens.classes, p)},
                    "members": {mid: ens.classes[int(np.argmax(pm[j]))] for mid, pm in per_member.items()},
                    "engine": f"{ENGINE_LABELS[feature_set]} | {ens.name}",
                    "feature_set": feature_set,
                    "warnings": warns,
                }
                if cls != normal and rf_member is not None:
                    row = encoded[rf_member.id][j]
                    if explain_attacks:
                        res["explanation"] = _safe_explain(rf_member, row, rec)
                    else:
                        # deferred: computed only if a new alert is actually created
                        res["explain_fn"] = (lambda m=rf_member, r=row, x=rec: _safe_explain(m, r, x))
                results[i] = res
        return results  # type: ignore[return-value]
