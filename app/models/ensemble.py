"""Weighted soft-voting ensemble over registered models.

All members must share the same task (class list) and feature set. If a
member (e.g. the CNN when TensorFlow is missing) cannot be loaded, the
ensemble runs with the remaining members and *reports* which ones are
active, so the UI never claims an engine that is not running.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from app.models.model_registry import LoadedModel, ModelManager, model_id


class EnsembleDetector:
    def __init__(self, members: list[tuple[LoadedModel, float]], feature_set: str, task: str):
        if not members:
            raise ValueError("ensemble needs at least one member")
        classes = members[0][0].classes
        for m, _ in members:
            if m.classes != classes:
                raise ValueError("ensemble members disagree on class order")
        self.members = members
        self.classes = classes
        self.feature_set = feature_set
        self.task = task

    @property
    def name(self) -> str:
        return " + ".join(f"{m.metadata['algo'].upper()}({w:.2f})" for m, w in self.members)

    @property
    def member_ids(self) -> list[str]:
        return [m.id for m, _ in self.members]

    def predict_proba(self, df: pd.DataFrame) -> tuple[np.ndarray, dict[str, np.ndarray], dict[str, np.ndarray]]:
        """Returns (ensemble_proba, per-member proba, per-member encoded X)."""
        total_w = sum(w for _, w in self.members)
        agg = None
        per_member, encoded = {}, {}
        for m, w in self.members:
            X = m.preprocessor.transform(df)
            p = np.asarray(m.model.predict_proba(X))
            per_member[m.id] = p
            encoded[m.id] = X
            agg = p * w if agg is None else agg + p * w
        return agg / total_w, per_member, encoded


def build_ensemble(feature_set: str, task: str, weights: dict[str, float],
                   variant: str = "") -> tuple[EnsembleDetector | None, list[str]]:
    """Load the configured members; returns (detector or None, problems)."""
    mm = ModelManager.instance()
    members, problems = [], []
    for algo, w in weights.items():
        if w <= 0:
            continue
        mid = model_id(feature_set, task, algo, variant)
        try:
            members.append((mm.get(mid), w))
        except Exception as exc:  # missing / corrupted / TF unavailable
            problems.append(str(exc))
    if not members:
        return None, problems
    return EnsembleDetector(members, feature_set, task), problems
