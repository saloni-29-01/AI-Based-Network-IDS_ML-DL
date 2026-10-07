"""Basic model-input/output monitoring.

What is implemented (and only this):
  * Population Stability Index (PSI) between the predicted-class
    distribution on the model's validation split (reference) and the last
    N live predictions;
  * mean confidence of recent predictions;
  * share of records with categorical values unseen in training, and with
    numeric values above the training maximum.

PSI > 0.25 is a common rule-of-thumb for "significant shift". This is a
simple statistical indicator, not a full drift-detection framework.
"""
from __future__ import annotations

import math
import threading
from collections import Counter, deque


def psi(expected: dict[str, float], actual: dict[str, float], eps: float = 1e-4) -> float:
    keys = set(expected) | set(actual)
    total = 0.0
    for k in keys:
        e = max(expected.get(k, 0.0), eps)
        a = max(actual.get(k, 0.0), eps)
        total += (a - e) * math.log(a / e)
    return total


class DriftMonitor:
    def __init__(self, window: int = 500):
        self.window = window
        self.lock = threading.Lock()
        self.recent: dict[str, deque] = {}
        self.conf: dict[str, deque] = {}
        self.unseen: dict[str, deque] = {}
        self.out_of_range: dict[str, deque] = {}
        self.reference: dict[str, dict[str, float]] = {}

    def set_reference(self, feature_set: str, metadata: dict | None) -> None:
        if not metadata:
            return
        val = metadata.get("metrics", {}).get("validation")
        if not val:
            return
        classes = val["classes"]
        cm = val["confusion_matrix"]
        col_sums = [sum(row[j] for row in cm) for j in range(len(classes))]
        tot = sum(col_sums) or 1
        self.reference[feature_set] = {c: s / tot for c, s in zip(classes, col_sums)}

    def observe(self, feature_set: str, predicted: str, confidence: float, unseen: bool,
                out_of_range: bool) -> None:
        with self.lock:
            for store, val in ((self.recent, predicted), (self.conf, confidence),
                               (self.unseen, unseen), (self.out_of_range, out_of_range)):
                store.setdefault(feature_set, deque(maxlen=self.window)).append(val)

    def report(self) -> dict:
        out = {"method": "PSI on predicted-class distribution vs validation reference (basic check)",
               "window": self.window, "engines": {}}
        with self.lock:
            for fs, preds in self.recent.items():
                n = len(preds)
                counts = Counter(preds)
                actual = {k: v / n for k, v in counts.items()} if n else {}
                ref = self.reference.get(fs)
                value = psi(ref, actual) if ref and n >= 100 else None
                out["engines"][fs] = {
                    "n": n,
                    "actual_distribution": {k: round(v, 4) for k, v in actual.items()},
                    "reference_distribution": {k: round(v, 4) for k, v in (ref or {}).items()},
                    "psi": round(value, 4) if value is not None else None,
                    "status": ("insufficient data (<100 predictions)" if value is None else
                               "potential distribution shift" if value > 0.25 else
                               "moderate change" if value > 0.1 else "stable"),
                    "mean_confidence": round(sum(self.conf[fs]) / n, 4) if n else None,
                    "unseen_category_rate": round(sum(self.unseen[fs]) / n, 4) if n else None,
                    "out_of_range_rate": round(sum(self.out_of_range[fs]) / n, 4) if n else None,
                }
        return out

    def reset(self) -> None:
        with self.lock:
            self.recent.clear()
            self.conf.clear()
            self.unseen.clear()
            self.out_of_range.clear()
