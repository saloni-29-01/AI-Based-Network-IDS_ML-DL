"""Model feature importance / local explanation for tree ensembles.

Local explanations use *path attribution* (Saabas method, as in the
``treeinterpreter`` package): walking each tree's decision path, the change
in the predicted class probability at every split is credited to the
feature tested at that split; contributions are averaged over the trees.
``bias + sum(contributions) == predicted probability`` exactly.

This describes how the model arrived at its output; it is NOT a causal
explanation of the traffic.
"""
from __future__ import annotations

import numpy as np


def _tree_values(tree) -> np.ndarray:
    v = tree.tree_.value[:, 0, :].astype(float)
    s = v.sum(axis=1, keepdims=True)
    s[s == 0] = 1.0
    return v / s


_TREE_CACHE: dict[int, tuple] = {}


def _tree_arrays(est):
    """Plain-Python copies of a fitted tree's arrays (cached per estimator).
    Walking these directly is ~20x faster than calling decision_path per tree."""
    key = id(est)
    hit = _TREE_CACHE.get(key)
    if hit is not None and hit[0] is est:
        return hit[1]
    t = est.tree_
    arrs = (t.children_left.tolist(), t.children_right.tolist(), t.feature.tolist(),
            t.threshold.tolist(), _tree_values(est))
    _TREE_CACHE[key] = (est, arrs)
    return arrs


def path_contributions(forest, x: np.ndarray, class_idx: int) -> tuple[float, np.ndarray]:
    """Return (bias, per-input-column contribution) for one sample."""
    x = np.asarray(x, dtype=np.float32).ravel()
    xl = x.tolist()
    estimators = getattr(forest, "estimators_", None) or [forest]
    contrib = np.zeros(x.shape[0])
    bias = 0.0
    for est in estimators:
        left, right, feat, thr, vals = _tree_arrays(est)
        node = 0
        bias += vals[0, class_idx]
        while left[node] != -1:          # -1 marks a leaf
            f = feat[node]
            child = left[node] if xl[f] <= thr[node] else right[node]
            contrib[f] += vals[child, class_idx] - vals[node, class_idx]
            node = child
    n = len(estimators)
    return bias / n, contrib / n


def forest_proba(forest, x: np.ndarray) -> np.ndarray:
    """Mean leaf class-distribution over trees for one sample (== predict_proba)."""
    xl = np.asarray(x, dtype=np.float32).ravel().tolist()
    estimators = getattr(forest, "estimators_", None) or [forest]
    total = None
    for est in estimators:
        left, right, feat, thr, vals = _tree_arrays(est)
        node = 0
        while left[node] != -1:
            node = left[node] if xl[feat[node]] <= thr[node] else right[node]
        total = vals[node].copy() if total is None else total + vals[node]
    return total / len(estimators)


def explain_tree_prediction(loaded, X_row: np.ndarray, raw_record: dict, top_k: int = 6) -> dict | None:
    """Top contributing original features for the predicted class."""
    model = loaded.model
    if not hasattr(model, "tree_") and not hasattr(model, "estimators_"):
        return None
    proba = forest_proba(model, X_row)  # same as predict_proba, without thread-pool overhead
    cls = int(np.argmax(proba))
    bias, contrib = path_contributions(model, X_row, cls)
    per_feature = loaded.preprocessor.aggregate_to_features(contrib)
    ranked = sorted(per_feature.items(), key=lambda kv: abs(kv[1]), reverse=True)[:top_k]
    return {
        "method": "Model Feature Importance / Explanation (tree path attribution)",
        "model": loaded.id,
        "predicted_class": loaded.classes[cls],
        "base_rate": round(float(bias), 4),
        "probability": round(float(proba[cls]), 4),
        "top_features": [
            {"feature": f, "value": _fmt(raw_record.get(f)), "contribution": round(float(c), 4)}
            for f, c in ranked
        ],
    }


def global_importance(loaded, top_k: int = 15) -> list[dict]:
    model = loaded.model
    imp = getattr(model, "feature_importances_", None)
    if imp is None:
        return []
    agg = loaded.preprocessor.aggregate_to_features(np.asarray(imp))
    ranked = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
    return [{"feature": f, "importance": round(float(v), 5)} for f, v in ranked]


def _fmt(v):
    if isinstance(v, (float, np.floating)):
        return round(float(v), 4)
    if isinstance(v, (np.integer,)):
        return int(v)
    return v
