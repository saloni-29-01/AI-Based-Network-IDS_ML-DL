"""Metric computation. Every number shown in the UI comes from here."""
from __future__ import annotations

import numpy as np
from sklearn import metrics


def _safe(fn, *a, **k):
    try:
        v = fn(*a, **k)
        return None if v is None or (isinstance(v, float) and np.isnan(v)) else float(v)
    except ValueError:
        return None


def evaluate(y_true: np.ndarray, proba: np.ndarray, classes: list[str]) -> dict:
    """Compute a full metric bundle.

    ``y_true`` - integer class indices aligned with ``classes``.
    ``proba``  - (n, len(classes)) predicted probabilities.
    """
    y_true = np.asarray(y_true)
    y_pred = proba.argmax(axis=1)
    labels = list(range(len(classes)))
    cm = metrics.confusion_matrix(y_true, y_pred, labels=labels)
    report = metrics.classification_report(
        y_true, y_pred, labels=labels, target_names=classes, output_dict=True, zero_division=0)
    out: dict = {
        "n_samples": int(len(y_true)),
        "accuracy": float(metrics.accuracy_score(y_true, y_pred)),
        "confusion_matrix": cm.tolist(),
        "classes": list(classes),
        "per_class": {c: {"precision": report[c]["precision"], "recall": report[c]["recall"],
                          "f1": report[c]["f1-score"], "support": int(report[c]["support"])}
                      for c in classes},
    }
    normal_idx = classes.index("normal")
    true_attack = (y_true != normal_idx).astype(int)
    pred_attack = (y_pred != normal_idx).astype(int)
    attack_score = 1.0 - proba[:, normal_idx]
    tn, fp, fn, tp = metrics.confusion_matrix(true_attack, pred_attack, labels=[0, 1]).ravel()
    detection = {
        "accuracy": float((tp + tn) / max(1, tp + tn + fp + fn)),
        "precision": float(tp / max(1, tp + fp)),
        "recall": float(tp / max(1, tp + fn)),
        "f1": float(2 * tp / max(1, 2 * tp + fp + fn)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "false_negative_rate": float(fn / max(1, fn + tp)),
        "roc_auc": _safe(metrics.roc_auc_score, true_attack, attack_score),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }
    if len(classes) == 2:
        out.update({k: detection[k] for k in ("precision", "recall", "f1", "false_positive_rate",
                                              "false_negative_rate", "roc_auc")})
    else:
        out.update({
            "macro_precision": float(report["macro avg"]["precision"]),
            "macro_recall": float(report["macro avg"]["recall"]),
            "macro_f1": float(report["macro avg"]["f1-score"]),
            "weighted_precision": float(report["weighted avg"]["precision"]),
            "weighted_recall": float(report["weighted avg"]["recall"]),
            "weighted_f1": float(report["weighted avg"]["f1-score"]),
            "roc_auc_ovr_macro": _safe(_ovr_auc, y_true, proba, labels),
            # headline precision/recall/f1 for multiclass = macro averages
            "precision": float(report["macro avg"]["precision"]),
            "recall": float(report["macro avg"]["recall"]),
            "f1": float(report["macro avg"]["f1-score"]),
            "false_positive_rate": detection["false_positive_rate"],
            "false_negative_rate": detection["false_negative_rate"],
        })
    out["attack_detection"] = detection
    return out


def _ovr_auc(y_true, proba, labels):
    present = [l for l in labels if (y_true == l).any()]
    if len(present) < 2:
        return None
    aucs = []
    for l in present:
        aucs.append(metrics.roc_auc_score((y_true == l).astype(int), proba[:, l]))
    return float(np.mean(aucs))
