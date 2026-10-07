"""Unified training pipeline (replaces the notebook-only training flow).

Protocol (no leakage):
  * train on KDDTrain+ (minus a stratified 10% validation hold-out);
  * preprocessing is fitted on the training portion only;
  * report metrics on the validation hold-out, on the official KDDTest+
    split and on the harder KDDTest-21 subset.

Note: KDDTest+ contains attack types never seen in KDDTrain+, so test
scores are much lower than random-split scores within KDDTrain+ (which is
what the original binary notebook reported). The test-split numbers are the
honest measure of generalisation.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from app.features.schema import CLASSES_BINARY, CLASSES_MULTI, FEATURE_SETS
from app.models.classical import ALGORITHMS, build_classical
from app.models.cnn import CNNClassifier, tensorflow_available
from app.models.evaluation import evaluate
from app.models.explain import global_importance
from app.models.model_registry import LoadedModel, model_id, save_model
from app.preprocessing.dataset import dataset_version, load_split
from app.preprocessing.pipeline import Preprocessor
from app.utils.logging_setup import get_logger

log = get_logger("trainer")

TASKS = {"binary": ("binary", CLASSES_BINARY), "multiclass": ("category", CLASSES_MULTI)}
DEFAULT_ALGOS = ["lr", "nb", "svm", "dt", "rf", "cnn"]


def _encode_y(series: pd.Series, classes: list[str]) -> np.ndarray:
    idx = {c: i for i, c in enumerate(classes)}
    return series.map(idx).to_numpy()


def train_models(feature_sets=("full", "flow"), tasks=("binary", "multiclass"),
                 algos=DEFAULT_ALGOS, extra_train: pd.DataFrame | None = None,
                 variant: str = "", cnn_epochs: int = 10, seed: int = 42,
                 progress=None, ensemble_weights: dict[str, float] | None = None) -> list[dict]:
    """Train, evaluate and register models. Returns list of metadata dicts."""
    progress = progress or (lambda msg: None)
    ensemble_weights = ensemble_weights or {"rf": 0.6, "cnn": 0.4}
    if "cnn" in algos:
        tf_ok, tf_info = tensorflow_available()
        if not tf_ok:
            log.warning(f"TensorFlow unavailable ({tf_info}); CNN models will be skipped")
            algos = [a for a in algos if a != "cnn"]

    train_df = load_split("train")
    test_df, test21_df = load_split("test"), load_split("test21")
    fit_df, val_df = train_test_split(train_df, test_size=0.10, random_state=seed,
                                      stratify=train_df["category"])
    if extra_train is not None and len(extra_train):
        fit_df = pd.concat([fit_df, extra_train], ignore_index=True)
    ds_version = dataset_version() + (f"+{variant}({len(extra_train)} synthetic)" if variant else "")
    results = []

    for fs in feature_sets:
        pre = Preprocessor(fs).fit(fit_df)
        X_fit, X_val = pre.transform(fit_df), pre.transform(val_df)
        X_test, X_t21 = pre.transform(test_df), pre.transform(test21_df)
        for task in tasks:
            col, classes = TASKS[task]
            y_fit, y_val = _encode_y(fit_df[col], classes), _encode_y(val_df[col], classes)
            y_test, y_t21 = _encode_y(test_df[col], classes), _encode_y(test21_df[col], classes)
            probas: dict[str, dict[str, np.ndarray]] = {}
            for algo in algos:
                mid = model_id(fs, task, algo, variant)
                progress(f"training {mid}")
                log.info(f"training model id={mid} rows={len(X_fit)} inputs={X_fit.shape[1]}")
                t0 = time.perf_counter()
                history = None
                if algo == "cnn":
                    model = CNNClassifier(epochs=cnn_epochs, seed=seed)
                    model.fit(X_fit, y_fit, X_val, y_val, n_classes=len(classes))
                    history = model.history
                    params = {"epochs_max": cnn_epochs, "batch_size": model.batch_size,
                              "epochs_run": len(history.get("loss", []))}
                else:
                    model = build_classical(algo, seed)
                    model.fit(X_fit, y_fit)
                    params = {k: v for k, v in model.get_params().items()
                              if isinstance(v, (int, float, str, bool)) or v is None}
                train_secs = time.perf_counter() - t0
                p_val, p_test, p_t21 = (model.predict_proba(X) for X in (X_val, X_test, X_t21))
                probas[algo] = {"val": p_val, "test": p_test, "test21": p_t21}
                md = {
                    "name": f"{ALGORITHMS[algo]} ({task}, {fs} features)" + (f" [{variant}]" if variant else ""),
                    "algo": algo, "task": task, "feature_set": fs, "variant": variant or None,
                    "classes": classes,
                    "features": FEATURE_SETS[fs], "n_features": len(FEATURE_SETS[fs]),
                    "n_inputs": int(X_fit.shape[1]),
                    "dataset": ds_version, "preprocessing": pre.version,
                    "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "training_seconds": round(train_secs, 2),
                    "train_rows": int(len(X_fit)),
                    "train_class_counts": fit_df[col].value_counts().to_dict(),
                    "hyperparameters": params,
                    "metrics": {
                        "validation": evaluate(y_val, p_val, classes),
                        "test": evaluate(y_test, p_test, classes),
                        "test21": evaluate(y_t21, p_t21, classes),
                    },
                    "history": history,
                }
                if algo in ("rf", "dt"):
                    md["feature_importance"] = global_importance(
                        LoadedModel(mid, md, model, pre, classes))
                saved = save_model(mid, model, pre, md)
                _record_run(saved)
                results.append(saved)
                m = md["metrics"]["test"]
                log.info(f"trained id={mid} secs={train_secs:.1f} test_acc={m['accuracy']:.4f} test_f1={m['f1']:.4f}")
                progress(f"done {mid}: test accuracy {m['accuracy']:.4f}")

            # --- ensemble evaluated from the members' actual predictions ---
            members = {a: w for a, w in ensemble_weights.items() if a in probas and w > 0}
            if members:
                tot = sum(members.values())
                ens = {split: sum(probas[a][split] * w for a, w in members.items()) / tot
                       for split in ("val", "test", "test21")}
                eid = model_id(fs, task, "ensemble", variant)
                md = {
                    "name": f"Ensemble {'+'.join(a.upper() for a in members)} ({task}, {fs} features)" + (f" [{variant}]" if variant else ""),
                    "algo": "ensemble", "task": task, "feature_set": fs, "variant": variant or None,
                    "classes": classes, "features": FEATURE_SETS[fs], "n_features": len(FEATURE_SETS[fs]),
                    "members": {model_id(fs, task, a, variant): w for a, w in members.items()},
                    "dataset": ds_version, "preprocessing": pre.version,
                    "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "metrics": {
                        "validation": evaluate(y_val, ens["val"], classes),
                        "test": evaluate(y_test, ens["test"], classes),
                        "test21": evaluate(y_t21, ens["test21"], classes),
                    },
                }
                saved = save_model(eid, None, None, md)
                _record_run(saved)
                results.append(saved)
    return results


def _record_run(md: dict) -> None:
    try:
        from app.storage.repositories import record_model_run
        record_model_run(md)
    except Exception as exc:  # DB problems must not lose a trained model
        log.warning(f"could not record model run in DB: {exc}")
