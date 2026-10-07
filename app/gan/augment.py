"""GAN augmentation workflow: analyse imbalance -> train conditional
WGAN-GP -> generate minority samples -> validate -> write augmented
dataset + report. Also retrains models on the augmented data (variant
"gan") so a before/after comparison can be shown.

State is kept in a small in-memory job object so the GAN Lab page can poll
progress; results and reports are persisted under data/synthetic/.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from app.config import settings
from app.features.schema import CLASSES_MULTI, FULL_FEATURES
from app.gan.tabular_wgan import ConditionalWGANGP, TabularTransform, gan_available
from app.gan.validation import validate_synthetic
from app.preprocessing.dataset import load_split
from app.utils.logging_setup import get_logger

log = get_logger("augment")


@dataclass
class GANJob:
    status: str = "idle"       # idle | running | done | error
    message: str = ""
    error: str | None = None
    progress: list[str] = field(default_factory=list)
    report: dict | None = None
    started_at: float | None = None
    finished_at: float | None = None

    def note(self, msg: str) -> None:
        self.message = msg
        self.progress.append(msg)
        log.info(f"GAN: {msg}")


_job = GANJob()
_lock = threading.Lock()


def current_job() -> GANJob:
    return _job


def last_report() -> dict | None:
    p = settings.synthetic_dir / "gan_report.json"
    if _job.report:
        return _job.report
    if p.is_file():
        return json.loads(p.read_text())
    return None


def class_distribution(df: pd.DataFrame) -> dict:
    return df["category"].value_counts().reindex(CLASSES_MULTI).fillna(0).astype(int).to_dict()


def start_gan_job(target_classes: list[str] | None = None, per_class: int | None = None,
                  epochs: int = 60, retrain: bool = True, seed: int = 42) -> GANJob:
    with _lock:
        if _job.status == "running":
            return _job
        ok, info = gan_available()
        if not ok:
            _job.status, _job.error = "error", f"TensorFlow unavailable: {info}"
            return _job
        _reset_job()
        t = threading.Thread(target=_run_gan_job,
                             args=(target_classes, per_class, epochs, retrain, seed), daemon=True)
        t.start()
    return _job


def _reset_job() -> None:
    global _job
    _job = GANJob(status="running", started_at=time.time())


def _run_gan_job(target_classes, per_class, epochs, retrain, seed) -> None:
    try:
        settings.ensure_dirs()
        train = load_split("train")
        before = class_distribution(train)
        _job.note(f"original class distribution: {before}")

        # minority = classes below the median class count
        counts = {k: v for k, v in before.items() if v > 0}
        median = int(np.median(list(counts.values())))
        if target_classes is None:
            target_classes = [c for c in CLASSES_MULTI if c != "normal" and counts.get(c, 0) < median]
        # Conservative target: at most 20x the real samples of a class and at most
        # 25% of the majority class. Amplifying 52 real U2R rows to tens of
        # thousands would mostly teach the classifier the GAN's artefacts.
        majority = max(counts.values())
        targets = {c: min(majority // 4, counts.get(c, 0) * 20) for c in target_classes}
        _job.note(f"minority classes selected for augmentation: {target_classes} "
                  f"(targets {targets}; cap = min(20x real, 25% of majority))")

        transform = TabularTransform(FULL_FEATURES).fit(train)
        X = transform.encode(train)
        y_idx = train["category"].map({c: i for i, c in enumerate(CLASSES_MULTI)}).to_numpy()
        y_oh = np.eye(len(CLASSES_MULTI))[y_idx]
        _job.note(f"training conditional WGAN-GP ({epochs} epochs) on {len(X)} rows...")
        gan = ConditionalWGANGP(transform, CLASSES_MULTI, seed=seed)
        tr = gan.fit(X, y_oh, epochs=epochs, progress=_job.note)
        gan.save(settings.synthetic_dir / "gan_model")
        _job.note(f"GAN trained in {tr.seconds}s")

        known_services = set(train["service"].unique())
        synth_frames, per_class_reports = [], {}
        for cls in target_classes:
            want = per_class or max(0, targets.get(cls, 0) - counts.get(cls, 0))
            if want <= 0:
                continue
            raw = gan.generate(cls, int(want * 1.3))  # overgenerate, keep valid
            val = validate_synthetic(train[train["category"] == cls], raw, known_services)
            mask = np.array(val["valid_mask"], dtype=bool)
            kept = raw[mask].head(want).copy()
            kept["label"] = {"DoS": "neptune", "Probe": "satan", "R2L": "guess_passwd",
                             "U2R": "buffer_overflow"}.get(cls, "neptune")
            kept["difficulty"] = 20
            kept["category"], kept["binary"] = cls, "attack"
            synth_frames.append(kept)
            val.pop("valid_mask", None)
            val["kept"] = int(len(kept))
            per_class_reports[cls] = val
            _job.note(f"{cls}: generated {val['generated']}, valid {val['valid']}, "
                      f"kept {len(kept)}, quality {val['quality_score']}")

        synthetic = pd.concat(synth_frames, ignore_index=True) if synth_frames else pd.DataFrame()
        synthetic.to_csv(settings.synthetic_dir / "synthetic_samples.csv", index=False)
        after = class_distribution(pd.concat([train, synthetic], ignore_index=True)) if len(synthetic) else before
        _job.note(f"augmented class distribution: {after}")

        report = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "architecture": "Conditional WGAN-GP (gradient penalty, Gumbel-softmax categorical heads)",
            "epochs": epochs, "train_seconds": tr.seconds,
            "loss_curve": tr.loss_curve,
            "classes_augmented": target_classes,
            "synthetic_total": int(len(synthetic)),
            "class_balance_before": before,
            "class_balance_after": after,
            "per_class": per_class_reports,
            "retrain": None,
        }

        if retrain and len(synthetic):
            _job.note("retraining RF/CNN on augmented data for before/after comparison...")
            report["retrain"] = _retrain_comparison(synthetic)
        _job.report = report
        (settings.synthetic_dir / "gan_report.json").write_text(json.dumps(report, indent=2))
        _job.status = "done"
        _job.note("GAN augmentation complete")
    except Exception as exc:
        _job.status, _job.error = "error", f"{type(exc).__name__}: {exc}"
        log.exception(f"GAN job failed: {exc}")
    finally:
        _job.finished_at = time.time()


def _retrain_comparison(synthetic: pd.DataFrame) -> dict:
    """Train multiclass RF+CNN on augmented data (variant 'gan') and compare
    minority-class recall to the baseline models."""
    from app.models.model_registry import load_metadata, model_id
    from app.models.trainer import train_models

    base = load_metadata(model_id("full", "multiclass", "rf"))
    results = train_models(feature_sets=["full"], tasks=["multiclass"], algos=["rf", "cnn"],
                           extra_train=synthetic, variant="gan", cnn_epochs=10,
                           progress=_job.note, ensemble_weights={"rf": 0.6, "cnn": 0.4})
    aug = next((r for r in results if r["algo"] == "rf"), None)
    out = {"variant": "gan"}
    if base and aug:
        b, a = base["metrics"]["test"]["per_class"], aug["metrics"]["test"]["per_class"]
        out["baseline_test"] = {"accuracy": base["metrics"]["test"]["accuracy"],
                                "macro_f1": base["metrics"]["test"].get("macro_f1")}
        out["augmented_test"] = {"accuracy": aug["metrics"]["test"]["accuracy"],
                                 "macro_f1": aug["metrics"]["test"].get("macro_f1")}
        out["per_class_recall"] = {c: {"baseline": round(b[c]["recall"], 3),
                                       "augmented": round(a[c]["recall"], 3)}
                                   for c in b if c in a}
    return out
