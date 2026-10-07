"""Train, evaluate and register the IDS models.

Examples (run from the project root):
    python scripts/train_models.py                 # everything (full + flow, binary + multiclass)
    python scripts/train_models.py --no-cnn        # skip TensorFlow models
    python scripts/train_models.py --feature-sets flow --tasks multiclass
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.models.trainer import DEFAULT_ALGOS, train_models  # noqa: E402
from app.storage.database import init_db  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feature-sets", nargs="+", default=["full", "flow"], choices=["full", "flow"])
    ap.add_argument("--tasks", nargs="+", default=["binary", "multiclass"], choices=["binary", "multiclass"])
    ap.add_argument("--algos", nargs="+", default=DEFAULT_ALGOS, choices=DEFAULT_ALGOS)
    ap.add_argument("--no-cnn", action="store_true", help="skip the TensorFlow CNN")
    ap.add_argument("--cnn-epochs", type=int, default=10)
    args = ap.parse_args()
    settings.ensure_dirs()
    init_db()
    algos = [a for a in args.algos if not (args.no_cnn and a == "cnn")]
    t0 = time.time()
    results = train_models(args.feature_sets, args.tasks, algos, cnn_epochs=args.cnn_epochs,
                           progress=lambda m: print(f"[train] {m}", flush=True),
                           ensemble_weights=settings.parsed_weights())
    print(f"\n{'model':38s} {'test acc':>9s} {'test F1':>8s} {'FPR':>7s} {'test-21 acc':>11s}")
    for md in results:
        t, t21 = md["metrics"]["test"], md["metrics"]["test21"]
        print(f"{md['id']:38s} {t['accuracy']:9.4f} {t['f1']:8.4f} {t['false_positive_rate']:7.4f} {t21['accuracy']:11.4f}")
    print(f"\nTrained {len(results)} registry entries in {time.time()-t0:.0f}s -> {settings.model_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
