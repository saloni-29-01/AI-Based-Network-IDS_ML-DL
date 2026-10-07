"""Train the conditional WGAN-GP and augment NSL-KDD minority classes.

    python scripts/train_gan.py --epochs 60            # train + augment + retrain comparison
    python scripts/train_gan.py --epochs 40 --no-retrain
"""
from __future__ import annotations
import argparse, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.config import settings          # noqa: E402
from app.gan.augment import start_gan_job, current_job  # noqa: E402
from app.storage.database import init_db  # noqa: E402

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--per-class", type=int, default=None, help="override synthetic count per class")
    ap.add_argument("--no-retrain", action="store_true")
    args = ap.parse_args()
    settings.ensure_dirs(); init_db()
    start_gan_job(per_class=args.per_class, epochs=args.epochs, retrain=not args.no_retrain)
    job = current_job()
    while job.status == "running":
        time.sleep(2)
    if job.status == "error":
        print("GAN job failed:", job.error); return 1
    r = job.report
    print(f"\nSynthetic samples: {r['synthetic_total']}  classes: {r['classes_augmented']}")
    print("Before:", r["class_balance_before"]); print("After: ", r["class_balance_after"])
    if r.get("retrain") and r["retrain"].get("per_class_recall"):
        print("\nMinority-class recall (baseline -> augmented):")
        for c, v in r["retrain"]["per_class_recall"].items():
            print(f"  {c:7s} {v['baseline']:.3f} -> {v['augmented']:.3f}")
    print(f"\nReport -> {settings.synthetic_dir/'gan_report.json'}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
