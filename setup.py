"""One-time project setup / health check.

    python setup.py            # check environment, create folders, init DB,
                               # build demo data, train models if missing/incompatible
    python setup.py --retrain  # force retraining of all models
    python setup.py --with-gan # also run GAN augmentation (~15 min on CPU)

This is NOT a setuptools packaging script; it only prepares the local
environment so ``python run.py`` (or run_project.bat) works.
"""
from __future__ import annotations

import argparse
import importlib
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

OK, WARN, BAD = "[ OK ]", "[WARN]", "[FAIL]"


def check_python() -> bool:
    v = sys.version_info
    ok = v >= (3, 10)
    print(f"{OK if ok else BAD} Python {v.major}.{v.minor}.{v.micro} ({platform.system()})"
          + ("" if ok else " - Python 3.10+ required (3.12 recommended)"))
    return ok


def check_packages() -> bool:
    required = ["numpy", "pandas", "sklearn", "joblib", "fastapi", "uvicorn", "scapy", "psutil"]
    good = True
    for mod in required:
        try:
            m = importlib.import_module(mod)
            print(f"{OK} {mod} {getattr(m, '__version__', '')}")
        except Exception as exc:
            good = False
            print(f"{BAD} {mod} missing ({exc.__class__.__name__}) -> pip install -r requirements.txt")
    try:
        import tensorflow as tf
        print(f"{OK} tensorflow {tf.__version__} (CNN + GAN enabled)")
    except Exception as exc:
        print(f"{WARN} tensorflow unavailable ({exc.__class__.__name__}) - CNN/GAN disabled, "
              "classical models still work")
    return good


def check_capture() -> None:
    from app.capture.packet_capture import capture_capability
    cap = capture_capability()
    if cap["available"]:
        print(f"{OK} live capture possible ({cap['platform']}); run as Administrator/root to sniff")
    else:
        print(f"{WARN} live capture unavailable: {cap['reason']}")
        print("       Dataset Simulation, Flow Replay and PCAP Replay still work.")


def models_ok() -> bool:
    from app.models.model_registry import ModelManager, read_registry
    reg = read_registry()
    if not reg.get("models"):
        print(f"{WARN} no trained models found")
        return False
    try:
        mm = ModelManager.instance()
        for mid in ("full-multiclass-rf", "flow-multiclass-rf"):
            mm.get(mid)
        print(f"{OK} trained models load correctly ({len(reg['models'])} registry entries)")
        return True
    except Exception as exc:
        print(f"{WARN} models present but cannot be loaded here ({exc}) - will retrain")
        return False


def run(cmd: list[str]) -> None:
    print("  $ " + " ".join(cmd))
    subprocess.run([sys.executable, *cmd], cwd=ROOT, check=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--retrain", action="store_true")
    ap.add_argument("--with-gan", action="store_true")
    ap.add_argument("--no-cnn", action="store_true", help="skip CNN when (re)training")
    args = ap.parse_args()

    print("== AI Network IDS setup ==")
    if not (check_python() and check_packages()):
        return 1
    from app.config import settings
    from app.preprocessing.dataset import DatasetMissingError, load_split
    from app.storage.database import init_db
    settings.ensure_dirs()
    print(f"{OK} folders ready (data/, models/, logs/, reports/)")
    try:
        load_split("train"); load_split("test")
        print(f"{OK} NSL-KDD dataset found in {settings.nsl_kdd_dir}")
    except DatasetMissingError as exc:
        print(f"{BAD} {exc}")
        return 1
    init_db()
    print(f"{OK} database initialised at {settings.db_path}")
    if not (settings.data_dir / "flow_replay_nslkdd.jsonl").is_file():
        run(["scripts/build_flow_replay.py"])
    print(f"{OK} flow-replay file ready")
    if not (settings.pcap_dir / "demo_benign_traffic.pcap").is_file():
        run(["scripts/generate_demo_pcap.py"])
    print(f"{OK} benign demo PCAP ready")
    check_capture()
    if args.retrain or not models_ok():
        print("Training models (a few minutes on CPU)...")
        run(["scripts/train_models.py"] + (["--no-cnn"] if args.no_cnn else []))
    if args.with_gan:
        run(["scripts/train_gan.py", "--epochs", "60"])
    print("\nSetup complete. Start the dashboard with:  python run.py --open   (or run_project.bat)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
