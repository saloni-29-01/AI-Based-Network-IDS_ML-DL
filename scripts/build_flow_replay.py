"""Build the flow-replay JSONL file from the genuine NSL-KDD benchmark.

Each output line is one NSL-KDD record reduced to the 28 packet-derivable
("flow") features, plus its real ground-truth category and synthetic
private-range addresses so the dashboard's per-source views and risk
engine have something to group on. No traffic is generated; this only
re-shapes existing benchmark records the project already ships.

Usage:  python scripts/build_flow_replay.py [--split test] [--limit 1500]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.features.schema import FLOW_FEATURES  # noqa: E402
from app.preprocessing.dataset import load_split  # noqa: E402

# Deterministic synthetic hosts (RFC 1918 / RFC 5737) so views have grouping keys
INTERNAL = [f"192.168.20.{i}" for i in range(10, 40)]
EXTERNAL = [f"203.0.113.{i}" for i in range(2, 60)] + [f"198.51.100.{i}" for i in range(2, 60)]


def synth_addr(idx: int, category: str) -> dict:
    internal = INTERNAL[idx % len(INTERNAL)]
    external = EXTERNAL[(idx * 7) % len(EXTERNAL)]
    # attacks mostly originate externally; normal is internal->external
    if category == "normal":
        src, dst = internal, external
    else:
        src, dst = external, internal
    return {"src_ip": src, "dst_ip": dst,
            "src_port": 1024 + (idx * 13) % 64000, "dst_port": 1024 + (idx * 29) % 64000}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", default="test", choices=["train", "train20", "test", "test21"])
    ap.add_argument("--limit", type=int, default=1500, help="records to sample (stratified)")
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    settings.ensure_dirs()
    df = load_split(args.split)
    if args.limit and args.limit < len(df):
        # stratified sample so every attack category is represented
        frac = args.limit / len(df)
        parts = [g.sample(max(1, round(len(g) * frac)), random_state=args.seed)
                 for _, g in df.groupby("category")]
        import pandas as pd
        df = pd.concat(parts).sample(frac=1.0, random_state=args.seed)
    out = Path(args.out) if args.out else settings.pcap_dir.parent / "flow_replay_nslkdd.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out, "w", encoding="utf-8") as f:
        for idx, (_, row) in enumerate(df.iterrows()):
            rec = {c: (int(row[c]) if isinstance(row[c], bool) else row[c]) for c in FLOW_FEATURES}
            rec = {c: (v.item() if hasattr(v, "item") else v) for c, v in rec.items()}
            rec.update(synth_addr(idx, row["category"]))
            rec["packets"] = None
            rec["ground_truth"] = row["category"]
            rec["raw_label"] = row["label"]
            rec["record_ref"] = f"{args.split}#{_}"
            f.write(json.dumps(rec) + "\n")
            n += 1
    counts = df["category"].value_counts().to_dict()
    print(f"Wrote {n} flow records -> {out}\nCategory mix: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
