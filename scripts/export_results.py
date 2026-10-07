"""Write docs/RESULTS.md from the model registry and the GAN report.

Every number in RESULTS.md is copied from metadata written by the actual
training / evaluation runs - nothing is typed by hand.

    python scripts/export_results.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.models.model_registry import list_models  # noqa: E402


def pct(v):
    return "—" if v is None else f"{100 * v:.2f}%"


def model_table(models, task, split="test"):
    rows = ["| Model | Features | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |",
            "|---|---|---:|---:|---:|---:|---:|---:|"]
    for m in models:
        if m["task"] != task or m.get("variant"):
            continue
        t = m["metrics"][split]
        auc = t.get("roc_auc", t.get("roc_auc_ovr_macro"))
        rows.append(f"| {m['name'].split(' (')[0]} | {m['feature_set']} ({m['n_features']}) | {pct(t['accuracy'])} | "
                    f"{pct(t['precision'])} | {pct(t['recall'])} | **{pct(t['f1'])}** | "
                    f"{pct(t['false_positive_rate'])} | {'—' if auc is None else f'{auc:.3f}'} |")
    return "\n".join(rows)


def per_class(m, split="test"):
    t = m["metrics"][split]
    rows = ["| Class | Precision | Recall | F1 | Support |", "|---|---:|---:|---:|---:|"]
    for c, v in t["per_class"].items():
        rows.append(f"| {c} | {pct(v['precision'])} | {pct(v['recall'])} | {pct(v['f1'])} | {v['support']:,} |")
    return "\n".join(rows)


def main() -> int:
    models = list_models()
    if not models:
        print("No trained models - run scripts/train_models.py first")
        return 1
    by_id = {m["id"]: m for m in models}
    out = [f"# Results\n\n_Generated {datetime.now():%Y-%m-%d %H:%M} by `scripts/export_results.py` "
           "from the model registry - every figure comes from an actual evaluation run._\n",
           "Evaluation protocol: train on KDDTrain+ (minus a stratified 10% validation hold-out), "
           "preprocessing fitted on training data only, test on the official **KDDTest+** split "
           "(22,544 records, includes attack types unseen in training). Multiclass precision/recall/F1 are "
           "macro averages; FPR = normal traffic flagged as any attack.\n",
           f"Dataset fingerprint: `{models[0]['dataset']}`  \nPreprocessing: `{models[0]['preprocessing']}`\n",
           "## Binary classification (normal vs attack) — KDDTest+\n", model_table(models, "binary"),
           "\n## Multiclass classification (normal / DoS / Probe / R2L / U2R) — KDDTest+\n",
           model_table(models, "multiclass")]
    for mid in ("full-multiclass-ensemble", "flow-multiclass-ensemble"):
        if mid in by_id:
            m = by_id[mid]
            out += [f"\n### Per-class results: {m['name']}\n", per_class(m),
                    f"\nmacro-F1 {pct(m['metrics']['test']['macro_f1'])} · weighted-F1 "
                    f"{pct(m['metrics']['test']['weighted_f1'])}"]
    out.append("\n## Harder subset: KDDTest-21 (records most classifiers get wrong)\n")
    out.append(model_table(models, "multiclass", "test21"))

    gp = settings.synthetic_dir / "gan_report.json"
    if gp.is_file():
        g = json.loads(gp.read_text())
        out += ["\n## GAN augmentation (conditional WGAN-GP)\n",
                f"{g['architecture']}; {g['epochs']} epochs; {g['train_seconds']} s on CPU; "
                f"{g['synthetic_total']:,} synthetic samples for {', '.join(g['classes_augmented'])}.\n",
                "| Class | Before | After |", "|---|---:|---:|"]
        for c, v in g["class_balance_after"].items():
            out.append(f"| {c} | {g['class_balance_before'].get(c, 0):,} | {v:,} |")
        out += ["\n| Class | Generated | Valid | Kept | Duplicates of real | Internal duplicates | Distribution closeness | Quality |",
                "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for c, v in g["per_class"].items():
            out.append(f"| {c} | {v['generated']:,} | {v['valid']:,} | {v['kept']:,} | {v['duplicates_of_real']} | "
                       f"{v['internal_duplicates']} | {v['distribution_closeness']} | {v['quality_score']} |")
        rt = g.get("retrain") or {}
        if rt.get("per_class_recall"):
            out += ["\n### Effect on the Random Forest (KDDTest+)\n",
                    f"Accuracy {pct(rt['baseline_test']['accuracy'])} → {pct(rt['augmented_test']['accuracy'])}; "
                    f"macro-F1 {pct(rt['baseline_test']['macro_f1'])} → {pct(rt['augmented_test']['macro_f1'])}\n",
                    "| Class | Recall baseline | Recall GAN-augmented | Change |", "|---|---:|---:|---:|"]
            for c, v in rt["per_class_recall"].items():
                d = v["augmented"] - v["baseline"]
                out.append(f"| {c} | {pct(v['baseline'])} | {pct(v['augmented'])} | {d*100:+.1f} pp |")
        for mid in ("full-multiclass-ensemble-gan",):
            if mid in by_id:
                m = by_id[mid]
                out += [f"\n### Per-class results: {m['name']}\n", per_class(m)]
    else:
        out.append("\n## GAN augmentation\n\nNot run yet (`python scripts/train_gan.py`).")
    target = Path(__file__).resolve().parent.parent / "docs" / "RESULTS.md"
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
