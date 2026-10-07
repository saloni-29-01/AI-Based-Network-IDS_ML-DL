"""Self-contained HTML project report built from the live database and the
model registry (no fabricated numbers)."""
from __future__ import annotations

import html
import json
import time

from app.config import APP_VERSION
from app.gan.augment import last_report
from app.models.model_registry import list_models
from app.storage import repositories as repo


def _rows(headers, rows):
    th = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    trs = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"


def build_html_report() -> str:
    models = list_models()
    model_rows = [[m["name"], m["task"], m["feature_set"],
                   f"{m['metrics']['test']['accuracy']:.4f}",
                   f"{m['metrics']['test']['f1']:.4f}",
                   f"{m['metrics']['test']['false_positive_rate']:.4f}",
                   m.get("trained_at", "")] for m in models]
    sev = repo.alert_severity_counts()
    runs = repo.list_model_runs(10)
    gan = last_report()
    gan_html = "<p>GAN augmentation has not been run yet.</p>"
    if gan:
        before = gan["class_balance_before"]
        after = gan["class_balance_after"]
        gr = [[c, before.get(c, 0), after.get(c, 0)] for c in after]
        gan_html = f"<p>Architecture: {html.escape(gan['architecture'])}, {gan['epochs']} epochs, " \
                   f"{gan['synthetic_total']} synthetic samples.</p>" + _rows(["Class", "Before", "After"], gr)
        rt = gan.get("retrain") or {}
        if rt.get("per_class_recall"):
            rr = [[c, v["baseline"], v["augmented"]] for c, v in rt["per_class_recall"].items()]
            gan_html += "<h3>Minority-class recall (baseline vs augmented)</h3>" + \
                        _rows(["Class", "Baseline", "Augmented"], rr)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>AI Network IDS - Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:40px;color:#1a2230;max-width:1000px}}
h1{{border-bottom:3px solid #2b6cb0}} h2{{color:#2b6cb0;margin-top:34px}}
table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}}
th,td{{border:1px solid #cbd5e0;padding:6px 10px;text-align:left}} th{{background:#edf2f7}}
.note{{background:#fffbea;border-left:4px solid #d69e2e;padding:10px 14px;margin:14px 0}}
</style></head><body>
<h1>AI-Based Network Intrusion Detection System</h1>
<p>Generated {time.strftime('%Y-%m-%d %H:%M:%S')} - version {APP_VERSION}</p>
<div class="note"><b>Scientific honesty.</b> All metrics below come from actual model-evaluation runs
on the held-out NSL-KDD KDDTest+ split. NSL-KDD is a benchmark dataset and is not equivalent to live
production traffic; live/PCAP detection uses a separate 28-feature flow model trained only on
packet-derivable features. Risk scores are application-level triage values derived from model
confidence and context, not calibrated probabilities of compromise.</p>
<h2>1-2. Project &amp; Dataset</h2>
<p>Binary (normal vs attack) and multiclass (normal/DoS/Probe/R2L/U2R) detection on NSL-KDD, with a
conditional WGAN-GP augmentation pipeline, flow-based live detection, ensemble/risk scoring,
de-duplicated alerting and a real-time dashboard. Built on the original fork by Mohammed Ali Cheddad
(MIT); see README for attribution.</p>
<h2>3-6. Models &amp; Evaluation (KDDTest+)</h2>
{_rows(["Model", "Task", "Features", "Accuracy", "F1", "FPR", "Trained"], model_rows)}
<h2>4. GAN Augmentation</h2>
{gan_html}
<h2>7-9. Live detection, threats &amp; alerts (current session)</h2>
<p>Events stored: {repo.count_events()} &nbsp; Alerts: {repo.count_alerts()} &nbsp; By severity: {html.escape(json.dumps(sev))}</p>
{_rows(["Model run", "Task", "Dataset", "Accuracy", "F1"], [[r["model_id"], r["task"], r["dataset"], r["accuracy"], r["f1"]] for r in runs])}
<h2>11. Limitations</h2>
<ul>
<li>NSL-KDD content features (hot, num_failed_logins, logged_in, ...) cannot be reconstructed from packet
headers, so live/PCAP detection uses a reduced 28-feature model and cannot catch purely content-based
attacks (e.g. password guessing) as well as the benchmark model.</li>
<li>The 'service' mapping from port to NSL-KDD service name is an approximation (unknown ports -> 'private').</li>
<li>Risk scoring is rule-based triage, not a calibrated probability.</li>
<li>Models trained on a 2009 benchmark will not reflect modern attack techniques without retraining.</li>
</ul>
<h2>12. Future work</h2>
<ul><li>Session reassembly for content features; UNSW-NB15 / CIC-IDS2017 support; SHAP explanations;
online learning; distributed capture.</li></ul>
</body></html>"""
