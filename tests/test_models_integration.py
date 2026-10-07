"""Model loading, prediction, explanation and the end-to-end pipeline."""
import time

import numpy as np
import pytest

from app.features.schema import FLOW_FEATURES, FULL_FEATURES
from tests.conftest import requires_models

pytestmark = requires_models


def test_registry_has_both_engines_and_metadata():
    from app.models.model_registry import list_models
    ids = {m["id"] for m in list_models()}
    for fs in ("full", "flow"):
        for algo in ("rf", "dt", "lr", "nb", "svm", "ensemble"):
            assert f"{fs}-multiclass-{algo}" in ids
            assert f"{fs}-binary-{algo}" in ids
    md = next(m for m in list_models() if m["id"] == "full-multiclass-rf")
    for key in ("trained_at", "dataset", "preprocessing", "features", "metrics", "version"):
        assert key in md
    assert 0 < md["metrics"]["test"]["accuracy"] <= 1


def test_model_manager_caches_models():
    from app.models.model_registry import ModelManager
    mm = ModelManager.instance()
    a = mm.get("flow-multiclass-rf")
    b = mm.get("flow-multiclass-rf")
    assert a is b            # loaded once, reused


def test_missing_model_gives_clear_error():
    from app.models.model_registry import ModelLoadError, ModelManager
    with pytest.raises(ModelLoadError):
        ModelManager.instance().get("does-not-exist")


def test_detection_on_real_records_matches_saved_metrics_roughly():
    from app.detection.detector import Detector
    from app.preprocessing.dataset import load_split
    df = load_split("test").sample(600, random_state=3)
    recs = [{c: r[c] for c in FULL_FEATURES} for _, r in df.iterrows()]
    res = Detector().detect(recs, "full", explain_attacks=False)
    assert all(r["ok"] for r in res)
    for r in res:
        assert abs(sum(r["probabilities"].values()) - 1) < 1e-3
    acc = np.mean([r["predicted_class"] == t for r, t in zip(res, df["category"])])
    assert 0.6 < acc < 0.95   # KDDTest+ accuracy of the ensemble is ~0.75


def test_flow_engine_rejects_invalid_and_flags_unseen():
    from app.detection.detector import Detector
    from app.preprocessing.dataset import load_split
    row = load_split("test").iloc[5]
    rec = {c: row[c] for c in FLOW_FEATURES}
    d = Detector()
    bad = dict(rec, duration=-1)
    out = d.detect([rec, bad, dict(rec, service="zz_new")], "flow")
    assert out[0]["ok"] and not out[1]["ok"] and "negative" in out[1]["error"]
    assert out[2]["ok"] and out[2]["warnings"]


def test_tree_attribution_is_exact():
    from app.models.explain import forest_proba, path_contributions
    from app.models.model_registry import ModelManager
    from app.preprocessing.dataset import load_split
    m = ModelManager.instance().get("full-multiclass-rf")
    X = m.preprocessor.transform(load_split("test").head(15))
    P = m.model.predict_proba(X)
    for i in range(15):
        assert np.allclose(forest_proba(m.model, X[i]), P[i])
        c = int(P[i].argmax())
        bias, contrib = path_contributions(m.model, X[i], c)
        assert abs(bias + contrib.sum() - P[i, c]) < 1e-9


def test_end_to_end_flow_record_to_alert_in_db():
    """flow features -> model -> risk -> alert -> database."""
    from app.core.engine import IDSEngine
    from app.preprocessing.dataset import load_split
    from app.storage import repositories as repo
    df = load_split("test")
    dos = df[(df["category"] == "DoS") & (df["flag"] == "S0")].iloc[0]
    rec = {c: dos[c] for c in FLOW_FEATURES}
    eng = IDSEngine()
    out = eng.process_now([("pcap", "flow", rec, {"src_ip": "198.51.100.200", "dst_ip": "192.168.1.9",
                                                  "src_port": 4444, "dst_port": 80, "protocol": "tcp",
                                                  "packets": 1})])
    assert len(out) == 1
    ev = out[0]
    assert ev["verdict"] == "Attack" and ev["predicted_class"] == "DoS"
    assert repo.get_event(ev["id"]) is not None
    assert ev["alert"] is not None and ev["alert"]["explanation"]["top_features"]
    assert repo.get_alert(ev["alert"]["id"])["predicted_class"] == "DoS"


def test_dataset_simulation_source_runs_through_worker():
    from app.capture.dataset_sim import DatasetSimulationSource
    from app.core.engine import IDSEngine
    eng = IDSEngine()
    src = DatasetSimulationSource(eng, rate=5000, limit=120)
    eng.start_source(src)
    src.join(30)
    t = time.time()
    while eng.stats.events < 120 and time.time() - t < 30:
        time.sleep(0.2)
    eng.shutdown()
    assert eng.stats.events == 120
    assert eng.stats.sim_total == 120
    assert 0.5 < eng.stats.sim_correct / eng.stats.sim_total <= 1.0


def test_pcap_replay_produces_flows(tmp_dir):
    """Write a tiny benign capture, replay it, and check flows are produced."""
    pytest.importorskip("scapy")
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "gen", Path(__file__).resolve().parent.parent / "scripts" / "generate_demo_pcap.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.PKTS.clear()
    gen.build(4.0)
    gen.PKTS.sort(key=lambda p: p.time)
    from scapy.utils import wrpcap
    path = tmp_dir / "mini.pcap"
    wrpcap(str(path), gen.PKTS)

    from app.capture.pcap_reader import PcapReplaySource
    from app.core.engine import IDSEngine
    eng = IDSEngine()
    src = PcapReplaySource(eng, path, speed=100.0, max_gap=0.01)
    eng.start_source(src)
    src.join(60)
    t = time.time()
    while eng.queue.qsize() and time.time() - t < 30:
        time.sleep(0.2)
    time.sleep(1.0)
    eng.shutdown()
    assert src.state == "finished", src.error
    assert eng.stats.packets == len(gen.PKTS)
    assert eng.stats.flows > 5 and eng.stats.events == eng.stats.flows
