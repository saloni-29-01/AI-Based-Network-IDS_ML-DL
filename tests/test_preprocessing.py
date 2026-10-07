import numpy as np

from app.features.schema import (ATTACK_CATEGORY, CONTENT_FEATURES, FLOW_FEATURES,
                                 FULL_FEATURES)
from app.features.validators import validate_record
from app.preprocessing.dataset import load_split
from app.preprocessing.pipeline import Preprocessor


def test_dataset_loads_with_categories():
    df = load_split("train")
    assert len(df) == 125973
    assert set(df["category"]) == {"normal", "DoS", "Probe", "R2L", "U2R"}
    assert set(df["label"]) <= set(ATTACK_CATEGORY)


def test_flow_feature_set_excludes_content_features():
    assert len(FULL_FEATURES) == 41
    assert len(FLOW_FEATURES) == 28
    assert not set(CONTENT_FEATURES) & set(FLOW_FEATURES)


def test_preprocessor_train_test_consistency():
    train, test = load_split("train").head(5000), load_split("test").head(2000)
    pre = Preprocessor("full").fit(train)
    Xtr, Xte = pre.transform(train), pre.transform(test)
    assert Xtr.shape[1] == Xte.shape[1] == pre.n_outputs
    assert np.isfinite(Xte).all()


def test_scaler_fitted_on_train_only():
    """No leakage: transforming test data must not change the fitted statistics."""
    train, test = load_split("train").head(3000), load_split("test").head(3000)
    pre = Preprocessor("flow").fit(train)
    scale = pre.ct.named_transformers_["num"].named_steps["scale"]
    mean_before = scale.mean_.copy()
    pre.transform(test)
    assert np.allclose(mean_before, scale.mean_)


def test_unknown_category_is_ignored_not_crash():
    train = load_split("train").head(3000)
    pre = Preprocessor("full").fit(train)
    row = train.head(1).copy()
    row["service"] = "never_seen_service"
    X = pre.transform(row)
    svc_cols = [i for i, n in enumerate(pre.output_names) if n.startswith("service=")]
    assert X[0, svc_cols].sum() == 0


def test_feature_aggregation_maps_back_to_original_names():
    pre = Preprocessor("flow").fit(load_split("train").head(3000))
    agg = pre.aggregate_to_features(np.ones(pre.n_outputs))
    assert set(agg) == set(FLOW_FEATURES)


def test_validator_rejects_bad_records(full_record):
    assert validate_record(full_record, "full").ok
    bad = dict(full_record, src_bytes=float("nan"))
    assert not validate_record(bad, "full").ok
    bad = dict(full_record, serror_rate=1.7)
    assert not validate_record(bad, "full").ok
    bad = dict(full_record, protocol_type="sctp")
    assert not validate_record(bad, "full").ok
    missing = {k: v for k, v in full_record.items() if k != "count"}
    assert not validate_record(missing, "full").ok
    assert not validate_record(dict(full_record, extra=1), "full", allow_extra=False).ok


def test_validator_warns_on_unseen_service(full_record):
    rep = validate_record(dict(full_record, service="zzz"), "full", known_services={"http"})
    assert rep.ok and rep.warnings
