"""GAN data-path tests. These would have caught the double-tanh collapse
(every synthetic `duration` = 3, `hot` = 1) found during verification."""
import numpy as np
import pytest

from app.features.schema import FULL_FEATURES, RATE_FEATURES
from app.gan.tabular_wgan import TabularTransform, gan_available
from app.gan.validation import validate_synthetic
from app.preprocessing.dataset import load_split

tf_missing = not gan_available()[0]


@pytest.fixture(scope="module")
def train_sample():
    return load_split("train").sample(3000, random_state=1)


def test_encode_decode_roundtrip(train_sample):
    tt = TabularTransform(FULL_FEATURES).fit(train_sample)
    back = tt.decode(tt.encode(train_sample))
    for c in ("protocol_type", "service", "flag"):
        assert (back[c].values == train_sample[c].values).all()
    for c in ("src_bytes", "count", "dst_host_count", "duration"):
        assert np.allclose(back[c].values, train_sample[c].values, atol=1)
    for c in RATE_FEATURES:
        assert np.allclose(back[c].values, train_sample[c].values, atol=0.011)


def test_encoded_numeric_range_spans_minus_one_to_one(train_sample):
    tt = TabularTransform(FULL_FEATURES).fit(train_sample)
    X = tt.encode(train_sample)[:, :len(tt.numeric)]
    assert X.min() >= -1.0001 and X.max() <= 1.0001
    assert (X == -1).mean() > 0.3          # zero-inflated features map to exactly -1


@pytest.mark.skipif(tf_missing, reason="TensorFlow not installed")
def test_activation_can_reach_full_range(train_sample):
    import tensorflow as tf
    from app.gan.tabular_wgan import ConditionalWGANGP
    from app.features.schema import CLASSES_MULTI
    tt = TabularTransform(FULL_FEATURES).fit(train_sample)
    gan = ConditionalWGANGP(tt, CLASSES_MULTI)
    raw = tf.constant(np.full((2, tt.spec.output_dim), 20.0, dtype=np.float32))
    num = gan._activate(raw).numpy()[:, :len(tt.numeric)]
    assert num.max() > 0.99                # a double tanh would cap this at ~0.76
    raw = tf.constant(np.full((2, tt.spec.output_dim), -20.0, dtype=np.float32))
    assert gan._activate(raw).numpy()[:, :len(tt.numeric)].min() < -0.99
    # the generator's numeric head must be linear, otherwise tanh is applied twice
    gan._build()
    assert gan.gen.get_layer("num").activation.__name__ == "linear"


@pytest.mark.skipif(tf_missing, reason="TensorFlow not installed")
def test_short_training_produces_valid_non_constant_samples(train_sample):
    from app.features.schema import CLASSES_MULTI
    from app.gan.tabular_wgan import ConditionalWGANGP
    tt = TabularTransform(FULL_FEATURES).fit(train_sample)
    X = tt.encode(train_sample)
    y = np.eye(len(CLASSES_MULTI))[train_sample["category"].map(
        {c: i for i, c in enumerate(CLASSES_MULTI)}).to_numpy()]
    gan = ConditionalWGANGP(tt, CLASSES_MULTI, seed=3)
    res = gan.fit(X, y, epochs=2, batch_size=128)
    assert len(res.loss_curve) == 2 and all(np.isfinite(e["wasserstein"]) for e in res.loss_curve)
    syn = gan.generate("DoS", 400)
    assert list(syn.columns) == FULL_FEATURES and len(syn) == 400
    varying = [c for c in ("src_bytes", "dst_host_count", "count", "same_srv_rate", "dst_bytes")
               if syn[c].nunique() > 1]
    assert len(varying) >= 3, "numeric outputs collapsed to constants"
    rep = validate_synthetic(train_sample[train_sample.category == "DoS"], syn,
                             set(train_sample["service"]))
    assert rep["invalid"] == 0 and 0 <= rep["quality_score"] <= 100


def test_validation_flags_bad_rows(train_sample):
    real = train_sample.head(200)
    bad = real.head(10)[FULL_FEATURES].copy()
    bad.loc[bad.index[0], "serror_rate"] = 3.0
    bad.loc[bad.index[1], "flag"] = "BOGUS"
    rep = validate_synthetic(real, bad, set(real["service"]))
    assert rep["invalid"] == 2
    assert rep["duplicates_of_real"] >= 8   # the other rows are copies of real rows
