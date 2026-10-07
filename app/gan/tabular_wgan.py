"""Conditional WGAN-GP for tabular NSL-KDD augmentation.

Why this architecture:
  * WGAN-GP (Wasserstein GAN with gradient penalty) trains stably on
    tabular data and gives a meaningful loss curve (critic Wasserstein
    estimate), unlike vanilla GAN which mode-collapses easily here;
  * *conditional* on attack class, so we can request synthetic samples for
    a specific minority class (R2L, U2R);
  * mixed-type output head: numeric features use tanh (data is min-max
    scaled to [-1, 1]); each categorical column (protocol_type, service,
    flag) has its own softmax head, kept differentiable with a
    Gumbel-softmax during training and argmax-decoded at sampling time.

This is a genuine generator trained by adversarial optimisation - not noise
and not resampling. Synthetic samples are validated before use (range,
duplicates, categorical validity, distribution distance).

TensorFlow is imported lazily so importing this module never fails when TF
is absent; ``gan_available()`` reports the real state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from app.features.schema import CATEGORICAL, FULL_FEATURES
from app.utils.logging_setup import get_logger

log = get_logger("gan")


def gan_available() -> tuple[bool, str]:
    try:
        import tensorflow as tf  # noqa: F401
        return True, tf.__version__
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


@dataclass
class ColumnSpec:
    numeric: list[str]
    categories: dict[str, list[str]]
    num_min: np.ndarray
    num_max: np.ndarray

    @property
    def cat_dims(self) -> list[int]:
        return [len(v) for v in self.categories.values()]

    @property
    def output_dim(self) -> int:
        return len(self.numeric) + sum(self.cat_dims)


class TabularTransform:
    """Encode NSL-KDD rows to the GAN's numeric+one-hot space and back."""

    def __init__(self, features: list[str] = FULL_FEATURES):
        self.features = features
        self.numeric = [c for c in features if c not in CATEGORICAL]
        self.categorical = [c for c in features if c in CATEGORICAL]
        self.spec: ColumnSpec | None = None

    def fit(self, df: pd.DataFrame) -> "TabularTransform":
        cats = {c: sorted(df[c].astype(str).unique().tolist()) for c in self.categorical}
        num = df[self.numeric].to_numpy(dtype=np.float64)
        num = np.log1p(np.clip(num, 0, None))
        self.spec = ColumnSpec(self.numeric, cats, num.min(axis=0), num.max(axis=0))
        return self

    def encode(self, df: pd.DataFrame) -> np.ndarray:
        s = self.spec
        num = np.log1p(np.clip(df[self.numeric].to_numpy(dtype=np.float64), 0, None))
        rng = np.where(s.num_max > s.num_min, s.num_max - s.num_min, 1.0)
        num = 2 * (num - s.num_min) / rng - 1.0
        parts = [num]
        for c in self.categorical:
            idx = {v: i for i, v in enumerate(s.categories[c])}
            codes = df[c].astype(str).map(lambda v: idx.get(v, 0)).to_numpy()
            oh = np.zeros((len(df), len(s.categories[c])), dtype=np.float64)
            oh[np.arange(len(df)), codes] = 1.0
            parts.append(oh)
        return np.hstack(parts).astype(np.float32)

    def decode(self, arr: np.ndarray) -> pd.DataFrame:
        s = self.spec
        n_num = len(self.numeric)
        num = np.clip(arr[:, :n_num], -1, 1)
        rng = np.where(s.num_max > s.num_min, s.num_max - s.num_min, 1.0)
        num = (num + 1.0) / 2.0 * rng + s.num_min
        num = np.expm1(num)
        data = {c: num[:, i] for i, c in enumerate(self.numeric)}
        off = n_num
        for c in self.categorical:
            dim = len(s.categories[c])
            choice = arr[:, off:off + dim].argmax(axis=1)
            data[c] = [s.categories[c][k] for k in choice]
            off += dim
        df = pd.DataFrame(data)[self.features]
        from app.features.schema import INTEGER_FEATURES, RATE_FEATURES
        for c in self.numeric:
            if c in INTEGER_FEATURES:
                df[c] = np.rint(np.clip(df[c], 0, None)).astype(np.int64)
            elif c in RATE_FEATURES:
                df[c] = np.clip(df[c], 0.0, 1.0).round(2)
            else:
                df[c] = np.clip(df[c], 0, None)
        return df


@dataclass
class GANTrainResult:
    loss_curve: list[dict] = field(default_factory=list)
    epochs: int = 0
    classes: list[str] = field(default_factory=list)
    seconds: float = 0.0


class ConditionalWGANGP:
    def __init__(self, transform: TabularTransform, classes: list[str], noise_dim: int = 64,
                 critic_steps: int = 3, gp_weight: float = 10.0, seed: int = 42):
        self.transform = transform
        self.classes = classes
        self.noise_dim = noise_dim
        self.critic_steps = critic_steps
        self.gp_weight = gp_weight
        self.seed = seed
        self.gen = None
        self.critic = None
        self.cat_dims = transform.spec.cat_dims
        self.num_dim = len(transform.numeric)
        self.out_dim = transform.spec.output_dim

    # -------- model builders
    def _build(self):
        from tensorflow import keras
        from tensorflow.keras import layers

        n_cls = len(self.classes)
        z = keras.Input(shape=(self.noise_dim,))
        c = keras.Input(shape=(n_cls,))
        h = layers.Concatenate()([z, c])
        h = layers.Dense(128, activation="relu")(h)
        h = layers.BatchNormalization()(h)
        h = layers.Dense(128, activation="relu")(h)
        # pre-activation outputs; tanh is applied exactly once in _activate()
        num_out = layers.Dense(self.num_dim, name="num")(h)
        outs = [num_out]
        for i, dim in enumerate(self.cat_dims):
            outs.append(layers.Dense(dim, name=f"cat{i}")(h))  # logits
        self.gen = keras.Model([z, c], layers.Concatenate()(outs) if len(outs) > 1 else outs[0])

        x = keras.Input(shape=(self.out_dim,))
        cc = keras.Input(shape=(n_cls,))
        d = layers.Concatenate()([x, cc])
        d = layers.Dense(128, activation="leaky_relu")(d)
        d = layers.Dropout(0.2)(d)
        d = layers.Dense(128, activation="leaky_relu")(d)
        score = layers.Dense(1)(d)
        self.critic = keras.Model([x, cc], score)

    def _activate(self, raw):
        import tensorflow as tf
        num = tf.nn.tanh(raw[:, :self.num_dim])
        parts = [num]
        off = self.num_dim
        for dim in self.cat_dims:
            logits = raw[:, off:off + dim]
            g = -tf.math.log(-tf.math.log(tf.random.uniform(tf.shape(logits), 1e-6, 1.0)))
            parts.append(tf.nn.softmax((logits + g) / 0.5, axis=-1))  # gumbel-softmax
            off += dim
        return tf.concat(parts, axis=1)

    def fit(self, X: np.ndarray, y_onehot: np.ndarray, epochs: int = 60, batch_size: int = 128,
            progress=None) -> GANTrainResult:
        import time

        import tensorflow as tf
        tf.keras.utils.set_random_seed(self.seed)
        self._build()
        g_opt = tf.keras.optimizers.Adam(1e-4, beta_1=0.5, beta_2=0.9)
        c_opt = tf.keras.optimizers.Adam(1e-4, beta_1=0.5, beta_2=0.9)
        X = tf.convert_to_tensor(X, tf.float32)
        C = tf.convert_to_tensor(y_onehot, tf.float32)
        n = X.shape[0]
        res = GANTrainResult(classes=self.classes)
        t0 = time.time()

        @tf.function
        def critic_step(xr, cond):
            bs = tf.shape(xr)[0]
            z = tf.random.normal((bs, self.noise_dim))
            with tf.GradientTape() as tape:
                xf = self._activate(self.gen([z, cond], training=True))
                real = self.critic([xr, cond], training=True)
                fake = self.critic([xf, cond], training=True)
                eps = tf.random.uniform((bs, 1))
                xh = eps * xr + (1 - eps) * xf
                with tf.GradientTape() as gt:
                    gt.watch(xh)
                    sh = self.critic([xh, cond], training=True)
                grad = gt.gradient(sh, xh)
                gp = tf.reduce_mean((tf.norm(grad, axis=1) - 1.0) ** 2)
                loss = tf.reduce_mean(fake) - tf.reduce_mean(real) + self.gp_weight * gp
            g = tape.gradient(loss, self.critic.trainable_variables)
            c_opt.apply_gradients(zip(g, self.critic.trainable_variables))
            return tf.reduce_mean(real) - tf.reduce_mean(fake)  # Wasserstein estimate

        @tf.function
        def gen_step(cond):
            bs = tf.shape(cond)[0]
            z = tf.random.normal((bs, self.noise_dim))
            with tf.GradientTape() as tape:
                xf = self._activate(self.gen([z, cond], training=True))
                loss = -tf.reduce_mean(self.critic([xf, cond], training=True))
            g = tape.gradient(loss, self.gen.trainable_variables)
            g_opt.apply_gradients(zip(g, self.gen.trainable_variables))
            return loss

        # Class-balanced sampling: each batch draws classes uniformly, so the
        # conditional generator actually learns rare classes (U2R is 0.04% of
        # rows; with plain shuffling it would almost never be conditioned on).
        labels = np.asarray(y_onehot).argmax(axis=1)
        present = np.unique(labels)
        w = np.zeros(n)
        for k in present:
            w[labels == k] = 1.0 / (labels == k).sum() / len(present)
        rng = np.random.default_rng(self.seed)
        steps = max(1, n // batch_size)
        for ep in range(epochs):
            idx = tf.constant(rng.choice(n, size=steps * batch_size, replace=True, p=w))
            Xs, Cs = tf.gather(X, idx), tf.gather(C, idx)
            w_sum = g_sum = 0.0
            for s in range(steps):
                a, b = s * batch_size, (s + 1) * batch_size
                xr, cond = Xs[a:b], Cs[a:b]
                if tf.shape(xr)[0] < 2:
                    continue
                for _ in range(self.critic_steps):
                    w_sum += float(critic_step(xr, cond))
                g_sum += float(gen_step(cond))
            res.loss_curve.append({"epoch": ep + 1,
                                   "wasserstein": round(w_sum / (steps * self.critic_steps), 4),
                                   "generator_loss": round(g_sum / steps, 4)})
            if progress and (ep % 5 == 0 or ep == epochs - 1):
                progress(f"GAN epoch {ep+1}/{epochs} W={res.loss_curve[-1]['wasserstein']:.3f}")
        res.epochs = epochs
        res.seconds = round(time.time() - t0, 1)
        return res

    def generate(self, class_name: str, n: int, batch: int = 2048) -> pd.DataFrame:
        import tensorflow as tf
        ci = self.classes.index(class_name)
        rows = []
        done = 0
        while done < n:
            bs = min(batch, n - done)
            z = tf.random.normal((bs, self.noise_dim))
            cond = tf.one_hot([ci] * bs, len(self.classes))
            raw = self.gen([z, cond], training=False)
            rows.append(self._activate(raw).numpy())
            done += bs
        return self.transform.decode(np.vstack(rows))

    def save(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        self.gen.save(path / "generator.keras")
        import joblib
        joblib.dump({"transform": self.transform, "classes": self.classes,
                     "noise_dim": self.noise_dim}, path / "gan_meta.joblib")

    @classmethod
    def load(cls, path: Path) -> "ConditionalWGANGP":
        import joblib
        from tensorflow import keras
        meta = joblib.load(path / "gan_meta.joblib")
        obj = cls(meta["transform"], meta["classes"], noise_dim=meta["noise_dim"])
        obj._build()
        obj.gen = keras.models.load_model(path / "generator.keras", compile=False)
        return obj
