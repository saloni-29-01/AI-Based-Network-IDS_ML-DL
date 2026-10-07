"""1D-CNN classifier (Keras 3 / TensorFlow), refactored from the original
``MulticlassPrediction.ipynb`` architecture.

TensorFlow is imported lazily so the rest of the application (dashboard,
classical models, replay) keeps working when TensorFlow is not installed;
the registry then reports the CNN as unavailable instead of crashing.
"""
from __future__ import annotations

import os
from pathlib import Path

import numpy as np

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")


def tensorflow_available() -> tuple[bool, str]:
    try:
        import tensorflow as tf  # noqa: F401
        return True, tf.__version__
    except Exception as exc:  # ImportError or DLL load failure on Windows
        return False, f"{type(exc).__name__}: {exc}"


def build_cnn(n_features: int, n_classes: int):
    from tensorflow import keras
    from tensorflow.keras import layers

    model = keras.Sequential([
        layers.Input(shape=(n_features, 1)),
        layers.Conv1D(32, 3, padding="same", activation="relu"),
        layers.MaxPooling1D(2),
        layers.Dropout(0.2),
        layers.Conv1D(64, 3, padding="same", activation="relu"),
        layers.MaxPooling1D(2),
        layers.Dropout(0.2),
        layers.Flatten(),
        layers.Dense(64, activation="relu"),
        layers.Dense(n_classes, activation="softmax"),
    ])
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    return model


class CNNClassifier:
    """Small sklearn-like wrapper: fit / predict_proba / save / load."""

    def __init__(self, epochs: int = 10, batch_size: int = 256, seed: int = 42):
        self.epochs = epochs
        self.batch_size = batch_size
        self.seed = seed
        self.model = None
        self.history: dict = {}

    def fit(self, X: np.ndarray, y: np.ndarray, X_val=None, y_val=None, n_classes=None):
        import tensorflow as tf
        from tensorflow import keras

        tf.keras.utils.set_random_seed(self.seed)
        n_classes = n_classes or int(y.max()) + 1
        self.model = build_cnn(X.shape[1], n_classes)
        cb = [keras.callbacks.EarlyStopping(monitor="val_loss", patience=2,
                                            restore_best_weights=True)]
        val = (X_val[..., None], y_val) if X_val is not None else None
        hist = self.model.fit(X[..., None], y, validation_data=val,
                              validation_split=0.0 if val else 0.1,
                              epochs=self.epochs, batch_size=self.batch_size,
                              callbacks=cb, verbose=2)
        self.history = {k: [float(v) for v in vals] for k, vals in hist.history.items()}
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("CNN not loaded")
        X = np.asarray(X, dtype=np.float32)
        if len(X) <= 64:
            # direct call is much faster than model.predict for tiny batches
            return np.asarray(self.model(X[..., None], training=False))
        return self.model.predict(X[..., None], batch_size=2048, verbose=0)

    def save(self, path: Path) -> None:
        self.model.save(path)

    @classmethod
    def load(cls, path: Path) -> "CNNClassifier":
        from tensorflow import keras
        obj = cls()
        obj.model = keras.models.load_model(path)
        return obj
