"""Fit-on-train / transform-everywhere preprocessing.

* categorical (protocol_type, service, flag) -> one-hot, unknown categories
  ignored (all-zero) rather than crashing;
* numeric -> ``log1p`` (the byte/count features are extremely heavy-tailed)
  followed by ``StandardScaler`` fitted on the TRAINING split only.

The fitted object is persisted next to each model so inference uses exactly
the transformation the model was trained with.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from app.features.schema import CATEGORICAL, FEATURE_SETS

PREPROCESSING_VERSION = "pp-2.0 (onehot+log1p+standard)"


def _log1p_nonneg(x):
    return np.log1p(np.clip(np.asarray(x, dtype=float), 0, None))


class Preprocessor:
    def __init__(self, feature_set: str = "full"):
        if feature_set not in FEATURE_SETS:
            raise ValueError(f"unknown feature_set {feature_set}")
        self.feature_set = feature_set
        self.features = list(FEATURE_SETS[feature_set])
        self.categorical = [c for c in CATEGORICAL if c in self.features]
        self.numeric = [c for c in self.features if c not in self.categorical]
        self.version = PREPROCESSING_VERSION
        self.ct: ColumnTransformer | None = None
        self.output_names: list[str] = []
        self.output_to_feature: list[str] = []
        self.categories: dict[str, list[str]] = {}
        self.numeric_max: dict[str, float] = {}

    def fit(self, df: pd.DataFrame) -> "Preprocessor":
        num_pipe = Pipeline([
            ("log1p", FunctionTransformer(_log1p_nonneg, feature_names_out="one-to-one")),
            ("scale", StandardScaler()),
        ])
        self.ct = ColumnTransformer([
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), self.categorical),
            ("num", num_pipe, self.numeric),
        ])
        self.ct.fit(df[self.features])
        enc: OneHotEncoder = self.ct.named_transformers_["cat"]
        self.categories = {c: [str(v) for v in cats] for c, cats in zip(self.categorical, enc.categories_)}
        self.output_names, self.output_to_feature = [], []
        for c, cats in self.categories.items():
            for v in cats:
                self.output_names.append(f"{c}={v}")
                self.output_to_feature.append(c)
        for c in self.numeric:
            self.output_names.append(c)
            self.output_to_feature.append(c)
        self.numeric_max = {c: float(df[c].max()) for c in self.numeric}
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if self.ct is None:
            raise RuntimeError("Preprocessor is not fitted")
        missing = [c for c in self.features if c not in df.columns]
        if missing:
            raise ValueError(f"Missing feature columns: {missing}")
        return self.ct.transform(df[self.features]).astype(np.float32)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.fit(df).transform(df)

    @property
    def n_outputs(self) -> int:
        return len(self.output_names)

    def aggregate_to_features(self, contrib: np.ndarray) -> dict[str, float]:
        """Sum per-output contributions back onto original feature names."""
        out: dict[str, float] = {}
        for name, val in zip(self.output_to_feature, contrib):
            out[name] = out.get(name, 0.0) + float(val)
        return out
