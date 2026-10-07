"""NSL-KDD loading utilities (the single source of truth for reading the data)."""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd

from app.config import settings
from app.features.schema import (ATTACK_CATEGORY, LABEL_COLUMNS, NSL_KDD_COLUMNS)

SPLITS = {
    "train": "KDDTrain+.txt",
    "train20": "KDDTrain+_20Percent.txt",
    "test": "KDDTest+.txt",
    "test21": "KDDTest-21.txt",
}


class DatasetMissingError(FileNotFoundError):
    pass


def dataset_path(split: str) -> Path:
    if split not in SPLITS:
        raise ValueError(f"Unknown split {split!r}; expected one of {sorted(SPLITS)}")
    return settings.nsl_kdd_dir / SPLITS[split]


def file_sha1(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


@lru_cache(maxsize=8)
def load_split(split: str) -> pd.DataFrame:
    """Load one NSL-KDD split with named columns plus ``category`` and ``binary``."""
    path = dataset_path(split)
    if not path.is_file():
        raise DatasetMissingError(
            f"NSL-KDD file not found: {path}. Place the dataset in {settings.nsl_kdd_dir}.")
    df = pd.read_csv(path, names=NSL_KDD_COLUMNS + LABEL_COLUMNS)
    for col in ("protocol_type", "service", "flag", "label"):
        df[col] = df[col].astype(str)
    unknown = sorted(set(df["label"]) - set(ATTACK_CATEGORY))
    if unknown:
        raise ValueError(f"Unmapped NSL-KDD labels in {split}: {unknown}")
    df["category"] = df["label"].map(ATTACK_CATEGORY)
    df["binary"] = np.where(df["label"] == "normal", "normal", "attack")
    return df


def dataset_version() -> str:
    """Short fingerprint of the train/test files so model metadata pins its data."""
    parts = []
    for split in ("train", "test"):
        p = dataset_path(split)
        parts.append(f"{split}:{file_sha1(p) if p.is_file() else 'missing'}")
    return "NSL-KDD[" + ",".join(parts) + "]"
