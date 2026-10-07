"""Test configuration.

Points the app at a throw-away SQLite database BEFORE any app module is
imported, so tests never touch the demo database. Trained models are read
from the real models/ directory; model-dependent tests skip if absent.
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp(prefix="ids-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_TMP) / 'test.db'}"
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ.setdefault("LOG_LEVEL", "WARNING")

import pytest  # noqa: E402

from app.config import settings  # noqa: E402


def models_trained() -> bool:
    return (settings.model_dir / "registry.json").is_file()


requires_models = pytest.mark.skipif(not models_trained(),
                                     reason="models not trained (python scripts/train_models.py)")


@pytest.fixture
def tmp_dir():
    return Path(tempfile.mkdtemp(prefix="ids-case-"))


@pytest.fixture
def full_record():
    """A real KDDTest+ record (first row of the split)."""
    from app.features.schema import FULL_FEATURES
    from app.preprocessing.dataset import load_split
    row = load_split("test").iloc[0]
    # native Python types, as a real JSON client would send
    return {c: (row[c].item() if hasattr(row[c], "item") else row[c]) for c in FULL_FEATURES}
