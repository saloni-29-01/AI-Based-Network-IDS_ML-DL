"""Pre-inference validation of feature records."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

import pandas as pd

from app.features.schema import (CATEGORICAL, FEATURE_SETS, FLAGS, PROTOCOLS,
                                 RATE_FEATURES)


class FeatureValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass
class ValidationReport:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_record(record: dict, feature_set: str = "full",
                    known_services: set[str] | None = None,
                    allow_extra: bool = True) -> ValidationReport:
    """Validate a single raw (un-encoded) feature record.

    Errors make the record unusable (missing column, NaN/inf, non-numeric,
    negative counts). Warnings are recorded but inference still proceeds
    (unknown service -> one-hot all-zero, rate slightly out of range).
    """
    errors: list[str] = []
    warnings: list[str] = []
    features = FEATURE_SETS[feature_set]
    for col in features:
        if col not in record or record[col] is None:
            errors.append(f"missing feature '{col}'")
            continue
        val = record[col]
        if col in CATEGORICAL:
            sval = str(val)
            if col == "protocol_type" and sval not in PROTOCOLS:
                errors.append(f"protocol_type '{sval}' not supported (tcp/udp/icmp)")
            elif col == "flag" and sval not in FLAGS:
                errors.append(f"flag '{sval}' is not a valid NSL-KDD connection state")
            elif col == "service" and known_services and sval not in known_services:
                warnings.append(f"service '{sval}' unseen in training data")
            continue
        try:
            fval = float(val)
        except (TypeError, ValueError):
            errors.append(f"feature '{col}' is not numeric ({val!r})")
            continue
        if math.isnan(fval) or math.isinf(fval):
            errors.append(f"feature '{col}' is NaN/inf")
            continue
        if fval < 0:
            errors.append(f"feature '{col}' is negative ({fval})")
        if col in RATE_FEATURES and fval > 1.0001:
            errors.append(f"rate feature '{col}' > 1 ({fval})")
    if not allow_extra:
        extra = [k for k in record if k not in features]
        if extra:
            errors.append(f"unexpected columns: {extra}")
    return ValidationReport(ok=not errors, errors=errors, warnings=warnings)


def validate_frame(df: pd.DataFrame, feature_set: str = "full") -> ValidationReport:
    errors: list[str] = []
    features = FEATURE_SETS[feature_set]
    missing = [c for c in features if c not in df.columns]
    if missing:
        return ValidationReport(False, [f"missing columns: {missing}"])
    num = [c for c in features if c not in CATEGORICAL]
    numeric = df[num].apply(pd.to_numeric, errors="coerce")
    if numeric.isna().any().any():
        bad = numeric.columns[numeric.isna().any()].tolist()
        errors.append(f"NaN / non-numeric values in {bad}")
    if (numeric < 0).any().any():
        errors.append("negative values present")
    return ValidationReport(not errors, errors)
