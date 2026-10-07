"""Quality validation for GAN-generated samples."""
from __future__ import annotations

import numpy as np
import pandas as pd

from app.features.schema import CATEGORICAL, FLAGS, PROTOCOLS, RATE_FEATURES


def _numeric(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c not in CATEGORICAL]


def validate_synthetic(real: pd.DataFrame, synth: pd.DataFrame,
                       known_services: set[str]) -> dict:
    """Range / validity / duplicate / distribution checks on synthetic rows."""
    num = _numeric(synth)
    n = len(synth)
    invalid_mask = np.zeros(n, dtype=bool)

    neg = (synth[num] < 0).any(axis=1).to_numpy()
    nan = synth[num].isna().any(axis=1).to_numpy()
    rate_bad = np.zeros(n, dtype=bool)
    for c in RATE_FEATURES:
        if c in synth:
            rate_bad |= (synth[c] > 1.0001).to_numpy()
    proto_bad = (~synth["protocol_type"].isin(PROTOCOLS)).to_numpy()
    flag_bad = (~synth["flag"].isin(FLAGS)).to_numpy()
    invalid_mask |= neg | nan | rate_bad | proto_bad | flag_bad

    # exact duplicates of real rows / internal duplicates
    key_cols = num + CATEGORICAL
    real_keys = set(map(tuple, real[key_cols].round(3).to_numpy()))
    syn_keys = list(map(tuple, synth[key_cols].round(3).to_numpy()))
    dup_real = np.array([k in real_keys for k in syn_keys])
    seen, dup_internal = set(), np.zeros(n, dtype=bool)
    for i, k in enumerate(syn_keys):
        if k in seen:
            dup_internal[i] = True
        seen.add(k)

    unseen_service = (~synth["service"].isin(known_services)).to_numpy()

    # distribution distance per numeric feature (normalised abs mean diff + std ratio)
    dist = {}
    for c in num:
        r, s = real[c].to_numpy(dtype=float), synth[c].to_numpy(dtype=float)
        scale = (abs(r.mean()) + r.std() + 1e-6)
        dist[c] = {
            "real_mean": round(float(r.mean()), 3), "synth_mean": round(float(s.mean()), 3),
            "real_std": round(float(r.std()), 3), "synth_std": round(float(s.std()), 3),
            "mean_diff_norm": round(float(abs(r.mean() - s.mean()) / scale), 3),
        }
    mean_diffs = [d["mean_diff_norm"] for d in dist.values()]
    valid = int((~invalid_mask).sum())
    # quality score: validity, low duplication, distribution closeness
    validity = valid / n if n else 0
    dup_rate = float((dup_real | dup_internal).sum()) / n if n else 0
    dist_score = max(0.0, 1.0 - float(np.mean(mean_diffs))) if mean_diffs else 0.0
    quality = round(100 * (0.5 * validity + 0.2 * (1 - dup_rate) + 0.3 * dist_score), 1)
    return {
        "generated": n,
        "valid": valid,
        "invalid": int(invalid_mask.sum()),
        "invalid_breakdown": {"negative": int(neg.sum()), "nan": int(nan.sum()),
                              "rate_gt_1": int(rate_bad.sum()), "bad_protocol": int(proto_bad.sum()),
                              "bad_flag": int(flag_bad.sum())},
        "duplicates_of_real": int(dup_real.sum()),
        "internal_duplicates": int(dup_internal.sum()),
        "unseen_service_rate": round(float(unseen_service.mean()), 3) if n else 0,
        "validity_rate": round(validity, 3),
        "duplicate_rate": round(dup_rate, 3),
        "distribution_closeness": round(dist_score, 3),
        "quality_score": quality,
        "feature_distribution": dist,
        "valid_mask": (~invalid_mask).tolist(),
    }
