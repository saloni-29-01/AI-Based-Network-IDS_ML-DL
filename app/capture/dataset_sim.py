"""NSL-KDD dataset simulation: KDDTest+ records are replayed one by one
through preprocessing -> 41-feature models -> risk -> alerts -> dashboard.

The records are benchmark connection summaries, not live traffic; they carry
no IP addresses, and the UI labels this mode "DATASET SIMULATION". Because
ground truth is known, a running accuracy is shown alongside.
"""
from __future__ import annotations

from app.capture.base import SourceBase
from app.features.schema import FULL_FEATURES
from app.preprocessing.dataset import load_split
from app.utils.logging_setup import get_logger

log = get_logger("datasim")


class DatasetSimulationSource(SourceBase):
    mode = "dataset"
    label = "Dataset Simulation (NSL-KDD KDDTest+)"

    def __init__(self, engine, rate: float = 25.0, speed: float = 1.0, split: str = "test",
                 shuffle: bool = True, seed: int = 7, limit: int | None = None):
        super().__init__(engine, speed)
        self.rate = rate
        self.split = split
        df = load_split(split)
        if shuffle:
            df = df.sample(frac=1.0, random_state=seed)
        self.df = df if limit is None else df.head(limit)
        self.label = f"Dataset Simulation (NSL-KDD {split})"

    def run(self) -> None:
        total = len(self.df)
        self.progress = {"split": self.split, "total_records": total, "processed": 0, "percent": 0.0}
        log.info(f"dataset simulation start split={self.split} records={total} rate={self.rate}/s x{self.speed}")
        batch = []
        for i, (idx, row) in enumerate(self.df.iterrows(), 1):
            if self._stop.is_set():
                break
            rec = {c: row[c] for c in FULL_FEATURES}
            batch.append((rec, {"record_ref": f"{self.split}#{idx}", "ground_truth": row["category"],
                                "raw_label": row["label"], "protocol": row["protocol_type"],
                                "service": row["service"], "flag": row["flag"]}))
            interval = 1.0 / (self.rate * self.speed)
            # submit in small groups to keep queue overhead low at high speed
            if len(batch) >= max(1, int(self.rate * self.speed / 10)):
                for rec_, meta in batch:
                    self.engine.submit_record("dataset", "full", rec_, meta)
                batch.clear()
                if not self._wait(interval * max(1, int(self.rate * self.speed / 10))):
                    break
            self.progress.update(processed=i, percent=round(100 * i / total, 2))
        for rec_, meta in batch:
            self.engine.submit_record("dataset", "full", rec_, meta)
        log.info(f"dataset simulation end processed={self.progress['processed']}")
