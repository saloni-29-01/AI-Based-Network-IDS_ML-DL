"""Pydantic request/response schemas for the API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PredictRequest(BaseModel):
    records: list[dict[str, Any]] = Field(..., description="Raw NSL-KDD feature records")
    feature_set: str = Field("full", pattern="^(full|flow)$")
    explain: bool = True


class SimStartRequest(BaseModel):
    split: str = Field("test", pattern="^(train|train20|test|test21)$")
    rate: float = Field(25.0, gt=0, le=20000)
    speed: float = Field(1.0, gt=0, le=100)
    limit: int | None = Field(None, ge=1)
    shuffle: bool = True


class ReplayStartRequest(BaseModel):
    file: str | None = Field(None, description="PCAP filename under data/pcaps (default: bundled benign capture)")
    speed: float = Field(1.0, gt=0, le=100)
    max_gap: float = Field(1.0, ge=0, le=10)


class FlowReplayStartRequest(BaseModel):
    file: str | None = None
    rate: float = Field(25.0, gt=0, le=20000)
    speed: float = Field(1.0, gt=0, le=100)
    limit: int | None = Field(None, ge=1)


class CaptureStartRequest(BaseModel):
    interface: str | None = None
    bpf_filter: str = "ip"


class SpeedRequest(BaseModel):
    speed: float = Field(..., gt=0, le=100)


class AlertStatusRequest(BaseModel):
    status: str = Field(..., pattern="^(New|Investigating|Resolved|Ignored)$")


class GanTrainRequest(BaseModel):
    classes: list[str] | None = None
    per_class: int | None = Field(None, ge=1, le=100000)
    epochs: int = Field(60, ge=1, le=500)
    retrain: bool = True
