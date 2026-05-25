"""Detector Protocol and FlaggedFlow data object."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from netsentinel.ingestion.flows import FlowRecord


@dataclass
class FlaggedFlow:
    """A flow that has been flagged as anomalous by a detector."""

    flow: FlowRecord
    anomaly_score: float  # 0.0 to 1.0
    reason: str


@runtime_checkable
class Detector(Protocol):
    """Interface for anomaly detectors."""

    def flag(self, flows: list[FlowRecord]) -> list[FlaggedFlow]: ...
