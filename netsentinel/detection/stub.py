"""StubDetector — rule-based anomaly detection for Phase 1."""

from __future__ import annotations

import config
from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord


class StubDetector:
    """Flags flows by transparent rules so the agent has something real to investigate."""

    def flag(self, flows: list[FlowRecord]) -> list[FlaggedFlow]:
        flagged = []
        for flow in flows:
            reasons = []
            score = 0.0

            if flow.dst_port in config.STUB_SUSPICIOUS_PORTS:
                reasons.append(f"suspicious destination port {flow.dst_port}")
                score = max(score, 0.8)

            if flow.packet_rate > config.STUB_HIGH_PACKET_RATE:
                reasons.append(
                    f"high packet rate ({flow.packet_rate:.0f} pps)"
                )
                score = max(score, 0.7)

            byte_rate = (
                flow.byte_count / flow.duration if flow.duration > 0 else 0.0
            )
            if byte_rate > config.STUB_HIGH_BYTE_RATE:
                reasons.append(f"high byte rate ({byte_rate:.0f} B/s)")
                score = max(score, 0.6)

            if reasons:
                flagged.append(
                    FlaggedFlow(
                        flow=flow,
                        anomaly_score=score,
                        reason="; ".join(reasons),
                    )
                )

        return flagged
