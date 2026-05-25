"""Tests for detection layer: StubDetector and LstmDetector."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from netsentinel.detection.base import Detector, FlaggedFlow
from netsentinel.detection.stub import StubDetector
from netsentinel.ingestion.flows import FlowRecord


def _make_flow(**overrides) -> FlowRecord:
    """Create a FlowRecord with sensible defaults."""
    defaults = {
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.1",
        "src_port": 50000,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 10,
        "byte_count": 5000,
        "duration": 5.0,
        "start_time": 1000000.0,
    }
    defaults.update(overrides)
    return FlowRecord(**defaults)


class TestStubDetector:
    def test_satisfies_protocol(self):
        assert isinstance(StubDetector(), Detector)

    def test_normal_flow_not_flagged(self):
        flow = _make_flow(dst_port=80, packet_count=10, duration=5.0, byte_count=5000)
        flagged = StubDetector().flag([flow])
        assert flagged == []

    def test_suspicious_port_flagged(self):
        flow = _make_flow(dst_port=4444)
        flagged = StubDetector().flag([flow])
        assert len(flagged) == 1
        assert flagged[0].anomaly_score == 0.8
        assert "4444" in flagged[0].reason

    def test_high_packet_rate_flagged(self):
        flow = _make_flow(packet_count=5001, duration=5.0)
        flagged = StubDetector().flag([flow])
        assert len(flagged) == 1
        assert "packet rate" in flagged[0].reason

    def test_high_byte_rate_flagged(self):
        flow = _make_flow(byte_count=6_000_000, duration=5.0)
        flagged = StubDetector().flag([flow])
        assert len(flagged) == 1
        assert "byte rate" in flagged[0].reason

    def test_multiple_reasons(self):
        flow = _make_flow(dst_port=4444, packet_count=10000, duration=5.0)
        flagged = StubDetector().flag([flow])
        assert len(flagged) == 1
        assert "4444" in flagged[0].reason
        assert "packet rate" in flagged[0].reason

    def test_returns_flagged_flow_objects(self):
        flow = _make_flow(dst_port=4444)
        flagged = StubDetector().flag([flow])
        assert isinstance(flagged[0], FlaggedFlow)
        assert flagged[0].flow is flow


class TestLstmDetector:
    @pytest.fixture(autouse=True)
    def skip_if_no_model(self):
        if not config.LSTM_MODEL_PATH.exists():
            pytest.skip("LSTM model not trained yet")

    def test_satisfies_protocol(self):
        from netsentinel.detection.lstm import LstmDetector
        assert isinstance(LstmDetector(), Detector)

    def test_normal_flow_not_flagged(self):
        from netsentinel.detection.lstm import LstmDetector
        flow = _make_flow(dst_port=80, packet_count=10, duration=5.0, byte_count=5000)
        flagged = LstmDetector().flag([flow])
        assert flagged == []

    def test_anomalous_flow_flagged(self):
        from netsentinel.detection.lstm import LstmDetector
        # Extreme values: very high packet count, zero duration
        flow = _make_flow(
            dst_port=4444, packet_count=100000, duration=0.01,
            byte_count=50_000_000,
        )
        flagged = LstmDetector().flag([flow])
        assert len(flagged) == 1
        assert flagged[0].anomaly_score > 0.5
        assert "LSTM" in flagged[0].reason

    def test_returns_flagged_flow_objects(self):
        from netsentinel.detection.lstm import LstmDetector
        flow = _make_flow(
            dst_port=31337, packet_count=100000, duration=0.01,
            byte_count=50_000_000,
        )
        flagged = LstmDetector().flag([flow])
        if flagged:
            assert isinstance(flagged[0], FlaggedFlow)
            assert flagged[0].flow is flow

    def test_missing_model_raises(self, tmp_path):
        from netsentinel.detection.lstm import LstmDetector
        with pytest.raises(FileNotFoundError):
            LstmDetector(model_path=tmp_path / "nonexistent.pt")
