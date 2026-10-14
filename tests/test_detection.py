"""Tests for the sequence LSTM detector."""

from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.detection.base import Detector, FlaggedFlow
from netsentinel.detection.lstm import (
    CHECKPOINT_FORMAT_VERSION,
    NO_MODEL_MESSAGE,
    NUM_STANDARDIZED,
    FlowLSTMAutoencoder,
    LstmDetector,
    ModelNotTrainedError,
    batch_sequences,
    encode_flow,
    model_status,
    sequence_errors,
)
from netsentinel.ingestion.flows import FlowRecord, PacketRecord


def _flow(packets: list[PacketRecord], protocol: str = "TCP") -> FlowRecord:
    return FlowRecord("10.0.0.1", "1.1.1.1", 50000, 443, protocol,
                      len(packets), sum(p.length for p in packets), 1.0,
                      packets[0].timestamp if packets else 0.0, packets=packets)


def _handshake() -> list[PacketRecord]:
    return [PacketRecord(10.0, 74, 1, 0x02), PacketRecord(10.5, 74, -1, 0x12),
            PacketRecord(10.5, 66, 1, 0x10)]


def _save_checkpoint(path: Path, threshold: float = 1.0, **overrides) -> None:
    torch.manual_seed(0)
    model = FlowLSTMAutoencoder(hidden_size=8)
    checkpoint = {
        "format_version": CHECKPOINT_FORMAT_VERSION,
        "model_state_dict": model.state_dict(),
        "hidden_size": 8,
        "num_layers": 1,
        "max_seq_len": 32,
        "feature_means": [0.0] * NUM_STANDARDIZED,
        "feature_stds": [1.0] * NUM_STANDARDIZED,
        "threshold": threshold,
    }
    checkpoint.update(overrides)
    torch.save(checkpoint, path)


class TestEncodeFlow:
    def test_features_of_known_packets(self):
        rows = encode_flow(_flow(_handshake()), max_len=32)
        assert rows.shape == (3, 8)
        assert rows[0].tolist() == pytest.approx(
            [math.log1p(74), 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0])
        assert rows[1].tolist() == pytest.approx(
            [math.log1p(74), math.log1p(0.5), -1.0, 1.0, 1.0, 0.0, 0.0, 0.0])

    def test_udp_has_no_tcp_bits(self):
        rows = encode_flow(_flow([PacketRecord(1.0, 80, 1, 0)], "UDP"), max_len=32)
        assert rows[0, 3:].tolist() == [0.0] * 5

    def test_truncates_to_max_len(self):
        pkts = [PacketRecord(float(i), 100, 1, 0) for i in range(50)]
        assert encode_flow(_flow(pkts), max_len=32).shape == (32, 8)

    def test_out_of_order_timestamp_gap_is_zero(self):
        pkts = [PacketRecord(5.0, 100, 1, 0), PacketRecord(4.0, 100, -1, 0)]
        assert encode_flow(_flow(pkts), max_len=32)[1, 1].item() == 0.0


class TestMasking:
    def test_padding_does_not_change_a_flows_error(self):
        torch.manual_seed(0)
        model = FlowLSTMAutoencoder(hidden_size=8).eval()
        short = torch.randn(3, 8)
        long = torch.randn(20, 8)

        with torch.no_grad():
            x1, l1 = batch_sequences([short])
            alone = sequence_errors(x1, model(x1, l1), l1)[0]
            x2, l2 = batch_sequences([short, long])
            padded = sequence_errors(x2, model(x2, l2), l2)[0]

        assert padded.item() == pytest.approx(alone.item(), rel=1e-5)


class TestCheckpointLoading:
    def test_missing_checkpoint_raises_no_model(self, tmp_path):
        with pytest.raises(ModelNotTrainedError, match="Save windows for training"):
            LstmDetector(model_path=tmp_path / "missing.pt")

    def test_old_format_checkpoint_is_rejected(self, tmp_path):
        path = tmp_path / "old.pt"
        torch.save({"model_state_dict": {}, "feature_means": [0.0] * 7}, path)
        assert model_status(path) == NO_MODEL_MESSAGE

    def test_corrupt_checkpoint_is_rejected(self, tmp_path):
        path = tmp_path / "corrupt.pt"
        path.write_bytes(b"not a checkpoint")
        assert NO_MODEL_MESSAGE in model_status(path)

    def test_ready_checkpoint_has_no_status_message(self, tmp_path):
        path = tmp_path / "m.pt"
        _save_checkpoint(path)
        assert model_status(path) is None


class TestLstmDetector:
    def test_satisfies_protocol(self, tmp_path):
        path = tmp_path / "m.pt"
        _save_checkpoint(path)
        assert isinstance(LstmDetector(model_path=path), Detector)

    def test_threshold_controls_flagging(self, tmp_path):
        path = tmp_path / "m.pt"
        _save_checkpoint(path, threshold=1e6)  # far above any real error
        flow = _flow(_handshake())

        assert LstmDetector(model_path=path).flag([flow]) == []
        flagged = LstmDetector(model_path=path, threshold=0.0).flag([flow])
        assert len(flagged) == 1
        assert isinstance(flagged[0], FlaggedFlow)
        assert flagged[0].flow is flow
        assert 0.0 < flagged[0].anomaly_score <= 1.0
        assert "LSTM" in flagged[0].reason

    def test_flows_without_packets_are_skipped(self, tmp_path):
        path = tmp_path / "m.pt"
        _save_checkpoint(path)
        detector = LstmDetector(model_path=path, threshold=0.0)
        assert detector.flag([_flow([])]) == []

    def test_scores_match_across_batch_sizes(self, tmp_path, monkeypatch):
        path = tmp_path / "m.pt"
        _save_checkpoint(path)
        flows = [_flow([PacketRecord(float(j), 100 + i, 1, 0) for j in range(1 + i % 7)])
                 for i in range(10)]
        detector = LstmDetector(model_path=path)
        expected = detector.score(flows)
        monkeypatch.setattr("config.LSTM_SCORE_BATCH_SIZE", 3)
        assert detector.score(flows) == pytest.approx(expected, rel=1e-5)
