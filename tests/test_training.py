"""Tests for LSTM training and training-data generation scripts."""

from __future__ import annotations

import copy
import random
import sys
from pathlib import Path

import pytest
import torch
from scapy.all import wrpcap

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.detection.lstm import FlowLSTMAutoencoder, LstmDetector
from scripts.generate_training_pcap import build_packet, generate_normal_traffic
from scripts.train_lstm import fit, train_model


class TestFit:
    def test_best_state_is_detached_from_live_weights(self):
        torch.manual_seed(0)
        model = FlowLSTMAutoencoder(hidden_size=8)
        x = torch.randn(40, 7, 1)

        best_state, _ = fit(model, x[:32], x[32:], epochs=2, batch_size=8,
                            learning_rate=1e-2)
        snapshot = copy.deepcopy(best_state)

        # Any later update to the model must not leak into the saved state.
        with torch.no_grad():
            for param in model.parameters():
                param.add_(1.0)

        for name, tensor in best_state.items():
            assert torch.equal(tensor, snapshot[name]), name

    def test_best_state_reproduces_best_val_loss(self):
        torch.manual_seed(0)
        model = FlowLSTMAutoencoder(hidden_size=8)
        x = torch.randn(40, 7, 1)
        train_x, val_x = x[:32], x[32:]

        best_state, best_val_loss = fit(model, train_x, val_x, epochs=5,
                                        batch_size=8, learning_rate=5e-2)

        model.load_state_dict(best_state)
        model.eval()
        with torch.no_grad():
            val_loss = torch.nn.MSELoss()(model(val_x), val_x).item()
        assert val_loss == pytest.approx(best_val_loss)


class TestCheckpointRoundTrip:
    def test_non_default_hidden_size_loads_in_detector(self, tmp_path):
        random.seed(0)
        torch.manual_seed(0)
        pcap = tmp_path / "normal.pcap"
        wrpcap(str(pcap), generate_normal_traffic(num_flows=30))
        model_path = tmp_path / "model.pt"

        train_model(str(pcap), output_path=str(model_path), epochs=2,
                    batch_size=8, hidden_size=8)

        detector = LstmDetector(model_path=model_path)
        assert detector.model.hidden_size == 8

    def test_explicit_zero_threshold_is_respected(self, tmp_path):
        model_path = tmp_path / "model.pt"
        torch.save({
            "model_state_dict": FlowLSTMAutoencoder().state_dict(),
            "feature_means": [0.0] * 7,
            "feature_stds": [1.0] * 7,
            "threshold": 9.0,
        }, model_path)

        assert LstmDetector(model_path=model_path, threshold=0.0).threshold == 0.0
        assert LstmDetector(model_path=model_path).threshold == 9.0


class TestBuildPacket:
    @pytest.mark.parametrize("proto", ["TCP", "UDP"])
    def test_frame_is_requested_size(self, proto):
        pkt = build_packet("10.0.0.1", "8.8.8.8", 50000, 53, proto, 300)
        assert len(pkt) == 300

    @pytest.mark.parametrize("proto, header_len", [("TCP", 54), ("UDP", 42)])
    def test_small_size_yields_bare_headers(self, proto, header_len):
        pkt = build_packet("10.0.0.1", "8.8.8.8", 50000, 53, proto, 10)
        assert len(pkt) == header_len
