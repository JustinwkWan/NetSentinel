"""LstmDetector — LSTM autoencoder anomaly detection for Phase 3.

The model learns the pattern of normal network flows. At inference time,
flows with high reconstruction error are flagged as anomalous.

Features extracted from each FlowRecord:
  packet_count, byte_count, duration, packet_rate, mean_packet_size,
  dst_port (log-scaled), src_port (log-scaled)
"""

from __future__ import annotations

import math
from pathlib import Path

import torch
import torch.nn as nn

import config
from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord

# Feature order must match training
FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "duration",
    "packet_rate",
    "mean_packet_size",
    "dst_port",
    "src_port",
]
NUM_FEATURES = len(FEATURE_NAMES)


def extract_features(flow: FlowRecord) -> list[float]:
    """Extract numeric features from a FlowRecord for the LSTM."""
    return [
        float(flow.packet_count),
        float(flow.byte_count),
        float(flow.duration),
        flow.packet_rate,
        flow.mean_packet_size,
        math.log1p(flow.dst_port),
        math.log1p(flow.src_port),
    ]


class FlowLSTMAutoencoder(nn.Module):
    """LSTM autoencoder for flow-level anomaly detection.

    Encoder: processes the feature sequence with an LSTM, producing
    a fixed-size hidden state. Decoder: reconstructs the original
    feature sequence from that hidden state. Reconstruction error
    is used as the anomaly score.
    """

    def __init__(self, input_size: int = NUM_FEATURES, hidden_size: int = 32,
                 num_layers: int = 1):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        # Encoder: takes features as a sequence of length input_size, each of dim 1
        self.encoder = nn.LSTM(
            input_size=1,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
        )

        # Decoder: reconstructs the sequence
        self.decoder = nn.LSTM(
            input_size=1,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
        )

        # Output projection back to feature dim
        self.output_layer = nn.Linear(hidden_size, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass. x shape: (batch, seq_len, 1)."""
        # Encode
        _, (hidden, cell) = self.encoder(x)

        # Decode: use encoder's final hidden state, feed zeros as input
        batch_size, seq_len, _ = x.shape
        decoder_input = torch.zeros(batch_size, seq_len, 1, device=x.device)
        decoder_output, _ = self.decoder(decoder_input, (hidden, cell))

        # Project back
        reconstruction = self.output_layer(decoder_output)
        return reconstruction


class LstmDetector:
    """Flags flows using an LSTM autoencoder's reconstruction error.

    Satisfies the Detector Protocol: flag(flows) -> list[FlaggedFlow].
    """

    def __init__(self, model_path: str | Path | None = None,
                 threshold: float | None = None):
        self.model_path = Path(model_path or config.LSTM_MODEL_PATH)
        self.threshold = threshold or config.LSTM_ANOMALY_THRESHOLD
        self.device = torch.device("cpu")

        # Load model
        self.model = FlowLSTMAutoencoder()
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"LSTM model not found at {self.model_path}. "
                f"Train one first with: python scripts/train_lstm.py"
            )

        checkpoint = torch.load(self.model_path, map_location=self.device,
                                weights_only=True)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()

        # Use threshold from checkpoint if not explicitly provided
        if threshold is None and "threshold" in checkpoint:
            self.threshold = checkpoint["threshold"]

        # Load normalization stats from training
        self.feature_means = checkpoint["feature_means"]
        self.feature_stds = checkpoint["feature_stds"]

    def _normalize(self, features: list[float]) -> torch.Tensor:
        """Normalize features using training statistics."""
        t = torch.tensor(features, dtype=torch.float32)
        means = torch.tensor(self.feature_means, dtype=torch.float32)
        stds = torch.tensor(self.feature_stds, dtype=torch.float32)
        # Avoid division by zero
        stds = torch.clamp(stds, min=1e-8)
        return (t - means) / stds

    def _compute_anomaly_score(self, flow: FlowRecord) -> float:
        """Compute reconstruction error for a single flow."""
        features = extract_features(flow)
        normalized = self._normalize(features)

        # Shape: (1, seq_len, 1)
        x = normalized.unsqueeze(0).unsqueeze(-1)

        with torch.no_grad():
            reconstruction = self.model(x)

        # Mean squared error as anomaly score
        mse = torch.mean((x - reconstruction) ** 2).item()
        return mse

    def flag(self, flows: list[FlowRecord]) -> list[FlaggedFlow]:
        """Flag flows with reconstruction error above threshold."""
        flagged = []

        for flow in flows:
            score = self._compute_anomaly_score(flow)

            if score > self.threshold:
                # Normalize score to 0-1 range (sigmoid-like scaling)
                normalized_score = min(1.0, score / (score + self.threshold))

                flagged.append(
                    FlaggedFlow(
                        flow=flow,
                        anomaly_score=normalized_score,
                        reason=f"LSTM anomaly score {score:.4f} "
                               f"(threshold {self.threshold:.4f})",
                    )
                )

        return flagged
