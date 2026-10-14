"""LstmDetector - LSTM autoencoder over per-packet sequences.

Each flow becomes the time-ordered sequence of its first max_seq_len
packets. One step is one packet, described by STEP_FEATURES. The model
learns to reconstruct sequences of normal traffic, so flows it
reconstructs poorly are flagged.
"""

from __future__ import annotations

import math
from pathlib import Path

import torch
import torch.nn as nn
from torch.nn.utils.rnn import pack_padded_sequence, pad_sequence

import config
from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord

STEP_FEATURES = [
    "log_size", "log_gap", "direction", "is_tcp", "syn", "fin", "rst", "psh",
]
NUM_STEP_FEATURES = len(STEP_FEATURES)
# The leading features are unbounded and standardized with training
# statistics; the rest are already in [-1, 1].
NUM_STANDARDIZED = 2

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08

CHECKPOINT_FORMAT_VERSION = 2
DEFAULT_HIDDEN_SIZE = 32
DEFAULT_NUM_LAYERS = 1

NO_MODEL_MESSAGE = (
    "No compatible LSTM model. Collect training data with the dashboard's "
    "'Save windows for training' toggle, then run: python scripts/train_lstm.py"
)


class ModelNotTrainedError(RuntimeError):
    """No checkpoint, or one this detector version cannot use."""


def encode_flow(flow: FlowRecord, max_len: int) -> torch.Tensor:
    """Feature rows for the flow's first max_len packets: shape (n, 8)."""
    is_tcp = 1.0 if flow.protocol == "TCP" else 0.0
    rows = []
    prev_ts = None
    for pkt in flow.packets[:max_len]:
        gap = 0.0 if prev_ts is None else max(0.0, pkt.timestamp - prev_ts)
        prev_ts = pkt.timestamp
        flags = pkt.tcp_flags
        rows.append([
            math.log1p(pkt.length),
            math.log1p(gap),
            float(pkt.direction),
            is_tcp,
            float(bool(flags & TCP_SYN)),
            float(bool(flags & TCP_FIN)),
            float(bool(flags & TCP_RST)),
            float(bool(flags & TCP_PSH)),
        ])
    return torch.tensor(rows, dtype=torch.float32).reshape(-1, NUM_STEP_FEATURES)


def standardize(seq: torch.Tensor, means: list[float],
                stds: list[float]) -> torch.Tensor:
    """Standardize the unbounded leading features with training stats."""
    out = seq.clone()
    m = torch.tensor(means, dtype=torch.float32)
    s = torch.clamp(torch.tensor(stds, dtype=torch.float32), min=1e-8)
    out[:, :NUM_STANDARDIZED] = (out[:, :NUM_STANDARDIZED] - m) / s
    return out


def batch_sequences(
    seqs: list[torch.Tensor],
) -> tuple[torch.Tensor, torch.Tensor]:
    """Zero-pad to the longest sequence: x (B, T, 8) and lengths (B,)."""
    lengths = torch.tensor([len(s) for s in seqs], dtype=torch.long)
    return pad_sequence(seqs, batch_first=True), lengths


def sequence_errors(x: torch.Tensor, recon: torch.Tensor,
                    lengths: torch.Tensor) -> torch.Tensor:
    """Mean squared error per sequence over its real steps only: (B,)."""
    steps = torch.arange(x.size(1), device=x.device)
    mask = (steps[None, :] < lengths[:, None].to(x.device)).float()
    step_err = ((x - recon) ** 2).mean(dim=2)
    return (step_err * mask).sum(dim=1) / lengths.to(x.device).float()


class FlowLSTMAutoencoder(nn.Module):
    """Encoder LSTM reads a packet sequence into a fixed-size state; the
    decoder LSTM rebuilds the sequence from that state alone."""

    def __init__(self, input_size: int = NUM_STEP_FEATURES,
                 hidden_size: int = DEFAULT_HIDDEN_SIZE,
                 num_layers: int = DEFAULT_NUM_LAYERS):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.encoder = nn.LSTM(input_size=input_size, hidden_size=hidden_size,
                               num_layers=num_layers, batch_first=True)
        # The decoder is driven only by the encoder state; its input is zeros.
        self.decoder = nn.LSTM(input_size=1, hidden_size=hidden_size,
                               num_layers=num_layers, batch_first=True)
        self.output_layer = nn.Linear(hidden_size, input_size)

    def forward(self, x: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        """x: (B, T, input_size), lengths: (B,). Returns (B, T, input_size)."""
        packed = pack_padded_sequence(x, lengths.cpu(), batch_first=True,
                                      enforce_sorted=False)
        _, (hidden, cell) = self.encoder(packed)
        batch_size, seq_len, _ = x.shape
        decoder_input = torch.zeros(batch_size, seq_len, 1, device=x.device)
        decoder_output, _ = self.decoder(decoder_input, (hidden, cell))
        return self.output_layer(decoder_output)


def load_checkpoint(path: str | Path | None = None) -> dict:
    """Load a format 2 checkpoint, or raise ModelNotTrainedError."""
    path = Path(path or config.LSTM_MODEL_PATH)
    if not path.exists():
        raise ModelNotTrainedError(NO_MODEL_MESSAGE)
    try:
        checkpoint = torch.load(path, map_location="cpu", weights_only=True)
    except Exception as e:
        raise ModelNotTrainedError(
            f"{NO_MODEL_MESSAGE} (could not read {path}: {e})"
        ) from e
    if (not isinstance(checkpoint, dict)
            or checkpoint.get("format_version") != CHECKPOINT_FORMAT_VERSION):
        raise ModelNotTrainedError(NO_MODEL_MESSAGE)
    return checkpoint


def model_status(path: str | Path | None = None) -> str | None:
    """None when a usable model exists, else the message explaining why not."""
    try:
        load_checkpoint(path)
    except ModelNotTrainedError as e:
        return str(e)
    return None


class LstmDetector:
    """Flags flows whose packet sequence the autoencoder reconstructs poorly.

    Satisfies the Detector Protocol: flag(flows) -> list[FlaggedFlow].
    """

    def __init__(self, model_path: str | Path | None = None,
                 threshold: float | None = None):
        checkpoint = load_checkpoint(model_path)
        self.model = FlowLSTMAutoencoder(
            hidden_size=checkpoint["hidden_size"],
            num_layers=checkpoint["num_layers"],
        )
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()
        self.max_seq_len = checkpoint["max_seq_len"]
        self.feature_means = checkpoint["feature_means"]
        self.feature_stds = checkpoint["feature_stds"]
        self.threshold = (
            threshold if threshold is not None else checkpoint["threshold"]
        )

    def score(self, flows: list[FlowRecord]) -> list[float]:
        """Reconstruction error per flow. Every flow must have packets."""
        seqs = [
            standardize(encode_flow(f, self.max_seq_len),
                        self.feature_means, self.feature_stds)
            for f in flows
        ]
        scores: list[float] = []
        batch_size = config.LSTM_SCORE_BATCH_SIZE
        for start in range(0, len(seqs), batch_size):
            x, lengths = batch_sequences(seqs[start:start + batch_size])
            with torch.no_grad():
                recon = self.model(x, lengths)
            scores.extend(sequence_errors(x, recon, lengths).tolist())
        return scores

    def flag(self, flows: list[FlowRecord]) -> list[FlaggedFlow]:
        # Flows assembled without packets (e.g. hand-built ones) cannot be scored
        scorable = [f for f in flows if f.packets]
        flagged = []
        for flow, score in zip(scorable, self.score(scorable)):
            if score > self.threshold:
                flagged.append(
                    FlaggedFlow(
                        flow=flow,
                        anomaly_score=min(1.0, score / (score + self.threshold)),
                        reason=f"LSTM sequence anomaly score {score:.4f} "
                               f"(threshold {self.threshold:.4f})",
                    )
                )
        return flagged
