"""Train the LSTM autoencoder on normal traffic for anomaly detection."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

import config
from netsentinel.detection.lstm import (
    FlowLSTMAutoencoder,
    extract_features,
)
from netsentinel.ingestion.sources import PcapFileSource, process_packets


def train_model(
    pcap_path: str,
    output_path: str | None = None,
    epochs: int = 50,
    batch_size: int = 32,
    learning_rate: float = 1e-3,
    hidden_size: int = 32,
) -> None:
    """Train the LSTM autoencoder on flows from a normal traffic PCAP."""
    output_path = output_path or str(config.LSTM_MODEL_PATH)

    # Load and assemble flows
    print(f"[*] Loading PCAP: {pcap_path}")
    source = PcapFileSource(pcap_path)
    flows = process_packets(source)
    print(f"[*] Assembled {len(flows)} flows")

    if len(flows) < 10:
        print("[!] Too few flows for training. Need at least 10.")
        sys.exit(1)

    # Extract features
    print("[*] Extracting features...")
    all_features = [extract_features(f) for f in flows]
    feature_tensor = torch.tensor(all_features, dtype=torch.float32)

    # Compute normalization statistics
    feature_means = feature_tensor.mean(dim=0).tolist()
    feature_stds = feature_tensor.std(dim=0).tolist()

    # Normalize
    means_t = torch.tensor(feature_means, dtype=torch.float32)
    stds_t = torch.tensor(feature_stds, dtype=torch.float32)
    stds_t = torch.clamp(stds_t, min=1e-8)
    normalized = (feature_tensor - means_t) / stds_t

    # Shape for LSTM: (batch, seq_len, 1) — each feature is a timestep
    x = normalized.unsqueeze(-1)

    # Train/val split (90/10)
    n = len(x)
    n_train = int(0.9 * n)
    train_x = x[:n_train]
    val_x = x[n_train:]

    train_dataset = TensorDataset(train_x, train_x)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    # Build model
    model = FlowLSTMAutoencoder(hidden_size=hidden_size)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()

    print(f"[*] Training LSTM autoencoder ({n_train} train, {n - n_train} val)...")
    print(f"    Epochs: {epochs}, Batch size: {batch_size}, LR: {learning_rate}")

    best_val_loss = float("inf")
    best_state = None

    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0.0
        for batch_x, batch_target in train_loader:
            optimizer.zero_grad()
            reconstruction = model(batch_x)
            loss = criterion(reconstruction, batch_target)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch_x.size(0)
        train_loss /= n_train

        # Validation
        model.eval()
        with torch.no_grad():
            val_reconstruction = model(val_x)
            val_loss = criterion(val_reconstruction, val_x).item()

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = model.state_dict()

        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"    Epoch {epoch + 1:3d}/{epochs}: "
                  f"train_loss={train_loss:.6f}, val_loss={val_loss:.6f}")

    # Compute threshold from training data reconstruction errors
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        train_reconstruction = model(train_x)
        per_sample_mse = torch.mean((train_x - train_reconstruction) ** 2, dim=(1, 2))
        mean_error = per_sample_mse.mean().item()
        std_error = per_sample_mse.std().item()
        # Threshold: mean + 3 standard deviations
        suggested_threshold = mean_error + 3 * std_error

    print(f"\n[*] Training complete.")
    print(f"    Best val loss: {best_val_loss:.6f}")
    print(f"    Mean reconstruction error: {mean_error:.6f}")
    print(f"    Suggested threshold: {suggested_threshold:.6f}")

    # Save checkpoint
    save_path = Path(output_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model_state_dict": best_state,
            "feature_means": feature_means,
            "feature_stds": feature_stds,
            "threshold": suggested_threshold,
            "train_loss": best_val_loss,
            "epochs": epochs,
        },
        str(save_path),
    )
    print(f"[*] Model saved to {save_path}")
    print(f"\n    To use: python -m netsentinel.cli <pcap> --detector lstm")
    print(f"    Suggested config: LSTM_ANOMALY_THRESHOLD = {suggested_threshold:.6f}")


def main():
    parser = argparse.ArgumentParser(
        description="Train the LSTM anomaly detector on normal traffic"
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default=str(config.PCAP_DIR / "normal_traffic.pcap"),
        help="Path to a PCAP of normal traffic (default: data/pcaps/normal_traffic.pcap)",
    )
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--hidden-size", type=int, default=32)
    parser.add_argument("--output", default=None, help="Model output path")
    args = parser.parse_args()

    train_model(
        pcap_path=args.pcap,
        output_path=args.output,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        hidden_size=args.hidden_size,
    )


if __name__ == "__main__":
    main()
