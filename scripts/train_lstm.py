"""Train the sequence LSTM autoencoder on captured normal traffic.

By default trains on every pcap in data/training/, which the dashboard's
'Save windows for training' toggle fills during live capture.
"""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import torch
from torch.utils.data import DataLoader, TensorDataset

import config
from netsentinel.detection.lstm import (
    CHECKPOINT_FORMAT_VERSION,
    DEFAULT_HIDDEN_SIZE,
    NUM_STANDARDIZED,
    FlowLSTMAutoencoder,
    batch_sequences,
    encode_flow,
    sequence_errors,
    standardize,
)
from netsentinel.ingestion.flows import FlowRecord
from netsentinel.ingestion.sources import PCAP_SUFFIXES, PcapFileSource, process_packets

COLLECT_HINT = (
    "Start a live capture in the dashboard with 'Save windows for training' "
    f"turned on to collect normal traffic into {config.TRAINING_DIR}."
)


class TrainingDataError(RuntimeError):
    """The training data is missing or too small to train on."""


def find_pcaps(paths: list[str | Path]) -> list[Path]:
    """Expand files and directories into pcap files, in a stable order."""
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found.extend(sorted(
                p for p in path.iterdir()
                if p.is_file() and p.suffix.lower() in PCAP_SUFFIXES
            ))
        elif path.is_file() and path.suffix.lower() in PCAP_SUFFIXES:
            found.append(path)
    return found


def is_excluded(flow: FlowRecord) -> bool:
    """Flows that must never be learned as normal traffic."""
    return (flow.src_port in config.TRAINING_EXCLUDE_PORTS
            or flow.dst_port in config.TRAINING_EXCLUDE_PORTS)


def fit(
    model: FlowLSTMAutoencoder,
    train_x: torch.Tensor,
    train_len: torch.Tensor,
    val_x: torch.Tensor,
    val_len: torch.Tensor,
    epochs: int,
    batch_size: int,
    learning_rate: float,
) -> tuple[dict[str, torch.Tensor], float]:
    """Train the autoencoder and return (best_state, best_val_loss).

    best_state is a detached copy: state_dict() returns references to the
    live parameters, which later optimizer steps would silently overwrite.
    """
    loader = DataLoader(TensorDataset(train_x, train_len),
                        batch_size=batch_size, shuffle=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)

    best_val_loss = float("inf")
    best_state = None
    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        for batch_x, batch_len in loader:
            optimizer.zero_grad()
            loss = sequence_errors(batch_x, model(batch_x, batch_len), batch_len).mean()
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch_x.size(0)
        train_loss /= len(train_x)

        model.eval()
        with torch.no_grad():
            val_loss = sequence_errors(val_x, model(val_x, val_len), val_len).mean().item()

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = copy.deepcopy(model.state_dict())

        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"    Epoch {epoch + 1:3d}/{epochs}: "
                  f"train_loss={train_loss:.6f}, val_loss={val_loss:.6f}")

    return best_state, best_val_loss


def train_model(
    paths: list[str | Path] | None = None,
    output_path: str | Path | None = None,
    epochs: int = 50,
    batch_size: int = 32,
    learning_rate: float = 1e-3,
    hidden_size: int = DEFAULT_HIDDEN_SIZE,
    min_flows: int | None = None,
) -> dict:
    """Train on every flow in the given pcaps and save a checkpoint."""
    paths = paths if paths else [config.TRAINING_DIR]
    output_path = Path(output_path or config.LSTM_MODEL_PATH)
    min_flows = config.LSTM_MIN_TRAINING_FLOWS if min_flows is None else min_flows
    max_len = config.LSTM_MAX_SEQ_LEN

    pcaps = find_pcaps(paths)
    if not pcaps:
        raise TrainingDataError(
            f"No pcap files found in {', '.join(map(str, paths))}. {COLLECT_HINT}"
        )

    print(f"[*] Reading {len(pcaps)} pcap file(s)...")
    flows: list[FlowRecord] = []
    n_excluded = 0
    for pcap in pcaps:
        for flow in process_packets(PcapFileSource(str(pcap))):
            if is_excluded(flow):
                n_excluded += 1
            else:
                flows.append(flow)
    print(f"[*] {len(flows)} flows kept, {n_excluded} excluded")

    if len(flows) < min_flows:
        raise TrainingDataError(
            f"Found {len(flows)} usable flows; training needs at least {min_flows}. "
            f"Collect more traffic. {COLLECT_HINT}"
        )

    raw = [encode_flow(f, max_len) for f in flows]
    steps = torch.cat(raw)[:, :NUM_STANDARDIZED]
    feature_means = steps.mean(dim=0).tolist()
    feature_stds = steps.std(dim=0).tolist()
    x, lengths = batch_sequences(
        [standardize(s, feature_means, feature_stds) for s in raw]
    )

    order = torch.randperm(len(x))
    x, lengths = x[order], lengths[order]
    n_train = int(0.9 * len(x))
    train_x, train_len = x[:n_train], lengths[:n_train]
    val_x, val_len = x[n_train:], lengths[n_train:]

    model = FlowLSTMAutoencoder(hidden_size=hidden_size)
    print(f"[*] Training ({n_train} train, {len(x) - n_train} val, "
          f"{epochs} epochs, batch {batch_size}, lr {learning_rate})...")
    best_state, best_val_loss = fit(model, train_x, train_len, val_x, val_len,
                                    epochs, batch_size, learning_rate)

    # Threshold: mean + 3 standard deviations of training-set errors
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        errors = sequence_errors(train_x, model(train_x, train_len), train_len)
    threshold = (errors.mean() + 3 * errors.std()).item()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "format_version": CHECKPOINT_FORMAT_VERSION,
            "model_state_dict": best_state,
            "hidden_size": model.hidden_size,
            "num_layers": model.num_layers,
            "max_seq_len": max_len,
            "feature_means": feature_means,
            "feature_stds": feature_stds,
            "threshold": threshold,
            "best_val_loss": best_val_loss,
            "epochs": epochs,
            "training_files": [p.name for p in pcaps],
            "n_flows": len(flows),
            "n_excluded": n_excluded,
        },
        str(output_path),
    )
    print(f"[*] Saved {output_path} (threshold {threshold:.6f}, "
          f"best val loss {best_val_loss:.6f})")

    return {
        "n_files": len(pcaps),
        "n_flows": len(flows),
        "n_excluded": n_excluded,
        "threshold": threshold,
        "best_val_loss": best_val_loss,
        "output_path": str(output_path),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Train the sequence LSTM detector on captured normal traffic"
    )
    parser.add_argument(
        "paths", nargs="*",
        help=f"pcap files or directories (default: {config.TRAINING_DIR})",
    )
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--hidden-size", type=int, default=DEFAULT_HIDDEN_SIZE)
    parser.add_argument("--output", default=None, help="Model output path")
    args = parser.parse_args()

    try:
        train_model(
            paths=args.paths,
            output_path=args.output,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
            hidden_size=args.hidden_size,
        )
    except TrainingDataError as e:
        print(f"[!] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
