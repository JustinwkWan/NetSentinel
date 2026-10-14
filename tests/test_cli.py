"""Tests for the CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from netsentinel import cli


def test_missing_model_exits_with_instructions(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "LSTM_MODEL_PATH", tmp_path / "missing.pt")
    monkeypatch.setattr(sys, "argv", ["netsentinel", str(tmp_path / "any.pcap")])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    assert "python scripts/train_lstm.py" in capsys.readouterr().out
