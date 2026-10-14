"""Tests for LSTM training on captured traffic."""

from __future__ import annotations

import copy
import gc
import statistics
import weakref
import sys
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.detection.lstm import (
    CHECKPOINT_FORMAT_VERSION,
    FlowLSTMAutoencoder,
    LstmDetector,
    batch_sequences,
)
from netsentinel.ingestion.sources import PcapFileSource, process_packets
import scripts.train_lstm as train_lstm
from scripts.train_lstm import TrainingDataError, find_pcaps, fit, train_model
from tests.traffic import exfil_burst, normal_traffic, port_scan, write_pcap


def _random_batch(n: int, seed: int = 0):
    gen = torch.Generator().manual_seed(seed)
    seqs = [torch.randn(int(torch.randint(1, 10, (1,), generator=gen)), 8,
                        generator=gen) for _ in range(n)]
    return batch_sequences(seqs)


class TestFit:
    def test_best_state_is_detached_from_live_weights(self):
        torch.manual_seed(0)
        model = FlowLSTMAutoencoder(hidden_size=8)
        x, lengths = _random_batch(40)

        best_state, _, _ = fit(model, x[:32], lengths[:32], x[32:], lengths[32:],
                               epochs=2, batch_size=8, learning_rate=1e-2)
        snapshot = copy.deepcopy(best_state)
        with torch.no_grad():
            for param in model.parameters():
                param.add_(1.0)

        for name, tensor in best_state.items():
            assert torch.equal(tensor, snapshot[name]), name


    def test_stops_once_validation_stops_improving(self):
        torch.manual_seed(0)
        model = FlowLSTMAutoencoder(hidden_size=8)
        x, lengths = _random_batch(40)

        # A zero learning rate never improves on the first epoch's val loss
        _, _, epochs_run = fit(model, x[:32], lengths[:32], x[32:], lengths[32:],
                               epochs=100, batch_size=8, learning_rate=0.0,
                               patience=5)

        assert epochs_run == 6


class TestFindPcaps:
    def test_mixes_files_and_directories_and_skips_other_files(self, tmp_path):
        d = tmp_path / "windows"
        d.mkdir()
        (d / "a.pcapng").write_bytes(b"")
        (d / "b.pcap").write_bytes(b"")
        (d / "notes.txt").write_bytes(b"")
        single = tmp_path / "c.pcap"
        single.write_bytes(b"")

        found = find_pcaps([d, single, tmp_path / "missing.pcap"])

        assert [p.name for p in found] == ["a.pcapng", "b.pcap", "c.pcap"]


class TestTrainModel:
    def test_no_pcaps_explains_how_to_collect(self, tmp_path):
        with pytest.raises(TrainingDataError, match="Save windows for training"):
            train_model([tmp_path], output_path=tmp_path / "m.pt")

    def test_too_few_flows_is_refused(self, tmp_path):
        write_pcap(tmp_path / "w.pcap", normal_traffic(20, seed=1))
        with pytest.raises(TrainingDataError, match="at least 500"):
            train_model([tmp_path], output_path=tmp_path / "m.pt")

    def test_excluded_ports_are_not_learned(self, tmp_path):
        write_pcap(tmp_path / "w.pcap",
                   normal_traffic(60, seed=2) + port_scan(2_000_000.0, range(4440, 4450)))
        summary = train_model([tmp_path], output_path=tmp_path / "m.pt",
                              epochs=1, min_flows=10)
        assert summary["n_excluded"] == 1  # port 4444
        assert summary["n_flows"] == 60 + 9

    def test_checkpoint_round_trip(self, tmp_path):
        torch.manual_seed(0)
        write_pcap(tmp_path / "w.pcap", normal_traffic(80, seed=3))
        model_path = tmp_path / "m.pt"

        summary = train_model([tmp_path], output_path=model_path, epochs=2,
                              batch_size=16, hidden_size=8, min_flows=10)

        checkpoint = torch.load(model_path, weights_only=True)
        assert checkpoint["format_version"] == CHECKPOINT_FORMAT_VERSION
        assert checkpoint["max_seq_len"] == 32
        detector = LstmDetector(model_path=model_path)
        assert detector.model.hidden_size == 8
        assert detector.threshold == pytest.approx(summary["threshold"])

    def test_anomalies_score_higher_than_unseen_normal_traffic(self, tmp_path):
        torch.manual_seed(0)
        train_dir = tmp_path / "train"
        train_dir.mkdir()
        write_pcap(train_dir / "w.pcap", normal_traffic(400, seed=4))
        model_path = tmp_path / "m.pt"
        # 30 epochs leaves the model undertrained on this small set (val loss
        # still falling); 100 converges and separates the classes clearly.
        train_model([train_dir], output_path=model_path, epochs=100,
                    batch_size=32, min_flows=100)

        held_out = tmp_path / "held_out.pcap"
        write_pcap(held_out, normal_traffic(100, seed=99))
        attacks = tmp_path / "attacks.pcap"
        write_pcap(attacks, port_scan(3_000_000.0, range(20, 60)) +
                   exfil_burst(3_000_100.0))

        detector = LstmDetector(model_path=model_path)
        normal = detector.score(process_packets(PcapFileSource(str(held_out))))
        anomalous = detector.score(process_packets(PcapFileSource(str(attacks))))

        assert statistics.median(anomalous) > 2 * statistics.median(normal)

    def test_unreadable_pcap_is_skipped_not_fatal(self, tmp_path):
        write_pcap(tmp_path / "good.pcap", normal_traffic(40, seed=5))
        (tmp_path / "empty.pcapng").write_bytes(b"")
        (tmp_path / "truncated.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a\x1c\x00")

        summary = train_model([tmp_path], output_path=tmp_path / "m.pt",
                              epochs=1, min_flows=10)

        assert summary["n_files"] == 1
        assert summary["skipped_files"] == ["empty.pcapng", "truncated.pcapng"]

    def test_full_packet_lists_are_released_before_training(self, tmp_path, monkeypatch):
        write_pcap(tmp_path / "w.pcap", normal_traffic(30, seed=6))
        refs: list[weakref.ref] = []
        real_process = train_lstm.process_packets

        def tracking_process(source):
            flows = real_process(source)
            refs.extend(weakref.ref(f) for f in flows)
            return flows

        alive_at_fit: list[int] = []
        real_fit = train_lstm.fit

        def checking_fit(*args, **kwargs):
            gc.collect()
            alive_at_fit.append(sum(r() is not None for r in refs))
            return real_fit(*args, **kwargs)

        monkeypatch.setattr(train_lstm, "process_packets", tracking_process)
        monkeypatch.setattr(train_lstm, "fit", checking_fit)
        train_model([tmp_path], output_path=tmp_path / "m.pt", epochs=1, min_flows=10)

        assert alive_at_fit == [0]
