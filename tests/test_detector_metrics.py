"""Tests for the detector metrics script and its synthetic traffic."""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scripts.train_lstm as train_lstm
from eval import detector_metrics
from eval.attack_traffic import ATTACK_SCENARIOS, BENIGN_CONTROL
from eval.detector_metrics import (
    ScenarioResult,
    auc,
    format_summary,
    measure_scenario,
    read_flows,
    scenario_flows,
    split_by_time,
    sweep,
    threshold_for_false_alarm_rate,
    to_json,
)
from tests.traffic import normal_traffic, write_pcap

SCENARIOS = {s.name: s for s in ATTACK_SCENARIOS + [BENIGN_CONTROL]}


class TestSplitByTime:
    def test_holds_out_the_latest_files(self):
        pcaps = [Path(f"live_{i:05d}.pcapng") for i in range(10, 0, -1)]
        train, test = split_by_time(pcaps, 0.2)
        assert [p.name for p in test] == ["live_00009.pcapng", "live_00010.pcapng"]
        assert len(train) == 8
        assert max(p.name for p in train) < min(p.name for p in test)

    def test_holds_out_at_least_one_file(self):
        _, test = split_by_time([Path("a.pcap"), Path("b.pcap")], 0.01)
        assert [p.name for p in test] == ["b.pcap"]

    def test_rejects_a_single_file(self):
        with pytest.raises(ValueError):
            split_by_time([Path("a.pcap")], 0.5)


class TestAuc:
    def test_perfect_separation(self):
        assert auc([5, 6, 7], [1, 2, 3]) == 1.0

    def test_reversed(self):
        assert auc([1, 2], [5, 6]) == 0.0

    def test_ties_count_half(self):
        assert auc([2], [2]) == 0.5

    def test_empty_is_none(self):
        assert auc([], [1.0]) is None


class TestThresholdForFalseAlarmRate:
    def test_flags_at_most_the_target_rate(self):
        scores = [float(i) for i in range(100)]
        threshold = threshold_for_false_alarm_rate(scores, 0.05)
        assert sum(s > threshold for s in scores) == 5

    def test_zero_rate_flags_nothing(self):
        scores = [1.0, 2.0, 3.0]
        threshold = threshold_for_false_alarm_rate(scores, 0.0)
        assert sum(s > threshold for s in scores) == 0


class TestScenarioTraffic:
    """Each generator must come out of real ingestion with its attack's shape."""

    def _flows(self, name, tmp_path):
        return scenario_flows(SCENARIOS[name], 1, seed=0, workdir=tmp_path)[0]

    def test_every_scenario_produces_scorable_flows(self, tmp_path):
        for name in SCENARIOS:
            flows = self._flows(name, tmp_path)
            assert flows and all(f.packets for f in flows), name

    def test_port_scan_is_one_flow_per_port(self, tmp_path):
        flows = self._flows("port_scan", tmp_path)
        assert len(flows) == 100
        assert all(f.packet_count == 2 for f in flows)
        assert len({f.src_ip for f in flows}) == 1

    def test_stealth_scan_gets_no_replies(self, tmp_path):
        flows = self._flows("stealth_scan", tmp_path)
        assert all(p.direction == 1 for f in flows for p in f.packets)

    def test_reverse_shell_initiator_is_the_victim(self, tmp_path):
        (flow,) = self._flows("reverse_shell", tmp_path)
        assert flow.dst_port == 4444
        assert flow.src_ip.startswith("192.168.1.")

    def test_ssh_brute_force_is_one_flow_per_attempt(self, tmp_path):
        flows = self._flows("ssh_brute_force", tmp_path)
        assert len(flows) == 30
        assert all(f.dst_port == 22 for f in flows)

    def test_icmp_flood_is_one_non_tcp_flow(self, tmp_path):
        (flow,) = self._flows("icmp_flood", tmp_path)
        assert flow.protocol == "OTHER"
        assert flow.packet_count > 1000

    def test_same_seed_same_traffic(self, tmp_path):
        a = scenario_flows(SCENARIOS["dns_tunnel"], 2, seed=3, workdir=tmp_path)
        b = scenario_flows(SCENARIOS["dns_tunnel"], 2, seed=3, workdir=tmp_path)
        assert [f.flow_key for fl in a for f in fl] == [f.flow_key for fl in b for f in fl]
        assert [f.byte_count for fl in a for f in fl] == [f.byte_count for fl in b for f in fl]


class FixedDetector:
    """Scores each flow by its packet count, against a fixed threshold."""

    threshold = 10.0

    def score(self, flows):
        return [float(f.packet_count) for f in flows]


def _result(name, flow_scores):
    return ScenarioResult(name=name, description=name, instances=len(flow_scores),
                          instances_detected=0, flows=0, flows_flagged=0, auc=None,
                          flow_scores=flow_scores)


class TestMeasureScenario:
    def test_an_instance_counts_once_any_flow_is_flagged(self, tmp_path):
        # Port scan flows have 2 packets each, far below the threshold of 10
        scan = scenario_flows(SCENARIOS["port_scan"], 2, seed=0, workdir=tmp_path)
        shell = scenario_flows(SCENARIOS["reverse_shell"], 2, seed=0, workdir=tmp_path)
        detector = FixedDetector()

        missed = measure_scenario(detector, SCENARIOS["port_scan"], scan, [1.0, 50.0])
        caught = measure_scenario(detector, SCENARIOS["reverse_shell"], shell, [1.0])

        assert (missed.instances, missed.instances_detected) == (2, 0)
        assert (missed.flows, missed.flows_flagged) == (200, 0)
        assert missed.instance_detection_rate == missed.flow_detection_rate == 0.0
        assert missed.auc == pytest.approx(0.5)  # above 1.0, below 50.0
        assert (caught.instances_detected, caught.flows_flagged) == (2, 2)
        assert caught.instance_detection_rate == 1.0 and caught.auc == 1.0

    def test_empty_result_rates_are_zero(self):
        empty = _result("x", [])
        assert empty.instance_detection_rate == empty.flow_detection_rate == 0.0


class TestSweep:
    def test_rows_trade_false_alarms_for_detection(self):
        normal = [float(i) for i in range(100)]
        attacks = [_result("loud", [[200.0], [97.5]]), _result("quiet", [[90.0], [0.0]])]

        rows = sweep(normal, attacks)

        assert [r["target_false_alarm_rate"] for r in rows] == [0.01, 0.02, 0.05, 0.10]
        assert [r["false_alarm_rate"] for r in rows] == [0.01, 0.02, 0.05, 0.10]
        assert [r["per_scenario"]["loud"] for r in rows] == [0.5, 1.0, 1.0, 1.0]
        assert [r["per_scenario"]["quiet"] for r in rows] == [0.0, 0.0, 0.0, 0.5]
        assert rows[-1]["attacks_detected"] == 0.75


class TestReadFlows:
    def test_skips_unreadable_files_and_excluded_ports(self, tmp_path):
        from tests.traffic import port_scan

        good = tmp_path / "good.pcap"
        write_pcap(good, normal_traffic(5, seed=1) + port_scan(2_000_000.0, range(4443, 4446)))
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"not a pcap")

        flows, unreadable = read_flows([good, bad])

        assert unreadable == ["bad.pcap"]
        assert len(flows) == 5 + 2  # the port 4444 probe is excluded
        assert all(4444 not in (f.src_port, f.dst_port) for f in flows)


@pytest.fixture
def training_dir(tmp_path):
    d = tmp_path / "training"
    d.mkdir()
    for i in range(4):
        write_pcap(d / f"live_{i:05d}.pcap", normal_traffic(40, seed=i))
    return d


@pytest.fixture
def small_training(monkeypatch):
    """Train tiny models so the end-to-end runs stay fast."""
    real = train_lstm.train_model

    def train_model(paths, output_path):
        return real(paths, output_path=output_path, epochs=2, hidden_size=8, min_flows=10)

    monkeypatch.setattr(detector_metrics, "train_model", train_model)


class TestRun:
    def test_trains_a_separate_model_and_tests_on_later_windows(
        self, training_dir, small_training, capsys
    ):
        metrics = detector_metrics.run(holdout_fraction=0.25, instances=1,
                                       training_dir=training_dir)

        assert (metrics["train_windows"], metrics["test_windows"]) == (3, 1)
        assert metrics["normal_flows"] == 40
        assert metrics["model"] == "separate model, trained on a time split"
        assert [r.name for r in metrics["scenarios"]] == [s.name for s in ATTACK_SCENARIOS]
        assert metrics["control"].name == "benign_synthetic"
        assert 0.0 <= metrics["false_alarm_rate"] <= 1.0
        assert len(metrics["sweep"]) == 4

        summary = format_summary(metrics)
        assert "False alarm rate (unseen normal)" in summary
        assert all(s.name in summary for s in ATTACK_SCENARIOS)

        saved = json.loads(json.dumps(to_json(metrics)))
        assert "flow_scores" not in saved["scenarios"][0]
        assert {"flow_detection_rate", "instance_detection_rate"} <= saved["control"].keys()

    def test_existing_model_is_tested_on_windows_it_never_saw(self, training_dir, tmp_path):
        torch.manual_seed(0)
        model = tmp_path / "m.pt"
        first_three = sorted(training_dir.iterdir())[:3]
        train_lstm.train_model(first_three, output_path=model, epochs=1,
                               hidden_size=8, min_flows=10)

        metrics = detector_metrics.run(instances=1, model_path=model,
                                       training_dir=training_dir)

        assert (metrics["train_windows"], metrics["test_windows"]) == (3, 1)
        assert metrics["model"] == str(model)

    def test_model_trained_on_everything_is_refused(self, training_dir, tmp_path):
        model = tmp_path / "m.pt"
        train_lstm.train_model([training_dir], output_path=model, epochs=1,
                               hidden_size=8, min_flows=10)
        with pytest.raises(SystemExit, match="no unseen normal traffic"):
            detector_metrics.run(instances=1, model_path=model, training_dir=training_dir)

    def test_empty_training_dir_is_refused(self, tmp_path):
        with pytest.raises(SystemExit, match="No pcaps"):
            detector_metrics.run(training_dir=tmp_path)

    def test_main_prints_and_saves(self, training_dir, small_training, tmp_path,
                                   monkeypatch, capsys):
        results = tmp_path / "out" / "metrics.json"
        monkeypatch.setattr(detector_metrics, "RESULTS_PATH", results)
        monkeypatch.setattr(detector_metrics.config, "TRAINING_DIR", training_dir)
        monkeypatch.setattr(sys, "argv", ["detector_metrics", "--instances", "1",
                                          "--holdout", "0.25"])

        detector_metrics.main()

        assert "NETSENTINEL DETECTOR METRICS" in capsys.readouterr().out
        assert json.loads(results.read_text())["test_windows"] == 1
