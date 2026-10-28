"""Tests for the detector metrics script and its synthetic traffic."""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.attack_traffic import ATTACK_SCENARIOS, BENIGN_CONTROL
from eval.detector_metrics import (
    auc,
    scenario_flows,
    split_by_time,
    threshold_for_false_alarm_rate,
)

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
