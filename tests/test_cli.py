"""Tests for the CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from netsentinel import cli
from netsentinel.agent.report import ThreatReport
from netsentinel.agent.scheduler import InvestigationResult
from netsentinel.agent.timing import InvestigationTiming
from netsentinel.detection.base import FlaggedFlow
from tests.traffic import normal_traffic, write_pcap


def test_missing_model_exits_with_instructions(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "LSTM_MODEL_PATH", tmp_path / "missing.pt")
    monkeypatch.setattr(sys, "argv", ["netsentinel", str(tmp_path / "any.pcap")])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    assert "python scripts/train_lstm.py" in capsys.readouterr().out


class FakeDetector:
    def __init__(self, flag_count: int):
        self.flag_count = flag_count

    def flag(self, flows):
        return [FlaggedFlow(flow=f, anomaly_score=0.9, reason="sequence anomaly")
                for f in flows[:self.flag_count]]


@pytest.fixture
def run_cli(tmp_path, monkeypatch, capsys):
    """Run the CLI on a real pcap with a stand-in detector and agent."""

    def _run(packets, flag_count=0, investigate=None):
        pcap = tmp_path / "in.pcap"
        write_pcap(pcap, packets)
        monkeypatch.setattr(cli, "LstmDetector", lambda: FakeDetector(flag_count))
        if investigate is not None:
            monkeypatch.setattr(cli, "investigate_all", investigate)
        monkeypatch.setattr(sys, "argv", ["netsentinel", str(pcap)])
        try:
            cli.main()
            code = 0
        except SystemExit as e:
            code = e.code
        return code, capsys.readouterr().out

    return _run


def test_empty_pcap_exits_cleanly(run_cli):
    code, out = run_cli([])
    assert code == 0
    assert "No flows found" in out


def test_nothing_flagged_exits_cleanly(run_cli):
    code, out = run_cli(normal_traffic(3), flag_count=0)
    assert code == 0
    assert "Assembled 3 flows" in out
    assert "No suspicious flows detected" in out


def test_reports_each_investigation_and_the_total(run_cli):
    def investigate_all(flagged, on_result):
        results = []
        for i, ff in enumerate(flagged):
            timing = InvestigationTiming(total_s=2.0, llm_call_s=[1.5], tool_call_s=[0.2])
            if i == 0:
                report = ThreatReport(flow_key=ff.flow.flow_key, severity="high",
                                      threat_type="port scan", summary="Probing.")
                result = InvestigationResult(flagged=ff, timing=timing, report=report)
            else:
                result = InvestigationResult(flagged=ff, timing=timing, error="LLM timed out")
            on_result(i, result)
            results.append(result)
        return results

    code, out = run_cli(normal_traffic(3), flag_count=2, investigate=investigate_all)

    assert code == 0
    assert "Flagged 2 suspicious flows" in out
    assert "Flow 1/2" in out and "Flow 2/2" in out
    assert "THREAT REPORT" in out and "Threat Type: port scan" in out
    assert "1 LLM calls" in out
    assert "[!] Investigation failed" in out and "LLM timed out" in out
    assert "1/2 flows investigated successfully" in out
