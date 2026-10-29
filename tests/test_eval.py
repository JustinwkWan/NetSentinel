"""Tests for the evaluation harness: dataset, judge, harness, and reporting.

The agent and judge models are replaced with scripted stand-ins, so no
test makes a real LLM call.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from eval import harness, judge
from eval.dataset import EvalCase, build_eval_dataset
from eval.judge import JudgeScores, judge_report
from eval.report import EvalResult, format_eval_summary, save_eval_results
from netsentinel.agent.parsing import extract_json_object
from netsentinel.agent.report import ThreatReport
from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord


class TestDataset:
    def test_dataset_builds(self):
        cases = build_eval_dataset()
        assert len(cases) >= 5
        assert all(isinstance(c, EvalCase) for c in cases)

    def test_case_ids_are_unique(self):
        cases = build_eval_dataset()
        ids = [c.id for c in cases]
        assert len(ids) == len(set(ids))

    def test_cases_have_required_fields(self):
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for c in build_eval_dataset():
            assert c.id
            assert isinstance(c.flagged_flow, FlaggedFlow)
            assert isinstance(c.flagged_flow.flow, FlowRecord)
            assert c.expected_severity in valid_severities
            assert c.expected_threat_type
            assert c.expected_keywords  # at least one keyword
            assert c.description


class TestJudgeJsonExtraction:
    def test_plain_json(self):
        text = '{"severity_accuracy": 5, "threat_classification": 4}'
        data = extract_json_object(text)
        assert data == {"severity_accuracy": 5, "threat_classification": 4}

    def test_json_with_surrounding_text(self):
        text = 'Here is my evaluation:\n{"severity_accuracy": 3}\nThanks!'
        data = extract_json_object(text)
        assert data == {"severity_accuracy": 3}

    def test_nested_json(self):
        text = '{"a": 1, "b": {"c": 2}}'
        data = extract_json_object(text)
        assert data == {"a": 1, "b": {"c": 2}}

    def test_no_json_returns_none(self):
        assert extract_json_object("no braces here") is None

    def test_invalid_json_returns_none(self):
        assert extract_json_object("{not valid json}") is None


class TestJudgeScores:
    def test_total_sums_criteria(self):
        s = JudgeScores(
            case_id="x",
            severity_accuracy=5,
            threat_classification=4,
            evidence_quality=3,
            reasoning_quality=2,
            actionability=1,
        )
        assert s.total == 15
        assert s.max_total == 25
        assert s.percentage == 60.0

    def test_zero_scores(self):
        s = JudgeScores(case_id="x")
        assert s.total == 0
        assert s.percentage == 0.0


class TestReportFormatting:
    def _make_result(self, case_id="case1", with_scores=True, error=""):
        scores = (
            JudgeScores(
                case_id=case_id,
                severity_accuracy=5,
                threat_classification=4,
                evidence_quality=3,
                reasoning_quality=4,
                actionability=3,
                reasoning="Decent report",
            )
            if with_scores
            else None
        )
        return EvalResult(
            case_id=case_id,
            case_description="A test case",
            expected_severity="high",
            expected_threat_type="brute force",
            agent_severity="high",
            agent_threat_type="brute force",
            agent_summary="Detected brute force attack against SSH service",
            agent_cve_ids=["CVE-2021-12345"],
            agent_attack_techniques=["T1110"],
            scores=scores,
            error=error,
        )

    def test_summary_includes_aggregates(self):
        results = [self._make_result(), self._make_result(case_id="case2")]
        summary = format_eval_summary(results)
        assert "Cases run:     2" in summary
        assert "Cases scored:  2" in summary
        assert "Severity accuracy" in summary
        assert "Exact severity match" in summary

    def test_summary_handles_errored_cases(self):
        results = [
            self._make_result(),
            self._make_result(case_id="case2", with_scores=False, error="boom"),
        ]
        summary = format_eval_summary(results)
        assert "Cases errored: 1" in summary
        assert "boom" in summary

    def test_summary_handles_no_scored_cases(self):
        results = [self._make_result(with_scores=False, error="all failed")]
        summary = format_eval_summary(results)
        # Should not crash, should report 0 scored
        assert "Cases scored:  0" in summary

    def test_save_eval_results(self, tmp_path):
        results = [self._make_result()]
        save_eval_results(results, tmp_path)
        out = tmp_path / "eval_results.json"
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data) == 1
        assert data[0]["case_id"] == "case1"
        assert data[0]["scores"]["total"] == 19


def _case(case_id="reverse_shell_4444") -> EvalCase:
    return next(c for c in build_eval_dataset() if c.id == case_id)


def _report(**overrides) -> ThreatReport:
    fields = {"flow_key": "a->b/TCP", "severity": "critical",
              "threat_type": "reverse shell", "summary": "Shell on 4444."}
    return ThreatReport(**{**fields, **overrides})


class ScriptedJudge:
    def __init__(self, content):
        self.content, self.messages = content, None

    def invoke(self, messages):
        self.messages = messages

        class Response:
            content = self.content

        return Response()


class TestJudgeReport:
    def _judge(self, monkeypatch, content, report=None):
        llm = ScriptedJudge(content)
        monkeypatch.setattr(judge, "_make_judge_llm", lambda: llm)
        return judge_report("case", report or _report(), _case()), llm

    def test_scores_are_parsed_from_the_reply(self, monkeypatch):
        reply = ('Here you go: {"severity_accuracy": 5, "threat_classification": "4", '
                 '"evidence_quality": 3, "reasoning_quality": 5, "actionability": 4, '
                 '"reasoning": "Close."}')
        scores, _ = self._judge(monkeypatch, reply)
        assert (scores.severity_accuracy, scores.threat_classification, scores.total) == (5, 4, 21)
        assert scores.reasoning == "Close." and scores.raw_response == reply

    def test_prompt_holds_report_and_ground_truth(self, monkeypatch):
        report = _report(evidence=["dst port 4444"], cve_ids=["CVE-1"],
                         attack_techniques=["T1059"], remediation="Isolate.")
        _, llm = self._judge(monkeypatch, "{}", report)
        system, prompt = (m.content for m in llm.messages)
        assert "Do NOT reward verbose reports" in system
        for text in ("Severity: critical", "Evidence: dst port 4444", "CVE IDs: CVE-1",
                     "ATT&CK Techniques: T1059", "Remediation: Isolate.",
                     "Expected Severity: critical", "Expected Threat Type: reverse shell"):
            assert text in prompt

    def test_empty_report_fields_read_none(self, monkeypatch):
        _, llm = self._judge(monkeypatch, "{}")
        prompt = llm.messages[1].content
        for field_name in ("Evidence", "CVE IDs", "ATT&CK Techniques", "Remediation"):
            assert f"{field_name}: none" in prompt

    def test_unparseable_reply_scores_zero(self, monkeypatch):
        scores, _ = self._judge(monkeypatch, "I refuse to grade this.")
        assert scores.total == 0
        assert scores.reasoning == "Failed to parse judge response"
        assert scores.raw_response == "I refuse to grade this."


class TestHarness:
    @pytest.fixture
    def stubs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATA_DIR", tmp_path)
        state = {"agent_fails": set(), "judge_fails": set()}

        def investigate_flow(flagged):
            if flagged.flow.dst_port in state["agent_fails"]:
                raise RuntimeError("LLM timed out")
            return _report(flow_key=flagged.flow.flow_key)

        def judge_report(case_id, report, case):
            if case_id in state["judge_fails"]:
                raise RuntimeError("judge offline")
            return JudgeScores(case_id=case_id, severity_accuracy=5,
                               threat_classification=5, evidence_quality=4,
                               reasoning_quality=4, actionability=4)

        monkeypatch.setattr(harness, "investigate_flow", investigate_flow)
        monkeypatch.setattr(harness, "judge_report", judge_report)
        return state

    def test_scores_every_case(self, stubs):
        cases = build_eval_dataset()[:3]
        results = harness.run_eval(cases)
        assert [r.case_id for r in results] == [c.id for c in cases]
        assert all(r.scores.total == 22 and not r.error for r in results)
        assert results[0].agent_severity == "critical"

    def test_agent_and_judge_failures_are_recorded_per_case(self, stubs):
        shell, scan, ssh = (_case(i) for i in
                            ("reverse_shell_4444", "port_scan_31337", "ssh_brute_force"))
        stubs["agent_fails"].add(scan.flagged_flow.flow.dst_port)
        stubs["judge_fails"].add(ssh.id)

        results = harness.run_eval([shell, scan, ssh])

        assert results[0].scores.total == 22
        assert results[1].error == "Agent failed: LLM timed out" and results[1].scores is None
        assert results[2].error == "Judge failed: judge offline"
        assert results[2].agent_threat_type == "reverse shell"

    def test_save_writes_results(self, stubs, tmp_path):
        harness.run_eval([_case()], save=True)
        saved = json.loads((tmp_path / "eval" / "eval_results.json").read_text())
        assert [r["case_id"] for r in saved] == ["reverse_shell_4444"]

    def test_same_model_warning(self, stubs, monkeypatch, capsys):
        monkeypatch.setattr(config, "EVAL_JUDGE_MODEL", config.LLM_MODEL)
        harness.run_eval([_case()])
        assert "self-enhancement bias" in capsys.readouterr().out

    def test_cli_runs_selected_cases(self, stubs, monkeypatch):
        ran = []
        monkeypatch.setattr(harness, "run_eval",
                            lambda cases, save: ran.append(([c.id for c in cases], save)))
        monkeypatch.setattr(sys, "argv", ["harness", "--cases", "dns_tunnel", "--save"])
        harness.main()
        assert ran == [(["dns_tunnel"], True)]

    def test_cli_rejects_unknown_cases(self, stubs, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["harness", "--cases", "nope"])
        with pytest.raises(SystemExit) as exc:
            harness.main()
        assert exc.value.code == 1
