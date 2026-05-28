"""Tests for the evaluation harness — dataset, judge parsing, and reporting.

These tests cover everything except the actual LLM calls. The judge's LLM
invocation is exercised separately by running the harness end-to-end.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.dataset import EvalCase, build_eval_dataset
from eval.judge import JudgeScores, _extract_json_from_response
from eval.report import EvalResult, format_eval_summary, save_eval_results
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
        data = _extract_json_from_response(text)
        assert data == {"severity_accuracy": 5, "threat_classification": 4}

    def test_json_with_surrounding_text(self):
        text = 'Here is my evaluation:\n{"severity_accuracy": 3}\nThanks!'
        data = _extract_json_from_response(text)
        assert data == {"severity_accuracy": 3}

    def test_nested_json(self):
        text = '{"a": 1, "b": {"c": 2}}'
        data = _extract_json_from_response(text)
        assert data == {"a": 1, "b": {"c": 2}}

    def test_no_json_returns_none(self):
        assert _extract_json_from_response("no braces here") is None

    def test_invalid_json_returns_none(self):
        assert _extract_json_from_response("{not valid json}") is None


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
