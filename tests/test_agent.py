"""Tests for the agent layer: graph routing, iteration cap, report parsing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from api.models import ThreatReportDTO
from netsentinel.agent import graph, tools
from netsentinel.agent.parsing import as_text_list, content_to_text, extract_json_object
from netsentinel.agent.timing import InvestigationTiming
from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord

REPORT = {
    "severity": "critical",
    "threat_type": "reverse shell",
    "summary": "Outbound connection to Metasploit's default port.",
    "evidence": ["dst port 4444"],
    "cve_ids": [],
    "attack_techniques": ["T1059: Command and Scripting Interpreter"],
    "remediation": "Isolate the host.",
}


def _tool_call(call_id: str) -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[{
            "name": "cve_lookup",
            "args": {"query": "reverse shell"},
            "id": call_id,
            "type": "tool_call",
        }],
    )


def _final(report: dict = REPORT) -> AIMessage:
    return AIMessage(content=json.dumps(report))


def _check_transcript(messages: list) -> None:
    """Enforce the Anthropic API rule the real endpoint returns a 400 for."""
    for i, msg in enumerate(messages):
        calls = getattr(msg, "tool_calls", None) or []
        if not calls:
            continue
        following = messages[i + 1 : i + 1 + len(calls)]
        answered = {m.tool_call_id for m in following if isinstance(m, ToolMessage)}
        missing = {c["id"] for c in calls} - answered
        if missing:
            raise ValueError(
                f"tool_use ids were found without tool_result blocks "
                f"immediately after: {sorted(missing)}"
            )


class FakeLLM(BaseChatModel):
    """Scripted chat model standing in for ChatAnthropic.

    A real BaseChatModel, so LangChain fires the same callbacks it would
    for the provider's model (which the timing instrumentation relies on).
    """

    responses: list[AIMessage]
    calls: list[dict] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools_, **kwargs):
        return self.bind(**kwargs)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        _check_transcript(messages)
        self.calls.append({"kwargs": kwargs, "messages": list(messages)})
        message = self.responses.pop(0)
        message.usage_metadata = {
            "input_tokens": 100, "output_tokens": 10, "total_tokens": 110,
        }
        return ChatResult(generations=[ChatGeneration(message=message)])


class EmptyStore:
    def query_cve(self, query):
        return []

    def query_attack(self, query):
        return []


@pytest.fixture
def run_agent(monkeypatch):
    """Run investigate_flow against a scripted LLM with a given cap."""
    monkeypatch.setattr(tools, "_store", EmptyStore())
    monkeypatch.setattr(graph, "_compiled_graph", None)

    def _run(responses: list[AIMessage], max_iterations: int, timing=None):
        llm = FakeLLM(responses=responses)
        monkeypatch.setattr(graph, "make_chat_model", lambda **kw: llm)
        monkeypatch.setattr(config, "AGENT_MAX_ITERATIONS", max_iterations)
        flow = FlowRecord("192.168.1.10", "10.0.0.99", 60000, 4444, "TCP",
                          25, 12000, 30.0, 1000000.0)
        report = graph.investigate_flow(
            FlaggedFlow(flow=flow, anomaly_score=0.8, reason="port 4444"),
            timing=timing,
        )
        return report, llm

    return _run


class TestIterationCap:
    def test_cap_hit_with_pending_tool_call_still_produces_report(self, run_agent):
        # Every agent turn asks for a tool, so the cap is what ends the loop.
        report, llm = run_agent(
            [_tool_call("call_1"), _tool_call("call_2"), _final()],
            max_iterations=2,
        )
        assert report.severity == "critical"
        assert report.threat_type == "reverse shell"
        assert len(llm.calls) == 3
        # The forced report keeps tools defined but forbids calling them.
        assert llm.calls[-1]["kwargs"] == {"tool_choice": {"type": "none"}}

    def test_final_answer_on_last_turn_is_kept(self, run_agent):
        report, llm = run_agent(
            [_tool_call("call_1"), _final()], max_iterations=2
        )
        assert report.severity == "critical"
        assert len(llm.calls) == 2  # no extra forced-report call

    def test_answer_without_tools_ends_immediately(self, run_agent):
        report, llm = run_agent([_final()], max_iterations=5)
        assert report.threat_type == "reverse shell"
        assert len(llm.calls) == 1


class TestTiming:
    def test_records_every_llm_and_tool_call(self, run_agent):
        timing = InvestigationTiming()
        run_agent(
            [_tool_call("call_1"), _tool_call("call_2"), _final()],
            max_iterations=2,
            timing=timing,
        )
        assert timing.llm_calls == 3  # two agent turns + forced report
        assert timing.tool_calls == 2
        assert timing.input_tokens == 300
        assert timing.output_tokens == 30
        assert timing.total_s >= timing.llm_s + timing.tool_s > 0

    def test_total_time_is_recorded_when_the_graph_fails(self, run_agent):
        timing = InvestigationTiming()
        with pytest.raises(IndexError):  # scripted model runs out of replies
            run_agent([_tool_call("call_1")], max_iterations=5, timing=timing)
        assert timing.total_s > 0
        # The failed second call still counts; only the first reported usage.
        assert timing.llm_calls == 2
        assert timing.input_tokens == 100


class TestExtractJsonObject:
    def test_brace_inside_string_value(self):
        text = 'Report: {"summary": "payload had \'{\' chars", "severity": "high"}'
        assert extract_json_object(text) == {
            "summary": "payload had '{' chars", "severity": "high",
        }

    def test_skips_invalid_object_before_valid_one(self):
        text = 'Thinking {not json} then {"severity": "low"}'
        assert extract_json_object(text) == {"severity": "low"}

    def test_code_fenced(self):
        text = '```json\n{"a": {"b": [1, 2]}}\n```'
        assert extract_json_object(text) == {"a": {"b": [1, 2]}}

    def test_none_when_absent(self):
        assert extract_json_object("no json here") is None


class TestParseReport:
    def _parse(self, data: dict):
        msg = AIMessage(content=json.dumps(data))
        return graph._parse_report({"messages": [msg]}, "flow")

    def test_string_list_fields_are_not_split_into_characters(self):
        report = self._parse({**REPORT, "cve_ids": "CVE-2021-44228"})
        assert report.cve_ids == ["CVE-2021-44228"]
        assert "Related CVEs: CVE-2021-44228" in report.format()

    def test_object_items_become_strings_and_pass_api_validation(self):
        report = self._parse({
            **REPORT,
            "evidence": [{"point": "dst port 4444"}, None, ""],
            "attack_techniques": [{"id": "T1059", "name": "Command Interpreter"}],
        })
        assert report.evidence == ["dst port 4444"]
        assert report.attack_techniques == ["T1059, Command Interpreter"]
        ThreatReportDTO(
            flow_key=report.flow_key,
            severity=report.severity,
            threat_type=report.threat_type,
            summary=report.summary,
            evidence=report.evidence,
            cve_ids=report.cve_ids,
            attack_techniques=report.attack_techniques,
            remediation=report.remediation,
        )

    def test_null_fields_fall_back_instead_of_reading_none(self):
        report = self._parse({**REPORT, "threat_type": None, "remediation": None})
        assert report.threat_type == "unknown"
        assert report.remediation == ""

    def test_answer_without_json_becomes_the_summary(self):
        msg = AIMessage(content="I could not reach a conclusion. " * 30)
        report = graph._parse_report({"messages": [msg]}, "flow")
        assert (report.severity, report.threat_type) == ("medium", "unknown")
        assert report.summary == msg.content[:500]

    def test_block_list_content_is_parsed(self):
        msg = AIMessage(content=[{"type": "text", "text": json.dumps(REPORT)}])
        assert graph._parse_report({"messages": [msg]}, "flow").severity == "critical"

    @pytest.mark.parametrize("raw, expected", [
        (" HIGH ", "high"), ("severe", "medium"), (None, "medium"),
    ])
    def test_severity_is_normalized(self, raw, expected):
        assert self._parse({**REPORT, "severity": raw}).severity == expected


class TestAsTextList:
    def test_none_and_empty(self):
        assert as_text_list(None) == []
        assert as_text_list("  ") == []

    def test_scalars_become_strings(self):
        assert as_text_list([1, "a"]) == ["1", "a"]


class TestContentToText:
    def test_block_list_is_joined(self):
        assert content_to_text([{"text": "a"}, {"type": "image"}, "b"]) == "a  b"

    def test_non_string_is_stringified(self):
        assert content_to_text(42) == "42"


class FakeStore:
    def __init__(self, results=None, error=None):
        self.results, self.error, self.queries = results or [], error, []

    def _query(self, query):
        self.queries.append(query)
        if self.error:
            raise self.error
        return self.results

    query_cve = query_attack = _query


class TestTools:
    """The tools return concise JSON, and never raise into the graph."""

    def test_cve_lookup_returns_id_severity_and_truncated_description(self, monkeypatch):
        store = FakeStore([{"content": "x" * 900,
                            "metadata": {"cve_id": "CVE-2021-44228", "severity": "critical"}}])
        monkeypatch.setattr(tools, "_store", store)

        entries = json.loads(tools.cve_lookup.invoke({"query": "log4j rce"}))

        assert store.queries == ["log4j rce"]
        assert entries == [{"cve_id": "CVE-2021-44228", "description": "x" * 500,
                            "severity": "critical"}]

    def test_attack_lookup_returns_id_and_name(self, monkeypatch):
        monkeypatch.setattr(tools, "_store", FakeStore([
            {"content": "Adversaries may scan.",
             "metadata": {"technique_id": "T1046", "name": "Network Service Discovery"}},
        ]))

        entries = json.loads(tools.attack_technique_lookup.invoke({"query": "scan"}))

        assert entries == [{"technique_id": "T1046", "name": "Network Service Discovery",
                            "description": "Adversaries may scan."}]

    def test_missing_metadata_reads_unknown(self, monkeypatch):
        monkeypatch.setattr(tools, "_store", FakeStore([{"content": "d"}]))
        cve = json.loads(tools.cve_lookup.invoke({"query": "q"}))[0]
        attack = json.loads(tools.attack_technique_lookup.invoke({"query": "q"}))[0]
        assert (cve["cve_id"], cve["severity"]) == ("unknown", "unknown")
        assert (attack["technique_id"], attack["name"]) == ("unknown", "unknown")

    @pytest.mark.parametrize("store", [FakeStore(), FakeStore(error=RuntimeError("db gone"))])
    def test_no_results_or_failure_is_a_message(self, monkeypatch, store):
        monkeypatch.setattr(tools, "_store", store)
        assert tools.cve_lookup.invoke({"query": "q"}) == (
            "No relevant CVE entries found for this query.")
        assert tools.attack_technique_lookup.invoke({"query": "q"}) == (
            "No relevant ATT&CK techniques found for this query.")

    def test_store_is_opened_once_and_reused(self, monkeypatch):
        opened = []
        monkeypatch.setattr(tools, "_store", None)
        monkeypatch.setattr(tools, "RAGStore", lambda: opened.append(1) or FakeStore())
        tools.cve_lookup.invoke({"query": "a"})
        tools.attack_technique_lookup.invoke({"query": "b"})
        assert len(opened) == 1

    def test_set_store_injects_a_store(self, monkeypatch):
        monkeypatch.setattr(tools, "_store", None)
        store = FakeStore()
        tools.set_store(store)
        tools.cve_lookup.invoke({"query": "q"})
        assert store.queries == ["q"]
