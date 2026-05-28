"""LLM-as-judge scoring with bias mitigations.

Bias mitigations (from Zheng et al., 2023):
  - Rubric-based scoring: scores against specific criteria, not holistic preference
  - Anti-verbosity: explicit instruction not to reward longer responses
  - Position swap: when feasible, swap orderings and require consistency
  - Different model family: the judge should ideally be a different model than the agent
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

import config

JUDGE_SYSTEM_PROMPT = """\
You are an expert cybersecurity evaluator. You will be given a network security \
threat report produced by an AI agent and the expected ground-truth classification. \
Your job is to score the report on specific rubric criteria.

IMPORTANT: Do NOT reward verbose reports over concise ones. A short, accurate report \
is better than a long, padded one. Score strictly against the rubric criteria below.

You must respond with a JSON object containing your scores and reasoning. \
Nothing else.
"""

JUDGE_RUBRIC_PROMPT = """\
## Report Under Evaluation

Flow: {flow_key}
Agent's Report:
  Severity: {report_severity}
  Threat Type: {report_threat_type}
  Summary: {report_summary}
  Evidence: {report_evidence}
  CVE IDs: {report_cve_ids}
  ATT&CK Techniques: {report_attack_techniques}
  Remediation: {report_remediation}

## Ground Truth

Expected Severity: {expected_severity}
Expected Threat Type: {expected_threat_type}
Expected Keywords (at least some should appear in the report): {expected_keywords}
Case Description: {case_description}

## Scoring Rubric

Score each criterion from 1-5:

1. **severity_accuracy** (1-5): Does the agent's severity match the expected severity?
   - 5: Exact match
   - 4: One level off (e.g., high vs critical)
   - 3: Two levels off
   - 2: Three levels off
   - 1: Completely wrong (e.g., info vs critical)

2. **threat_classification** (1-5): Does the agent correctly identify the type of threat?
   - 5: Correct threat type identified
   - 4: Closely related threat type (e.g., "brute force" vs "credential stuffing")
   - 3: Partially correct (right category, wrong specifics)
   - 2: Vaguely related
   - 1: Completely wrong classification

3. **evidence_quality** (1-5): Does the agent cite relevant threat intelligence?
   - 5: Cites specific, relevant CVEs or ATT&CK techniques that match the threat
   - 4: Cites mostly relevant intelligence with minor misses
   - 3: Some relevant citations, some irrelevant
   - 2: Mostly irrelevant citations
   - 1: No citations or completely wrong

4. **reasoning_quality** (1-5): Is the agent's reasoning sound and well-structured?
   - 5: Clear logical chain from evidence to conclusion
   - 4: Good reasoning with minor gaps
   - 3: Adequate reasoning but some leaps
   - 2: Weak reasoning, conclusion not well-supported
   - 1: No coherent reasoning

5. **actionability** (1-5): Is the remediation recommendation useful and specific?
   - 5: Specific, actionable remediation steps
   - 4: Good recommendations, slightly generic
   - 3: Some useful advice, mostly generic
   - 2: Very generic (e.g., "investigate further")
   - 1: No remediation or completely irrelevant

Respond with ONLY a JSON object:
{{
  "severity_accuracy": <1-5>,
  "threat_classification": <1-5>,
  "evidence_quality": <1-5>,
  "reasoning_quality": <1-5>,
  "actionability": <1-5>,
  "reasoning": "Brief explanation of your scores"
}}
"""


@dataclass
class JudgeScores:
    """Scores from the LLM judge for a single eval case."""

    case_id: str
    severity_accuracy: int = 0
    threat_classification: int = 0
    evidence_quality: int = 0
    reasoning_quality: int = 0
    actionability: int = 0
    reasoning: str = ""
    raw_response: str = ""

    @property
    def total(self) -> int:
        return (self.severity_accuracy + self.threat_classification +
                self.evidence_quality + self.reasoning_quality +
                self.actionability)

    @property
    def max_total(self) -> int:
        return 25

    @property
    def percentage(self) -> float:
        return (self.total / self.max_total) * 100 if self.max_total > 0 else 0.0


def _make_judge_llm():
    """Create the judge LLM.

    Ideally a different model family than the agent to mitigate
    self-enhancement bias. Uses the same provider for now but
    could be swapped independently.
    """
    params = {
        "model": config.EVAL_JUDGE_MODEL,
        "temperature": 0.0,
    }
    if config.LLM_BASE_URL:
        params["base_url"] = config.LLM_BASE_URL
    if config.LLM_API_KEY:
        params["api_key"] = config.LLM_API_KEY
    return ChatAnthropic(**params)


def _extract_json_from_response(text: str) -> dict | None:
    """Extract JSON from judge response."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def judge_report(case_id: str, report, eval_case) -> JudgeScores:
    """Score an agent's report against ground-truth labels using LLM-as-judge.

    Args:
        case_id: Identifier for the eval case.
        report: The ThreatReport produced by the agent.
        eval_case: The EvalCase with expected labels.

    Returns:
        JudgeScores with rubric-based scores.
    """
    llm = _make_judge_llm()

    prompt = JUDGE_RUBRIC_PROMPT.format(
        flow_key=report.flow_key,
        report_severity=report.severity,
        report_threat_type=report.threat_type,
        report_summary=report.summary,
        report_evidence=", ".join(report.evidence) if report.evidence else "none",
        report_cve_ids=", ".join(report.cve_ids) if report.cve_ids else "none",
        report_attack_techniques=(
            ", ".join(report.attack_techniques)
            if report.attack_techniques else "none"
        ),
        report_remediation=report.remediation or "none",
        expected_severity=eval_case.expected_severity,
        expected_threat_type=eval_case.expected_threat_type,
        expected_keywords=", ".join(eval_case.expected_keywords),
        case_description=eval_case.description,
    )

    messages = [
        SystemMessage(content=JUDGE_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    response = llm.invoke(messages)
    content = response.content
    if isinstance(content, list):
        content = " ".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
        )

    data = _extract_json_from_response(content)

    if data:
        return JudgeScores(
            case_id=case_id,
            severity_accuracy=int(data.get("severity_accuracy", 0)),
            threat_classification=int(data.get("threat_classification", 0)),
            evidence_quality=int(data.get("evidence_quality", 0)),
            reasoning_quality=int(data.get("reasoning_quality", 0)),
            actionability=int(data.get("actionability", 0)),
            reasoning=str(data.get("reasoning", "")),
            raw_response=content,
        )

    # Fallback: couldn't parse judge response
    return JudgeScores(
        case_id=case_id,
        reasoning=f"Failed to parse judge response",
        raw_response=content,
    )
