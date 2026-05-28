"""Eval report: produces a summary of evaluation results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from eval.judge import JudgeScores


@dataclass
class EvalResult:
    """Result for a single eval case: agent output + judge scores."""

    case_id: str
    case_description: str
    expected_severity: str
    expected_threat_type: str
    agent_severity: str = ""
    agent_threat_type: str = ""
    agent_summary: str = ""
    agent_cve_ids: list[str] = field(default_factory=list)
    agent_attack_techniques: list[str] = field(default_factory=list)
    scores: JudgeScores | None = None
    error: str = ""


def format_eval_summary(results: list[EvalResult]) -> str:
    """Format a human-readable evaluation summary."""
    lines = []
    lines.append("=" * 70)
    lines.append("NETSENTINEL EVALUATION REPORT")
    lines.append("=" * 70)

    # Aggregate metrics
    scored = [r for r in results if r.scores and r.scores.total > 0]
    errored = [r for r in results if r.error]
    total_cases = len(results)

    lines.append(f"\nCases run:     {total_cases}")
    lines.append(f"Cases scored:  {len(scored)}")
    lines.append(f"Cases errored: {len(errored)}")

    if scored:
        avg_total = sum(s.scores.total for s in scored) / len(scored)
        avg_pct = sum(s.scores.percentage for s in scored) / len(scored)
        avg_severity = sum(s.scores.severity_accuracy for s in scored) / len(scored)
        avg_threat = sum(s.scores.threat_classification for s in scored) / len(scored)
        avg_evidence = sum(s.scores.evidence_quality for s in scored) / len(scored)
        avg_reasoning = sum(s.scores.reasoning_quality for s in scored) / len(scored)
        avg_action = sum(s.scores.actionability for s in scored) / len(scored)

        lines.append(f"\n--- Aggregate Scores (averaged over {len(scored)} cases) ---")
        lines.append(f"  Overall:              {avg_total:.1f}/25 ({avg_pct:.0f}%)")
        lines.append(f"  Severity accuracy:    {avg_severity:.1f}/5")
        lines.append(f"  Threat classification:{avg_threat:.1f}/5")
        lines.append(f"  Evidence quality:     {avg_evidence:.1f}/5")
        lines.append(f"  Reasoning quality:    {avg_reasoning:.1f}/5")
        lines.append(f"  Actionability:        {avg_action:.1f}/5")

        # Severity match rate
        exact_severity = sum(
            1 for r in scored
            if r.agent_severity.lower() == r.expected_severity.lower()
        )
        lines.append(f"\n  Exact severity match: {exact_severity}/{len(scored)} "
                      f"({exact_severity / len(scored) * 100:.0f}%)")

    # Per-case breakdown
    lines.append(f"\n{'=' * 70}")
    lines.append("PER-CASE BREAKDOWN")
    lines.append("=" * 70)

    for r in results:
        lines.append(f"\n--- {r.case_id} ---")
        lines.append(f"  Description: {r.case_description}")
        lines.append(f"  Expected: {r.expected_severity} / {r.expected_threat_type}")

        if r.error:
            lines.append(f"  ERROR: {r.error}")
            continue

        lines.append(f"  Agent:    {r.agent_severity} / {r.agent_threat_type}")
        lines.append(f"  Summary:  {r.agent_summary[:150]}...")

        if r.agent_cve_ids:
            lines.append(f"  CVEs:     {', '.join(r.agent_cve_ids[:5])}")
        if r.agent_attack_techniques:
            lines.append(f"  ATT&CK:   {', '.join(r.agent_attack_techniques[:5])}")

        if r.scores:
            lines.append(f"  Scores:   {r.scores.total}/25 ({r.scores.percentage:.0f}%)")
            lines.append(f"    Severity={r.scores.severity_accuracy} "
                          f"Threat={r.scores.threat_classification} "
                          f"Evidence={r.scores.evidence_quality} "
                          f"Reasoning={r.scores.reasoning_quality} "
                          f"Action={r.scores.actionability}")
            if r.scores.reasoning:
                lines.append(f"  Judge: {r.scores.reasoning[:200]}")

    lines.append(f"\n{'=' * 70}")

    # Honest framing (per design doc)
    lines.append("\nNote: Scores are from an LLM-as-judge, which is a noisy estimator,")
    lines.append("not ground truth. The eval set labels are human-set; the judge")
    lines.append("measures agreement with those labels.")
    lines.append("=" * 70)

    return "\n".join(lines)


def save_eval_results(results: list[EvalResult], output_dir: Path) -> None:
    """Save raw evaluation results as JSON for later analysis."""
    output_dir.mkdir(parents=True, exist_ok=True)

    data = []
    for r in results:
        entry = {
            "case_id": r.case_id,
            "case_description": r.case_description,
            "expected_severity": r.expected_severity,
            "expected_threat_type": r.expected_threat_type,
            "agent_severity": r.agent_severity,
            "agent_threat_type": r.agent_threat_type,
            "agent_summary": r.agent_summary,
            "agent_cve_ids": r.agent_cve_ids,
            "agent_attack_techniques": r.agent_attack_techniques,
            "error": r.error,
        }
        if r.scores:
            entry["scores"] = {
                "severity_accuracy": r.scores.severity_accuracy,
                "threat_classification": r.scores.threat_classification,
                "evidence_quality": r.scores.evidence_quality,
                "reasoning_quality": r.scores.reasoning_quality,
                "actionability": r.scores.actionability,
                "total": r.scores.total,
                "percentage": r.scores.percentage,
                "reasoning": r.scores.reasoning,
            }
        data.append(entry)

    output_path = output_dir / "eval_results.json"
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[*] Raw results saved to {output_path}")
