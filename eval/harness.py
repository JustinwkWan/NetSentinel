"""Evaluation harness: runs the agent over the eval set and scores results.

Usage:
    python -m eval.harness [--cases CASE_ID ...] [--save]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from eval.dataset import EvalCase, build_eval_dataset
from eval.judge import judge_report
from eval.report import EvalResult, format_eval_summary, save_eval_results
from netsentinel.agent.graph import investigate_flow
from netsentinel.agent.report import ThreatReport


def run_eval(cases: list[EvalCase] | None = None,
             save: bool = False) -> list[EvalResult]:
    """Run the full evaluation pipeline.

    1. For each eval case, run the agent to produce a ThreatReport.
    2. Score each report with the LLM-as-judge.
    3. Produce and print the eval summary.
    """
    if cases is None:
        cases = build_eval_dataset()

    print(f"[*] Running evaluation on {len(cases)} cases...")
    print(f"    Agent model: {config.LLM_MODEL}")
    print(f"    Judge model: {config.EVAL_JUDGE_MODEL}")
    print()

    results: list[EvalResult] = []

    for i, case in enumerate(cases, 1):
        print(f"[{i}/{len(cases)}] {case.id}: {case.description}")

        result = EvalResult(
            case_id=case.id,
            case_description=case.description,
            expected_severity=case.expected_severity,
            expected_threat_type=case.expected_threat_type,
        )

        # Step 1: Run the agent
        try:
            report = investigate_flow(case.flagged_flow)
            result.agent_severity = report.severity
            result.agent_threat_type = report.threat_type
            result.agent_summary = report.summary
            result.agent_cve_ids = report.cve_ids
            result.agent_attack_techniques = report.attack_techniques
            print(f"  Agent: severity={report.severity}, type={report.threat_type}")
        except Exception as e:
            result.error = f"Agent failed: {e}"
            print(f"  ERROR: {result.error}")
            results.append(result)
            continue

        # Step 2: Judge the report
        try:
            scores = judge_report(case.id, report, case)
            result.scores = scores
            print(f"  Judge: {scores.total}/25 ({scores.percentage:.0f}%)")
        except Exception as e:
            result.error = f"Judge failed: {e}"
            print(f"  Judge ERROR: {result.error}")

        results.append(result)

    # Step 3: Print summary
    summary = format_eval_summary(results)
    print("\n" + summary)

    # Optionally save raw results
    if save:
        save_eval_results(results, config.DATA_DIR / "eval")

    return results


def main():
    parser = argparse.ArgumentParser(description="Run the NetSentinel evaluation harness")
    parser.add_argument(
        "--cases",
        nargs="*",
        help="Specific case IDs to run (default: all)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save raw results to data/eval/eval_results.json",
    )
    args = parser.parse_args()

    dataset = build_eval_dataset()

    if args.cases:
        dataset = [c for c in dataset if c.id in args.cases]
        if not dataset:
            print(f"[!] No matching cases found for: {args.cases}")
            sys.exit(1)

    run_eval(cases=dataset, save=args.save)


if __name__ == "__main__":
    main()
