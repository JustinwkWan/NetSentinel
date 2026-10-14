"""Benchmark agent investigations: where the time goes, and before/after.

Runs a batch of flagged flows (taken from the eval dataset, so every run
investigates the same inputs) through the same scheduler the API and CLI
use, then reports wall time, per-flow time, and per-call LLM/tool latency.

Usage:
    python scripts/benchmark_investigations.py --label baseline
    python scripts/benchmark_investigations.py --label parallel
    python scripts/benchmark_investigations.py --compare BEFORE.json AFTER.json

Note: each run makes real LLM calls (roughly 2-6 per flow).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from eval.dataset import build_eval_dataset
from netsentinel.agent.scheduler import investigate_all
from netsentinel.llm import deadline_hits, get_rate_limiter

BENCHMARK_DIR = config.DATA_DIR / "benchmarks"

# Settings recorded with each result, so runs are comparable. Missing ones
# (e.g. before a setting existed) are stored as null.
RECORDED_SETTINGS = [
    "LLM_MODEL",
    "AGENT_MAX_ITERATIONS",
    "INVESTIGATION_MAX_CONCURRENCY",
    "LLM_REQUESTS_PER_SECOND",
    "LLM_MAX_BURST",
    "LLM_MAX_RETRIES",
    "LLM_TIMEOUT_SECONDS",
]


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile; 0.0 for an empty list."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


def summarize(values: list[float]) -> dict:
    return {
        "count": len(values),
        "total": sum(values),
        "mean": sum(values) / len(values) if values else 0.0,
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "max": max(values, default=0.0),
    }


def run_benchmark(n_flows: int, label: str) -> dict:
    cases = build_eval_dataset()
    flagged = [cases[i % len(cases)].flagged_flow for i in range(n_flows)]

    print(f"[*] Benchmark '{label}': investigating {n_flows} flows...")
    limiter_before = get_rate_limiter().stats()
    deadline_hits_before = deadline_hits()
    start = time.perf_counter()
    results = investigate_all(
        flagged,
        on_result=lambda i, r: print(
            f"    flow {i + 1:2d} done in {r.timing.total_s:5.1f}s "
            f"(waited {r.timing.queued_s:5.1f}s, {r.timing.llm_calls} LLM calls)"
            + ("" if r.report else f"  FAILED: {r.error}")
        ),
    )
    wall_s = time.perf_counter() - start
    limiter_after = get_rate_limiter().stats()

    timings = [r.timing for r in results]
    llm_calls = [s for t in timings for s in t.llm_call_s]
    return {
        "label": label,
        "recorded_at": datetime.now().isoformat(timespec="seconds"),
        "settings": {k: getattr(config, k, None) for k in RECORDED_SETTINGS},
        "flows": n_flows,
        "failed": sum(1 for r in results if r.report is None),
        "wall_s": wall_s,
        "flow_total_s": summarize([t.total_s for t in timings]),
        "flow_queued_s": summarize([t.queued_s for t in timings]),
        "llm_call_s": summarize(llm_calls),
        "llm_calls_per_flow": len(llm_calls) / n_flows,
        "tool_call_s": summarize([s for t in timings for s in t.tool_call_s]),
        "input_tokens": sum(t.input_tokens for t in timings),
        "output_tokens": sum(t.output_tokens for t in timings),
        "throughput_flows_per_min": n_flows / wall_s * 60 if wall_s else 0.0,
        "rate_limit_wait_s": limiter_after.wait_s - limiter_before.wait_s,
        "deadline_hits": deadline_hits() - deadline_hits_before,
    }


ROWS = [
    ("Wall time (s)", lambda r: r["wall_s"]),
    ("Throughput (flows/min)", lambda r: r["throughput_flows_per_min"]),
    ("Failed flows", lambda r: r["failed"]),
    ("Per-flow time p50 (s)", lambda r: r["flow_total_s"]["p50"]),
    ("Per-flow time p95 (s)", lambda r: r["flow_total_s"]["p95"]),
    ("Wait for worker p50 (s)", lambda r: r["flow_queued_s"]["p50"]),
    ("Wait for worker max (s)", lambda r: r["flow_queued_s"]["max"]),
    ("LLM calls per flow", lambda r: r["llm_calls_per_flow"]),
    ("LLM round-trip p50 (s)", lambda r: r["llm_call_s"]["p50"]),
    ("LLM round-trip p95 (s)", lambda r: r["llm_call_s"]["p95"]),
    ("LLM round-trip max (s)", lambda r: r["llm_call_s"]["max"]),
    ("Rate-limit wait total (s)", lambda r: r["rate_limit_wait_s"]),
    ("Calls cut off by deadline", lambda r: r["deadline_hits"]),
    ("Tool call p50 (s)", lambda r: r["tool_call_s"]["p50"]),
    ("Tool call max (s)", lambda r: r["tool_call_s"]["max"]),
    ("Input tokens", lambda r: r["input_tokens"]),
    ("Output tokens", lambda r: r["output_tokens"]),
]


def _fmt(value) -> str:
    if value is None:
        return "-"
    return f"{value:,.2f}" if isinstance(value, float) else f"{value:,}"


def format_results(*runs: dict) -> str:
    header = f"{'':26}" + "".join(f"{r['label']:>16}" for r in runs)
    lines = [header, "-" * len(header)]
    for name, get in ROWS:
        values = []
        for r in runs:
            try:
                values.append(get(r))
            except KeyError:
                values.append(None)
        lines.append(f"{name:26}" + "".join(f"{_fmt(v):>16}" for v in values))
    lines.append("")
    for r in runs:
        settings = ", ".join(f"{k}={v}" for k, v in r["settings"].items() if v is not None)
        lines.append(f"{r['label']}: {settings}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--flows", type=int, default=10,
                        help="Number of flagged flows to investigate (default 10)")
    parser.add_argument("--label", default="run", help="Name for this run")
    parser.add_argument("--compare", nargs="+", metavar="JSON",
                        help="Print saved results side by side instead of running")
    parser.add_argument("--concurrency", type=int,
                        help="Override INVESTIGATION_MAX_CONCURRENCY "
                             "(1 reproduces the old one-at-a-time behavior)")
    parser.add_argument("--rps", type=float,
                        help="Override LLM_REQUESTS_PER_SECOND")
    parser.add_argument("--no-rate-limit", action="store_true",
                        help="Disable request pacing (for a pre-limiter baseline)")
    args = parser.parse_args()

    # Overrides must land before the shared pool and limiter are created.
    if args.concurrency is not None:
        config.INVESTIGATION_MAX_CONCURRENCY = args.concurrency
    if args.rps is not None:
        config.LLM_REQUESTS_PER_SECOND = args.rps
    if args.no_rate_limit:
        config.LLM_REQUESTS_PER_SECOND = 1000.0
        config.LLM_MAX_BURST = 1000

    if args.compare:
        runs = [json.loads(Path(p).read_text()) for p in args.compare]
        print(format_results(*runs))
        return

    result = run_benchmark(args.flows, args.label)
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = BENCHMARK_DIR / f"{args.label}-{stamp}.json"
    out.write_text(json.dumps(result, indent=2))
    print()
    print(format_results(result))
    print(f"\n[*] Saved to {out}")


if __name__ == "__main__":
    main()
