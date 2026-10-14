"""Runs agent investigations on a shared, bounded worker pool.

All investigations in the process (every API run, every live-capture window,
the CLI) share one pool of INVESTIGATION_MAX_CONCURRENCY workers. Flows in a
batch run in parallel, while total concurrency stays capped no matter how
many batches are active. Batches queue first-in, first-out.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import config
from netsentinel.agent.graph import investigate_flow
from netsentinel.agent.report import ThreatReport
from netsentinel.agent.timing import InvestigationTiming
from netsentinel.detection.base import FlaggedFlow


@dataclass
class InvestigationResult:
    """Outcome of one flow's investigation: a report or an error."""

    flagged: FlaggedFlow
    timing: InvestigationTiming
    report: ThreatReport | None = None
    error: str | None = None


ResultCallback = Callable[[int, InvestigationResult], None]


def _investigate(flagged: FlaggedFlow, submitted_at: float) -> InvestigationResult:
    timing = InvestigationTiming(queued_s=time.perf_counter() - submitted_at)
    try:
        report = investigate_flow(flagged, timing=timing)
    except Exception as e:  # one bad flow must not sink the batch
        return InvestigationResult(flagged=flagged, timing=timing, error=str(e))
    return InvestigationResult(flagged=flagged, timing=timing, report=report)


_executor: ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=config.INVESTIGATION_MAX_CONCURRENCY,
                thread_name_prefix="investigation",
            )
        return _executor


def investigate_all(
    flagged: list[FlaggedFlow], on_result: ResultCallback | None = None
) -> list[InvestigationResult]:
    """Investigate every flow on the shared pool; results in input order.

    on_result(index, result) is called from a worker thread as each
    investigation finishes, so it must be thread-safe.
    """
    submitted_at = time.perf_counter()

    def task(index: int, ff: FlaggedFlow) -> InvestigationResult:
        result = _investigate(ff, submitted_at)
        if on_result is not None:
            on_result(index, result)
        return result

    executor = _get_executor()
    futures = [executor.submit(task, i, ff) for i, ff in enumerate(flagged)]
    return [f.result() for f in futures]
