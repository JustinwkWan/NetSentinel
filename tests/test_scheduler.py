"""Tests for parallel investigations, rate limiting, and timing."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from api.jobs import Job, run_pipeline
from netsentinel import llm
from netsentinel.agent import scheduler
from netsentinel.agent.report import ThreatReport
from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord

MAX_WORKERS = 3


def _flagged(n: int) -> list[FlaggedFlow]:
    return [
        FlaggedFlow(
            flow=FlowRecord("10.0.0.1", "10.0.0.2", 40000 + i, 4444, "TCP",
                            10, 1000, 1.0, 0.0),
            anomaly_score=0.9,
            reason="test",
        )
        for i in range(n)
    ]


class ConcurrencyProbe:
    """Stand-in for investigate_flow that records peak concurrency."""

    def __init__(self, delay: float = 0.05, fail_ports: set[int] | None = None):
        self.delay = delay
        self.fail_ports = fail_ports or set()
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()

    def __call__(self, flagged: FlaggedFlow, timing=None) -> ThreatReport:
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            # Later flows finish first, to prove results keep input order.
            time.sleep(self.delay * (1 + (50000 - flagged.flow.src_port) % 3))
            if flagged.flow.src_port in self.fail_ports:
                raise RuntimeError("provider exploded")
            return ThreatReport(flow_key=flagged.flow.flow_key, severity="high",
                                threat_type="t", summary="s")
        finally:
            with self._lock:
                self.active -= 1


@pytest.fixture
def pool(monkeypatch):
    """A fresh shared pool capped at MAX_WORKERS for each test."""
    monkeypatch.setattr(config, "INVESTIGATION_MAX_CONCURRENCY", MAX_WORKERS)
    monkeypatch.setattr(scheduler, "_executor", None)
    yield
    if scheduler._executor is not None:
        scheduler._executor.shutdown(wait=True)


class TestInvestigateAll:
    def test_runs_in_parallel_up_to_the_cap(self, pool, monkeypatch):
        probe = ConcurrencyProbe()
        monkeypatch.setattr(scheduler, "investigate_flow", probe)

        scheduler.investigate_all(_flagged(10))

        assert probe.peak == MAX_WORKERS

    def test_cap_is_shared_across_concurrent_batches(self, pool, monkeypatch):
        probe = ConcurrencyProbe()
        monkeypatch.setattr(scheduler, "investigate_flow", probe)

        batches = [
            threading.Thread(target=scheduler.investigate_all, args=(_flagged(6),))
            for _ in range(3)
        ]
        for t in batches:
            t.start()
        for t in batches:
            t.join()

        assert probe.peak == MAX_WORKERS

    def test_results_keep_input_order_and_report_each_once(self, pool, monkeypatch):
        monkeypatch.setattr(scheduler, "investigate_flow", ConcurrencyProbe())
        flagged = _flagged(7)
        seen: list[int] = []
        seen_lock = threading.Lock()

        def on_result(index, result):
            with seen_lock:
                seen.append(index)

        results = scheduler.investigate_all(flagged, on_result=on_result)

        assert [r.flagged for r in results] == flagged
        assert sorted(seen) == list(range(7))

    def test_failure_is_isolated_to_its_flow(self, pool, monkeypatch):
        flagged = _flagged(4)
        bad_port = flagged[1].flow.src_port
        monkeypatch.setattr(scheduler, "investigate_flow",
                            ConcurrencyProbe(fail_ports={bad_port}))

        results = scheduler.investigate_all(flagged)

        assert results[1].report is None
        assert results[1].error == "provider exploded"
        assert all(r.report is not None for i, r in enumerate(results) if i != 1)

    def test_queue_wait_is_measured(self, pool, monkeypatch):
        monkeypatch.setattr(scheduler, "investigate_flow", ConcurrencyProbe())

        results = scheduler.investigate_all(_flagged(MAX_WORKERS + 2))

        assert all(r.timing.queued_s < 0.05 for r in results[:MAX_WORKERS])
        assert all(r.timing.queued_s >= 0.04 for r in results[MAX_WORKERS:])


class TestRunPipelineOrdering:
    def test_reports_follow_flagged_order(self, pool, monkeypatch, tmp_path):
        flagged = _flagged(5)
        monkeypatch.setattr(scheduler, "investigate_flow", ConcurrencyProbe())
        monkeypatch.setattr("api.jobs.process_packets", lambda source: [f.flow for f in flagged])

        class FlagAll:
            def flag(self, flows):
                return flagged

        monkeypatch.setattr("api.jobs._load_detector", lambda name: FlagAll())
        job = Job(job_id="j", pcap_path=str(tmp_path / "x.pcap"),
                  pcap_name="x.pcap", detector="stub")

        run_pipeline(job)

        assert job.status == "done"
        assert [r.flow_key for r in job.reports] == [f.flow.flow_key for f in flagged]
        assert job.n_reports == job.progress_done == 5
        assert job.investigation_s is not None
        assert all(r.timing is not None for r in job.reports)


class TestRateLimiter:
    @pytest.fixture
    def fresh_limiter(self, monkeypatch):
        monkeypatch.setattr(llm, "_rate_limiter", None)

    def test_every_chat_model_shares_one_limiter(self, fresh_limiter):
        agent = llm.make_chat_model()
        judge = llm.make_chat_model(model="some-judge-model")
        assert agent.rate_limiter is judge.rate_limiter is llm.get_rate_limiter()

    def test_chat_models_use_configured_retry_and_timeout(self, fresh_limiter):
        model = llm.make_chat_model()
        assert model.max_retries == config.LLM_MAX_RETRIES
        assert model.default_request_timeout == config.LLM_TIMEOUT_SECONDS

    def test_limiter_paces_requests_and_records_wait(self, fresh_limiter, monkeypatch):
        monkeypatch.setattr(config, "LLM_REQUESTS_PER_SECOND", 20.0)
        monkeypatch.setattr(config, "LLM_MAX_BURST", 1)
        limiter = llm.get_rate_limiter()

        start = time.perf_counter()
        for _ in range(5):
            limiter.acquire()
        elapsed = time.perf_counter() - start

        # 20/s with no burst allowance: 5 requests need at least ~4 gaps.
        assert elapsed >= 4 / 20 * 0.9
        stats = limiter.stats()
        assert stats.requests == 5
        assert stats.wait_s == pytest.approx(elapsed, abs=0.05)
