"""Tests for the API layer: PCAP listing, job store, and live capture."""

from __future__ import annotations

import pathlib
import stat
import sys
import textwrap
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from api import capture
from api.capture import CaptureManager
from api.jobs import Job, JobStore, run_pipeline
from api.main import app

FAKE_DUMPCAP = textwrap.dedent('''
    """Stand-in for dumpcap: same CLI shape, writes empty rotation files."""
    import os, signal, sys, time

    args = sys.argv[1:]
    out = args[args.index("-w") + 1]
    if args[args.index("-i") + 1] == "bad":
        sys.stderr.write('dumpcap: There is no device named "bad".\\n')
        sys.exit(1)

    # Real dumpcap reports to stderr; write more than a pipe buffer holds
    # before producing any capture file.
    sys.stderr.write("x" * 256 * 1024)
    sys.stderr.flush()

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    base, ext = os.path.splitext(out)
    for n in (1, 2):
        open(f"{base}_{n:05d}_20261013000000{ext}", "wb").close()
    while True:
        time.sleep(0.05)
''')


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


@pytest.fixture
def pcap_dir(tmp_path, monkeypatch):
    d = tmp_path / "pcaps"
    d.mkdir()
    monkeypatch.setattr(config, "PCAP_DIR", d)
    return d


@pytest.fixture
def model_ready(monkeypatch):
    monkeypatch.setattr("netsentinel.detection.lstm.model_status", lambda path=None: None)


@pytest.fixture
def no_model(monkeypatch):
    from netsentinel.detection.lstm import NO_MODEL_MESSAGE
    monkeypatch.setattr("netsentinel.detection.lstm.model_status",
                        lambda path=None: NO_MODEL_MESSAGE)
    return NO_MODEL_MESSAGE


class TestModelReadiness:
    def test_health_reports_missing_model(self, no_model):
        body = TestClient(app).get("/health").json()
        assert body == {"status": "ok", "model_ready": False, "model_message": no_model}

    def test_health_reports_ready_model(self, model_ready):
        body = TestClient(app).get("/health").json()
        assert body == {"status": "ok", "model_ready": True, "model_message": None}

    def test_run_without_model_is_refused(self, no_model, pcap_dir):
        (pcap_dir / "x.pcap").write_bytes(b"")
        res = TestClient(app).post("/runs", json={"pcap_name": "x.pcap"})
        assert res.status_code == 409
        assert res.json()["detail"] == no_model


class TestListPcaps:
    def test_file_deleted_mid_listing_is_skipped(self, pcap_dir, monkeypatch):
        (pcap_dir / "kept.pcap").write_bytes(b"x" * 10)
        real_iterdir = pathlib.Path.iterdir

        class VanishingPath(type(pcap_dir)):
            """Exists when checked, deleted by the time it is stat'ed."""

            def is_file(self, **kwargs):
                return True

            def stat(self, **kwargs):
                raise FileNotFoundError(self)

        vanished = VanishingPath(pcap_dir / "live_00001_20261013000000.pcapng")

        # Simulate dumpcap's ring buffer deleting a rotation mid-listing.
        def iterdir_with_vanished(self):
            yield from real_iterdir(self)
            if self == pcap_dir:
                yield vanished

        monkeypatch.setattr(pathlib.Path, "iterdir", iterdir_with_vanished)

        res = TestClient(app).get("/pcaps")
        assert res.status_code == 200
        assert [p["name"] for p in res.json()] == ["kept.pcap"]


class TestJobStore:
    def test_oldest_finished_jobs_are_evicted(self, monkeypatch):
        monkeypatch.setattr(config, "API_MAX_JOBS_RETAINED", 2)
        store = JobStore()
        jobs = [store.create(f"/p{i}", f"p{i}") for i in range(3)]
        for i, job in enumerate(jobs):
            job.started_at = 1000.0 + i
            job.status = "done"
        running = store.create("/p3", "p3")
        running.started_at = 900.0  # older than all, but still active

        ids = {j.job_id for j in store.list()}
        assert jobs[0].job_id not in ids
        assert {jobs[1].job_id, jobs[2].job_id, running.job_id} <= ids

    def test_failed_ingest_still_signals_ingested(self, tmp_path):
        job = Job(job_id="j", pcap_path=str(tmp_path / "missing.pcap"),
                  pcap_name="missing.pcap")
        run_pipeline(job)
        assert job.status == "error"
        assert job.ingested.is_set()


@pytest.fixture
def fake_dumpcap(tmp_path, pcap_dir, monkeypatch):
    script = tmp_path / "fake_dumpcap.py"
    script.write_text(FAKE_DUMPCAP)
    wrapper = tmp_path / "dumpcap"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)

    submitted: list[Job] = []
    monkeypatch.setattr(capture, "find_dumpcap", lambda: str(wrapper))
    monkeypatch.setattr(capture, "start_job_in_background", submitted.append)
    monkeypatch.setattr(config, "CAPTURE_LOG_PATH", tmp_path / "logs" / "dumpcap.log")
    return submitted


class TestCaptureManager:
    def _rotation_files(self, pcap_dir: Path) -> list[Path]:
        return sorted(pcap_dir.glob("live_*.pcapng"))

    def test_capture_progresses_despite_heavy_stderr(self, fake_dumpcap, pcap_dir):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10)
        try:
            assert _wait_for(lambda: len(self._rotation_files(pcap_dir)) == 2), (
                "dumpcap stalled before writing its capture files"
            )
        finally:
            mgr.stop()

    def test_stop_analyzes_final_window_and_waits_for_ingest(
        self, fake_dumpcap, pcap_dir
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10)
        assert _wait_for(lambda: len(self._rotation_files(pcap_dir)) == 2)
        mgr.stop()

        # Both the closed rotation and the in-progress one were submitted.
        names = [p.name for p in self._rotation_files(pcap_dir)]
        assert sorted(j.pcap_name for j in fake_dumpcap) == names
        assert mgr.snapshot()["status"] == "stopped"

        # Files stay on disk until their jobs have read them.
        time.sleep(0.2)
        assert len(self._rotation_files(pcap_dir)) == 2

        for job in fake_dumpcap:
            job.ingested.set()
        mgr._cleanup_thread.join(timeout=5)
        assert self._rotation_files(pcap_dir) == []
        assert mgr.snapshot()["files_cleaned"] == 2

    def test_startup_failure_reports_dumpcap_error(self, fake_dumpcap):
        mgr = CaptureManager()
        with pytest.raises(RuntimeError, match='no device named "bad"'):
            mgr.start(iface="bad", duration=60, files=10)
        assert mgr.snapshot()["status"] == "error"

    def test_stop_without_session_is_noop(self, fake_dumpcap):
        mgr = CaptureManager()
        mgr.stop()
        assert mgr.snapshot()["status"] == "stopped"
        assert fake_dumpcap == []
