"""Tests for the API layer: PCAP listing, job store, and live capture."""

from __future__ import annotations

import os
import pathlib
import stat
import subprocess
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


class TestPcapRoutes:
    def test_lists_only_pcap_files_in_name_order(self, pcap_dir):
        (pcap_dir / "b.pcapng").write_bytes(b"x" * 7)
        (pcap_dir / "a.PCAP").write_bytes(b"")
        (pcap_dir / "notes.txt").write_text("not a capture")
        (pcap_dir / "dir.pcap").mkdir()

        body = TestClient(app).get("/pcaps").json()

        assert [(p["name"], p["size_bytes"]) for p in body] == [("a.PCAP", 0), ("b.pcapng", 7)]

    def test_upload_saves_the_file(self, pcap_dir):
        res = TestClient(app).post(
            "/pcaps/upload", files={"file": ("cap.pcap", b"\xd4\xc3\xb2\xa1", "application/octet-stream")})
        assert res.status_code == 200
        assert res.json()["name"] == "cap.pcap" and res.json()["size_bytes"] == 4
        assert (pcap_dir / "cap.pcap").read_bytes() == b"\xd4\xc3\xb2\xa1"

    def test_upload_strips_directories_from_the_name(self, pcap_dir):
        res = TestClient(app).post(
            "/pcaps/upload", files={"file": ("../../evil.pcap", b"x", "application/octet-stream")})
        assert res.json()["name"] == "evil.pcap"
        assert (pcap_dir / "evil.pcap").exists()
        assert not (pcap_dir.parent.parent / "evil.pcap").exists()

    def test_upload_rejects_other_file_types(self, pcap_dir):
        res = TestClient(app).post(
            "/pcaps/upload", files={"file": ("run.sh", b"x", "text/plain")})
        assert res.status_code == 400
        assert list(pcap_dir.iterdir()) == []


@pytest.fixture
def submitted(monkeypatch):
    jobs = []
    monkeypatch.setattr("api.main.start_job_in_background", jobs.append)
    return jobs


class TestRunRoutes:
    def test_run_on_a_listed_pcap(self, pcap_dir, model_ready, submitted):
        (pcap_dir / "x.pcap").write_bytes(b"")
        client = TestClient(app)

        res = client.post("/runs", json={"pcap_name": "x.pcap"})

        assert res.status_code == 200
        run = res.json()
        assert (run["pcap_name"], run["status"]) == ("x.pcap", "pending")
        assert [j.pcap_path for j in submitted] == [str(pcap_dir / "x.pcap")]
        assert client.get(f"/runs/{run['job_id']}").json()["job_id"] == run["job_id"]
        assert run["job_id"] in [r["job_id"] for r in client.get("/runs").json()]

    def test_run_on_a_local_path(self, tmp_path, model_ready, submitted):
        pcap = tmp_path / "elsewhere" / "cap.pcapng"
        pcap.parent.mkdir()
        pcap.write_bytes(b"")

        res = TestClient(app).post("/runs", json={"pcap_path": str(pcap)})

        assert res.status_code == 200
        assert res.json()["pcap_name"] == "cap.pcapng"
        assert submitted[0].pcap_path == str(pcap.resolve())

    @pytest.mark.parametrize("body", [{}, {"pcap_name": "a.pcap", "pcap_path": "/a.pcap"}])
    def test_exactly_one_source_is_required(self, body, model_ready, submitted):
        assert TestClient(app).post("/runs", json=body).status_code == 400
        assert submitted == []

    @pytest.mark.parametrize("name", ["../secret.pcap", "a/b.pcap", "a\\b.pcap", ".hidden.pcap"])
    def test_pcap_names_cannot_leave_the_pcap_dir(self, name, pcap_dir, model_ready, submitted):
        res = TestClient(app).post("/runs", json={"pcap_name": name})
        assert res.status_code == 400
        assert submitted == []

    def test_unknown_pcap_name_is_404(self, pcap_dir, model_ready, submitted):
        assert TestClient(app).post("/runs", json={"pcap_name": "nope.pcap"}).status_code == 404

    def test_local_path_must_exist_and_be_a_pcap(self, tmp_path, model_ready, submitted):
        text = tmp_path / "notes.txt"
        text.write_text("x")
        client = TestClient(app)
        assert client.post("/runs", json={"pcap_path": str(text)}).status_code == 400
        assert client.post("/runs", json={"pcap_path": str(tmp_path / "gone.pcap")}).status_code == 404
        assert submitted == []

    def test_unknown_run_is_404(self):
        assert TestClient(app).get("/runs/does-not-exist").status_code == 404


class TestLocalBrowse:
    def test_lists_visible_dirs_and_pcaps(self, tmp_path):
        (tmp_path / "Captures").mkdir()
        (tmp_path / ".cache").mkdir()
        (tmp_path / "b.pcap").write_bytes(b"xy")
        (tmp_path / "A.pcapng").write_bytes(b"")
        (tmp_path / "readme.md").write_text("x")

        body = TestClient(app).get("/local/browse", params={"path": str(tmp_path)}).json()

        assert body["path"] == str(tmp_path.resolve())
        assert body["parent"] == str(tmp_path.resolve().parent)
        assert body["dirs"] == ["Captures"]
        assert [(p["name"], p["size_bytes"]) for p in body["pcaps"]] == [("A.pcapng", 0), ("b.pcap", 2)]

    def test_defaults_to_home(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
        assert TestClient(app).get("/local/browse").json()["path"] == str(tmp_path.resolve())

    def test_filesystem_root_has_no_parent(self):
        assert TestClient(app).get("/local/browse", params={"path": "/"}).json()["parent"] is None

    def test_file_is_not_a_directory(self, tmp_path):
        f = tmp_path / "a.pcap"
        f.write_bytes(b"")
        assert TestClient(app).get("/local/browse", params={"path": str(f)}).status_code == 400

    def test_unreadable_directory_is_403(self, tmp_path, monkeypatch):
        def deny(self):
            raise PermissionError(self)

        monkeypatch.setattr(pathlib.Path, "iterdir", deny)
        res = TestClient(app).get("/local/browse", params={"path": str(tmp_path)})
        assert res.status_code == 403


class TestCaptureRoutes:
    def test_errors_map_to_status_codes(self, monkeypatch):
        from netsentinel.detection.lstm import ModelNotTrainedError

        class Manager:
            def __init__(self, error):
                self.error = error

            def start(self, **kwargs):
                raise self.error

            def snapshot(self):
                return {"status": "stopped"}

        client = TestClient(app)
        monkeypatch.setattr("api.main.manager", Manager(ModelNotTrainedError("train first")))
        res = client.post("/capture/start", json={})
        assert (res.status_code, res.json()["detail"]) == (409, "train first")

        monkeypatch.setattr("api.main.manager", Manager(RuntimeError("dumpcap missing")))
        res = client.post("/capture/start", json={})
        assert (res.status_code, res.json()["detail"]) == (400, "dumpcap missing")

    def test_start_passes_settings_and_reports_status(self, monkeypatch):
        calls = []

        class Manager:
            def start(self, **kwargs):
                calls.append(kwargs)

            def stop(self):
                calls.append("stop")

            def snapshot(self):
                return {"status": "running", "iface": "en1"}

        monkeypatch.setattr("api.main.manager", Manager())
        client = TestClient(app)
        res = client.post("/capture/start", json={"iface": "en1", "duration": 30,
                                                  "files": 5, "save_for_training": True})
        assert res.json()["status"] == "running"
        assert calls == [{"iface": "en1", "duration": 30, "files": 5,
                          "save_for_training": True}]
        assert client.get("/capture/status").json()["iface"] == "en1"
        client.post("/capture/stop")
        assert calls[-1] == "stop"


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


@pytest.fixture(autouse=True)
def no_leaked_processes(monkeypatch):
    """Terminate any dumpcap a test started, even when the test failed
    before stopping its capture."""
    started: list[subprocess.Popen] = []
    real_popen = capture.subprocess.Popen

    def tracking_popen(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        started.append(proc)
        return proc

    monkeypatch.setattr(capture.subprocess, "Popen", tracking_popen)
    yield
    for proc in started:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


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
    monkeypatch.setattr(config, "CAPTURE_PID_PATH", tmp_path / "logs" / "dumpcap.pid")
    monkeypatch.setattr(capture, "_FAKE_DUMPCAP_WRAPPER", str(wrapper), raising=False)
    return submitted


class TestCaptureManager:
    def _rotation_files(self, pcap_dir: Path) -> list[Path]:
        return sorted(pcap_dir.glob("live_*.pcapng"))

    def test_capture_progresses_despite_heavy_stderr(
        self, fake_dumpcap, pcap_dir, model_ready
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10)
        try:
            assert _wait_for(lambda: len(self._rotation_files(pcap_dir)) == 2), (
                "dumpcap stalled before writing its capture files"
            )
        finally:
            mgr.stop()

    def test_stop_analyzes_final_window_and_waits_for_ingest(
        self, fake_dumpcap, pcap_dir, model_ready
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

    def test_startup_failure_reports_dumpcap_error(self, fake_dumpcap, model_ready):
        mgr = CaptureManager()
        with pytest.raises(RuntimeError, match='no device named "bad"'):
            mgr.start(iface="bad", duration=60, files=10)
        assert mgr.snapshot()["status"] == "error"

    def test_stop_without_session_is_noop(self, fake_dumpcap):
        mgr = CaptureManager()
        mgr.stop()
        assert mgr.snapshot()["status"] == "stopped"
        assert fake_dumpcap == []


@pytest.fixture
def training_dir(tmp_path, monkeypatch):
    d = tmp_path / "training"
    monkeypatch.setattr(config, "TRAINING_DIR", d)
    return d


class TestTrainingCapture:
    def _finish(self, mgr, submitted):
        mgr.stop()
        for job in submitted:
            job.ingested.set()
        if mgr._cleanup_thread is not None:
            mgr._cleanup_thread.join(timeout=5)

    def test_saved_windows_survive_cleanup(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10, save_for_training=True)
        assert _wait_for(lambda: len(list(pcap_dir.glob("live_*.pcapng"))) == 2)
        self._finish(mgr, fake_dumpcap)

        assert list(pcap_dir.glob("live_*.pcapng")) == []
        assert sorted(p.name for p in training_dir.iterdir()) == [
            "live_00001_20261013000000.pcapng", "live_00002_20261013000000.pcapng"]
        snap = mgr.snapshot()
        assert snap["training_files_saved"] == 2
        assert snap["save_for_training"] is True
        assert len(fake_dumpcap) == 2  # analysis still ran

    def test_toggle_off_saves_nothing(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10)
        assert _wait_for(lambda: len(list(pcap_dir.glob("live_*.pcapng"))) == 2)
        self._finish(mgr, fake_dumpcap)
        assert not training_dir.exists() or list(training_dir.iterdir()) == []

    def test_no_model_collects_without_analysis(
        self, fake_dumpcap, pcap_dir, training_dir, no_model
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10, save_for_training=True)
        assert mgr.snapshot()["analysis_enabled"] is False
        assert _wait_for(lambda: len(list(pcap_dir.glob("live_*.pcapng"))) == 2)
        self._finish(mgr, fake_dumpcap)

        assert fake_dumpcap == []
        assert len(list(training_dir.iterdir())) == 2
        assert mgr.snapshot()["runs_triggered"] == 0

    def test_no_model_without_toggle_is_refused(self, fake_dumpcap, no_model):
        res = TestClient(app).post("/capture/start", json={"iface": "en0"})
        assert res.status_code == 409
        assert res.json()["detail"] == no_model

    def test_already_saved_window_is_not_saved_twice(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10, save_for_training=True)
        assert _wait_for(lambda: len(list(pcap_dir.glob("live_*.pcapng"))) == 2)
        # The watcher saw the closed window; stop rescans every file.
        assert _wait_for(lambda: mgr.snapshot()["training_files_saved"] == 1)
        self._finish(mgr, fake_dumpcap)
        assert mgr.snapshot()["training_files_saved"] == 2


class TestTrainingSaveFailure:
    def test_failed_save_still_analyzes_and_stops_cleanly(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready, monkeypatch
    ):
        def refuse(*args, **kwargs):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(capture.os, "link", refuse)
        monkeypatch.setattr(capture.shutil, "copy2", refuse)

        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10, save_for_training=True)
        assert _wait_for(lambda: len(fake_dumpcap) == 1), "closed window not analyzed"
        mgr.stop()

        snap = mgr.snapshot()
        assert snap["status"] == "stopped"
        assert len(fake_dumpcap) == 2  # the final window was analyzed too
        assert snap["training_files_saved"] == 0
        assert "No space left on device" in snap["error"]
        for job in fake_dumpcap:
            job.ingested.set()
        mgr._cleanup_thread.join(timeout=5)
        assert list(pcap_dir.glob("live_*.pcapng")) == []

    def test_partial_copy_is_removed(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready, monkeypatch
    ):
        def refuse_link(*args, **kwargs):
            raise OSError(18, "Cross-device link")

        def partial_copy(src, dst, *args, **kwargs):
            Path(dst).write_bytes(b"partial")
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(capture.os, "link", refuse_link)
        monkeypatch.setattr(capture.shutil, "copy2", partial_copy)

        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10, save_for_training=True)
        assert _wait_for(lambda: len(fake_dumpcap) == 1)
        mgr.stop()

        assert list(training_dir.iterdir()) == []


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); ask ps whether it really runs
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                           capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


class TestOrphanedCapture:
    def test_server_shutdown_stops_the_capture(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready, monkeypatch
    ):
        mgr = CaptureManager()
        monkeypatch.setattr("api.main.manager", mgr)
        with TestClient(app) as client:
            res = client.post("/capture/start", json={"iface": "en0"})
            assert res.status_code == 200
            pid = mgr._proc.pid
        # Leaving the client runs the app's shutdown, as a reload or Ctrl-C does
        assert _wait_for(lambda: not _alive(pid)), "dumpcap outlived the server"

    def test_start_stops_a_capture_orphaned_by_a_crash(
        self, fake_dumpcap, pcap_dir, model_ready
    ):
        # A previous server was killed outright and left its dumpcap running
        orphan = subprocess.Popen(
            [capture._FAKE_DUMPCAP_WRAPPER, "-q", "-i", "en0",
             "-w", str(pcap_dir / "live.pcapng")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        config.CAPTURE_PID_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.CAPTURE_PID_PATH.write_text(str(orphan.pid))
        try:
            mgr = CaptureManager()
            mgr.start(iface="en0", duration=60, files=10)
            try:
                assert orphan.wait(timeout=5) is not None
                assert config.CAPTURE_PID_PATH.read_text() == str(mgr._proc.pid)
            finally:
                mgr.stop()
            assert not config.CAPTURE_PID_PATH.exists()
        finally:
            if orphan.poll() is None:
                orphan.kill()

    def test_unrelated_process_in_pid_file_is_left_alone(
        self, fake_dumpcap, pcap_dir, model_ready
    ):
        bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        config.CAPTURE_PID_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.CAPTURE_PID_PATH.write_text(str(bystander.pid))
        try:
            mgr = CaptureManager()
            mgr.start(iface="en0", duration=60, files=10)
            mgr.stop()
            assert bystander.poll() is None
        finally:
            bystander.kill()
            bystander.wait()
