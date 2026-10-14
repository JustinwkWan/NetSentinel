"""Live capture manager: drives a dumpcap ring buffer and auto-runs the
pipeline on each completed rotation.

Only one capture session runs at a time. dumpcap is spawned as the current
user, so /dev/bpf* must be readable (on macOS: `sudo chmod +r /dev/bpf*`).

dumpcap's stderr goes to config.CAPTURE_LOG_PATH rather than a pipe: nothing
drains a pipe while the capture runs, and a full pipe blocks dumpcap.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import BinaryIO

import config
from api.jobs import Job, start_job_in_background, store

# Candidate dumpcap locations, in priority order.
_DUMPCAP_CANDIDATES = [
    "/opt/homebrew/bin/dumpcap",
    "/usr/local/bin/dumpcap",
    "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
]

CAPTURE_PREFIX = "live"
_LOG_TAIL_BYTES = 4000


def find_dumpcap() -> str | None:
    found = shutil.which("dumpcap")
    if found:
        return found
    for candidate in _DUMPCAP_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


class CaptureManager:
    """Manages a single live-capture session and its watcher thread."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._watcher: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._log: BinaryIO | None = None
        # Rotation file name -> the job analyzing it, for this session
        self._jobs_by_file: dict[str, Job] = {}
        self._cleanup_thread: threading.Thread | None = None

        # Public-ish state (read under _lock)
        self.status: str = "stopped"  # stopped | running | error
        self.error: str | None = None
        self.iface: str | None = None
        self.duration: int = 60
        self.files: int = 10
        self.detector: str = "lstm"
        self.started_at: float | None = None
        self.runs_triggered: int = 0
        self.last_file: str | None = None
        self.files_cleaned: int = 0

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, iface: str, duration: int, files: int, detector: str) -> None:
        with self._lock:
            if self.is_running():
                raise RuntimeError("A capture is already running")

            dumpcap = find_dumpcap()
            if not dumpcap:
                self.status = "error"
                self.error = (
                    "dumpcap not found. Install Wireshark or ensure dumpcap is on PATH."
                )
                raise RuntimeError(self.error)

            # A previous session may still be waiting to delete its files
            # once their jobs have read them; let it finish first.
            if self._cleanup_thread is not None:
                self._cleanup_thread.join()
                self._cleanup_thread = None

            config.PCAP_DIR.mkdir(parents=True, exist_ok=True)

            # Clear any stale live_*.pcapng so the watcher starts fresh
            self._cleanup_capture_files()

            out = config.PCAP_DIR / f"{CAPTURE_PREFIX}.pcapng"
            cmd = [
                dumpcap,
                "-q",
                "-i", iface,
                "-b", f"duration:{duration}",
                "-b", f"files:{files}",
                "-w", str(out),
            ]

            # A session where dumpcap died on its own leaves its log open
            self._close_log()
            config.CAPTURE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            self._log = config.CAPTURE_LOG_PATH.open("wb")
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=self._log,
                    start_new_session=True,
                )
            except Exception as e:
                self._close_log()
                self.status = "error"
                self.error = f"Failed to launch dumpcap: {e}"
                raise RuntimeError(self.error)

            # Give dumpcap a moment; if it exits immediately it's an error
            # (bad interface, permission denied on /dev/bpf*, etc.)
            time.sleep(0.6)
            if self._proc.poll() is not None:
                self._close_log()
                self.status = "error"
                self.error = self._read_log_tail() or "dumpcap exited immediately"
                self._proc = None
                raise RuntimeError(self.error)

            self.status = "running"
            self.error = None
            self.iface = iface
            self.duration = duration
            self.files = files
            self.detector = detector
            self.started_at = time.time()
            self.runs_triggered = 0
            self.last_file = None
            self.files_cleaned = 0
            self._jobs_by_file = {}
            self._stop_event.clear()

            self._watcher = threading.Thread(target=self._watch_loop, daemon=True)
            self._watcher.start()

    def stop(self) -> None:
        with self._lock:
            if self._proc is None and self._watcher is None:
                self.status = "stopped"
                return

            self._stop_event.set()
            if self._proc is not None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()
                self._proc = None
            self._close_log()

            # Let the watcher exit first so only this thread submits jobs.
            # The watcher doesn't take self._lock, so joining is deadlock-free.
            if self._watcher is not None:
                self._watcher.join(timeout=4.0)
                self._watcher = None

            # dumpcap closes the in-progress rotation when it exits, so every
            # file is now complete. Analyze the final partial window too.
            self._submit_rotations(include_current=True)

            # Delete the files only after their jobs have read them, without
            # blocking this request on ingestion.
            jobs = list(self._jobs_by_file.values())
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_after_ingest, args=(jobs,), daemon=True
            )
            self._cleanup_thread.start()
            self.status = "stopped"

    def _cleanup_after_ingest(self, jobs: list[Job]) -> None:
        deadline = time.monotonic() + config.CAPTURE_INGEST_WAIT_SECONDS
        for job in jobs:
            job.ingested.wait(timeout=max(0.0, deadline - time.monotonic()))
        self.files_cleaned = self._cleanup_capture_files()

    def _close_log(self) -> None:
        if self._log is not None:
            self._log.close()
            self._log = None

    @staticmethod
    def _read_log_tail() -> str:
        try:
            data = config.CAPTURE_LOG_PATH.read_bytes()[-_LOG_TAIL_BYTES:]
        except OSError:
            return ""
        return data.decode(errors="replace").strip()

    def _cleanup_capture_files(self) -> int:
        """Delete all live_*.pcapng rotation files. Returns the count removed.

        On Unix, unlinking a file an in-flight job already opened is safe —
        the job's file descriptor keeps working until it closes.
        """
        removed = 0
        for f in config.PCAP_DIR.glob(f"{CAPTURE_PREFIX}_*.pcapng"):
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
        return removed

    def _watch_loop(self) -> None:
        """Poll the capture dir; submit each closed rotation exactly once."""
        while not self._stop_event.is_set():
            try:
                self._submit_rotations(include_current=False)
            except Exception as e:
                self.error = f"watcher error: {e}"
            # If dumpcap died unexpectedly, reflect that and stop watching
            if self._proc is not None and self._proc.poll() is not None:
                if not self._stop_event.is_set():
                    self.status = "error"
                    self.error = (
                        self._read_log_tail() or "dumpcap exited unexpectedly"
                    )
                break
            self._stop_event.wait(timeout=3.0)

    def _submit_rotations(self, include_current: bool) -> None:
        """Start a job for each rotation file not yet submitted.

        While dumpcap runs, the newest file is still being written, so it is
        skipped unless include_current is set (after dumpcap has exited).
        """
        files = sorted(config.PCAP_DIR.glob(f"{CAPTURE_PREFIX}_*.pcapng"))
        if not include_current:
            files = files[:-1]
        for path in files:
            if path.name in self._jobs_by_file:
                continue
            job = store.create(
                pcap_path=str(path),
                pcap_name=path.name,
                detector=self.detector,
            )
            start_job_in_background(job)
            self._jobs_by_file[path.name] = job
            self.runs_triggered += 1
            self.last_file = path.name

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "status": self.status,
                "error": self.error,
                "iface": self.iface,
                "duration": self.duration,
                "files": self.files,
                "detector": self.detector,
                "started_at": self.started_at,
                "runs_triggered": self.runs_triggered,
                "last_file": self.last_file,
                "files_cleaned": self.files_cleaned,
                "dumpcap_available": find_dumpcap() is not None,
            }


# Module-level singleton
manager = CaptureManager()
