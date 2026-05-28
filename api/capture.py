"""Live capture manager: drives a dumpcap ring buffer and auto-runs the
pipeline on each completed rotation.

Only one capture session runs at a time. dumpcap is spawned as the current
user, so /dev/bpf* must be readable (on macOS: `sudo chmod +r /dev/bpf*`).
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path

import config
from api.jobs import start_job_in_background, store

# Candidate dumpcap locations, in priority order.
_DUMPCAP_CANDIDATES = [
    "/opt/homebrew/bin/dumpcap",
    "/usr/local/bin/dumpcap",
    "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
]

CAPTURE_PREFIX = "live"


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
        self._processed: set[str] = set()

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

            config.PCAP_DIR.mkdir(parents=True, exist_ok=True)

            # Clear any stale live_*.pcapng so the watcher starts fresh
            self._cleanup_capture_files()

            out = config.PCAP_DIR / f"{CAPTURE_PREFIX}.pcapng"
            cmd = [
                dumpcap,
                "-i", iface,
                "-b", f"duration:{duration}",
                "-b", f"files:{files}",
                "-w", str(out),
            ]

            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            except Exception as e:
                self.status = "error"
                self.error = f"Failed to launch dumpcap: {e}"
                raise RuntimeError(self.error)

            # Give dumpcap a moment; if it exits immediately it's an error
            # (bad interface, permission denied on /dev/bpf*, etc.)
            time.sleep(0.6)
            if self._proc.poll() is not None:
                stderr = (self._proc.stderr.read() or b"").decode(errors="replace")
                self.status = "error"
                self.error = stderr.strip() or "dumpcap exited immediately"
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
            self._processed = set()
            self._stop_event.clear()

            self._watcher = threading.Thread(target=self._watch_loop, daemon=True)
            self._watcher.start()

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            if self._proc is not None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                self._proc = None

            # Let the watcher exit before deleting, so it can't spawn a job
            # against a file we're about to remove. The watcher doesn't take
            # self._lock, so joining here is deadlock-free.
            if self._watcher is not None:
                self._watcher.join(timeout=4.0)
                self._watcher = None

            self.files_cleaned = self._cleanup_capture_files()
            self.status = "stopped"

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
                self._submit_closed_rotations()
            except Exception as e:
                self.error = f"watcher error: {e}"
            # If dumpcap died unexpectedly, reflect that and stop watching
            if self._proc is not None and self._proc.poll() is not None:
                if not self._stop_event.is_set():
                    self.status = "error"
                    stderr = b""
                    if self._proc.stderr:
                        stderr = self._proc.stderr.read() or b""
                    self.error = (
                        stderr.decode(errors="replace").strip()
                        or "dumpcap exited unexpectedly"
                    )
                break
            self._stop_event.wait(timeout=3.0)

    def _submit_closed_rotations(self) -> None:
        files = sorted(config.PCAP_DIR.glob(f"{CAPTURE_PREFIX}_*.pcapng"))
        if len(files) <= 1:
            return
        # All but the last (still being written) are closed.
        for path in files[:-1]:
            if path.name in self._processed:
                continue
            job = store.create(
                pcap_path=str(path),
                pcap_name=path.name,
                detector=self.detector,
            )
            start_job_in_background(job)
            self._processed.add(path.name)
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
