"""FastAPI app: serves PCAP listing, run submission, and run polling."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

import config
from api.capture import manager
from api.jobs import start_job_in_background, store
from api.models import (
    CaptureStartRequest,
    CaptureStatus,
    LocalDirListing,
    LocalPcap,
    PcapInfo,
    RunDetail,
    RunRequest,
    RunSummary,
)

PCAP_SUFFIXES = (".pcap", ".pcapng")

app = FastAPI(title="NetSentinel API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _pcap_dir() -> Path:
    config.PCAP_DIR.mkdir(parents=True, exist_ok=True)
    return config.PCAP_DIR


def _resolve_pcap(name: str) -> Path:
    # Block path traversal — only allow plain filenames under PCAP_DIR
    if "/" in name or "\\" in name or name.startswith("."):
        raise HTTPException(400, "Invalid pcap name")
    path = _pcap_dir() / name
    if not path.is_file():
        raise HTTPException(404, f"PCAP not found: {name}")
    return path


def _resolve_local_path(raw: str) -> Path:
    # Local single-user tool: any readable absolute path the user picks is allowed.
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise HTTPException(404, f"File not found: {path}")
    if path.suffix.lower() not in PCAP_SUFFIXES:
        raise HTTPException(400, "Only .pcap and .pcapng files are accepted")
    return path


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/pcaps", response_model=list[PcapInfo])
def list_pcaps() -> list[PcapInfo]:
    pcap_dir = _pcap_dir()
    paths = [
        p for p in pcap_dir.iterdir()
        if p.is_file() and p.suffix.lower() in PCAP_SUFFIXES
    ]
    return [
        PcapInfo(
            name=p.name,
            size_bytes=p.stat().st_size,
            modified=p.stat().st_mtime,
        )
        for p in sorted(paths)
    ]


@app.post("/pcaps/upload", response_model=PcapInfo)
def upload_pcap(file: UploadFile = File(...)) -> PcapInfo:
    if not file.filename:
        raise HTTPException(400, "Missing filename")
    if not file.filename.lower().endswith(PCAP_SUFFIXES):
        raise HTTPException(400, "Only .pcap and .pcapng files are accepted")
    safe_name = Path(file.filename).name  # strip any directory traversal
    target = _pcap_dir() / safe_name
    with target.open("wb") as out:
        shutil.copyfileobj(file.file, out)
    st = target.stat()
    return PcapInfo(name=target.name, size_bytes=st.st_size, modified=st.st_mtime)


@app.post("/runs", response_model=RunSummary)
def create_run(req: RunRequest) -> RunSummary:
    if bool(req.pcap_name) == bool(req.pcap_path):
        raise HTTPException(400, "Provide exactly one of pcap_name or pcap_path")

    if req.pcap_path:
        path = _resolve_local_path(req.pcap_path)
        pcap_name = path.name
    else:
        path = _resolve_pcap(req.pcap_name)
        pcap_name = req.pcap_name

    job = store.create(
        pcap_path=str(path),
        pcap_name=pcap_name,
        detector=req.detector,
    )
    start_job_in_background(job)
    return job.to_summary()


@app.get("/local/browse", response_model=LocalDirListing)
def local_browse(path: str | None = None) -> LocalDirListing:
    base = (Path(path).expanduser() if path else Path.home()).resolve()
    if not base.is_dir():
        raise HTTPException(400, f"Not a directory: {base}")

    dirs: list[str] = []
    pcaps: list[LocalPcap] = []
    try:
        entries = sorted(base.iterdir(), key=lambda p: p.name.lower())
    except PermissionError:
        raise HTTPException(403, f"Permission denied: {base}")

    for entry in entries:
        try:
            if entry.is_dir():
                if not entry.name.startswith("."):
                    dirs.append(entry.name)
            elif entry.is_file() and entry.suffix.lower() in PCAP_SUFFIXES:
                st = entry.stat()
                pcaps.append(
                    LocalPcap(
                        name=entry.name,
                        path=str(entry),
                        size_bytes=st.st_size,
                        modified=st.st_mtime,
                    )
                )
        except (PermissionError, OSError):
            continue

    parent = str(base.parent) if base.parent != base else None
    return LocalDirListing(path=str(base), parent=parent, dirs=dirs, pcaps=pcaps)


@app.get("/runs", response_model=list[RunSummary])
def list_runs() -> list[RunSummary]:
    return [j.to_summary() for j in store.list()]


@app.get("/runs/{job_id}", response_model=RunDetail)
def get_run(job_id: str) -> RunDetail:
    job = store.get(job_id)
    if not job:
        raise HTTPException(404, f"Run not found: {job_id}")
    return job.to_detail()


@app.post("/capture/start", response_model=CaptureStatus)
def capture_start(req: CaptureStartRequest) -> CaptureStatus:
    try:
        manager.start(
            iface=req.iface,
            duration=req.duration,
            files=req.files,
            detector=req.detector,
        )
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    return CaptureStatus(**manager.snapshot())


@app.post("/capture/stop", response_model=CaptureStatus)
def capture_stop() -> CaptureStatus:
    manager.stop()
    return CaptureStatus(**manager.snapshot())


@app.get("/capture/status", response_model=CaptureStatus)
def capture_status() -> CaptureStatus:
    return CaptureStatus(**manager.snapshot())
