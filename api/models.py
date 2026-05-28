"""Pydantic schemas for the API surface."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

JobStatus = Literal[
    "pending", "ingesting", "detecting", "investigating", "done", "error"
]


class PcapInfo(BaseModel):
    name: str
    size_bytes: int
    modified: float  # epoch seconds


class FlowDTO(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration: float
    packet_rate: float
    mean_packet_size: float
    flow_key: str


class FlaggedFlowDTO(BaseModel):
    flow: FlowDTO
    anomaly_score: float
    reason: str


class ThreatReportDTO(BaseModel):
    flow_key: str
    severity: str
    threat_type: str
    summary: str
    evidence: list[str] = []
    cve_ids: list[str] = []
    attack_techniques: list[str] = []
    remediation: str = ""


class RunRequest(BaseModel):
    # Provide exactly one of pcap_name (within data/pcaps/) or pcap_path (absolute local path).
    pcap_name: str | None = None
    pcap_path: str | None = None
    detector: Literal["stub", "lstm"] = "stub"


class LocalPcap(BaseModel):
    name: str
    path: str
    size_bytes: int
    modified: float


class LocalDirListing(BaseModel):
    path: str
    parent: str | None
    dirs: list[str] = []
    pcaps: list[LocalPcap] = []


class RunSummary(BaseModel):
    job_id: str
    pcap_name: str
    detector: str
    status: JobStatus
    started_at: float
    finished_at: float | None = None
    n_flows: int = 0
    n_flagged: int = 0
    n_reports: int = 0
    error: str | None = None


class RunDetail(RunSummary):
    flagged: list[FlaggedFlowDTO] = []
    reports: list[ThreatReportDTO] = []
    progress_done: int = 0
    progress_total: int = 0


class CaptureStartRequest(BaseModel):
    iface: str = "en0"
    duration: int = 60
    files: int = 10
    detector: Literal["stub", "lstm"] = "lstm"


class CaptureStatus(BaseModel):
    status: Literal["stopped", "running", "error"]
    error: str | None = None
    iface: str | None = None
    duration: int = 60
    files: int = 10
    detector: str = "lstm"
    started_at: float | None = None
    runs_triggered: int = 0
    last_file: str | None = None
    files_cleaned: int = 0
    dumpcap_available: bool = False
