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


class TimingDTO(BaseModel):
    """Where one investigation's time went, in seconds."""

    queued_s: float
    total_s: float
    llm_calls: int
    llm_s: float
    tool_calls: int
    tool_s: float
    input_tokens: int
    output_tokens: int


class ThreatReportDTO(BaseModel):
    flow_key: str
    severity: str
    threat_type: str
    summary: str
    evidence: list[str] = []
    cve_ids: list[str] = []
    attack_techniques: list[str] = []
    remediation: str = ""
    timing: TimingDTO | None = None


class RunRequest(BaseModel):
    # Provide exactly one of pcap_name (within data/pcaps/) or pcap_path (absolute local path).
    pcap_name: str | None = None
    pcap_path: str | None = None


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
    status: JobStatus
    started_at: float
    finished_at: float | None = None
    n_flows: int = 0
    n_flagged: int = 0
    n_reports: int = 0
    investigation_s: float | None = None
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
    save_for_training: bool = False


class CaptureStatus(BaseModel):
    status: Literal["stopped", "running", "error"]
    error: str | None = None
    iface: str | None = None
    duration: int = 60
    files: int = 10
    started_at: float | None = None
    runs_triggered: int = 0
    last_file: str | None = None
    files_cleaned: int = 0
    dumpcap_available: bool = False
    save_for_training: bool = False
    analysis_enabled: bool = True
    training_files_saved: int = 0


class HealthStatus(BaseModel):
    status: Literal["ok"] = "ok"
    model_ready: bool
    model_message: str | None = None
