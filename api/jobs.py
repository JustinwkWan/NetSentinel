"""In-memory job store + background runner for pipeline runs."""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field

from api.models import (
    FlaggedFlowDTO,
    FlowDTO,
    JobStatus,
    RunDetail,
    RunSummary,
    ThreatReportDTO,
)
from netsentinel.agent.graph import investigate_flow
from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord
from netsentinel.ingestion.sources import PcapFileSource, process_packets


def _flow_to_dto(flow: FlowRecord) -> FlowDTO:
    return FlowDTO(
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        protocol=flow.protocol,
        packet_count=flow.packet_count,
        byte_count=flow.byte_count,
        duration=flow.duration,
        packet_rate=flow.packet_rate,
        mean_packet_size=flow.mean_packet_size,
        flow_key=flow.flow_key,
    )


def _flagged_to_dto(ff: FlaggedFlow) -> FlaggedFlowDTO:
    return FlaggedFlowDTO(
        flow=_flow_to_dto(ff.flow),
        anomaly_score=ff.anomaly_score,
        reason=ff.reason,
    )


def _load_detector(name: str):
    if name == "stub":
        from netsentinel.detection.stub import StubDetector
        return StubDetector()
    if name == "lstm":
        from netsentinel.detection.lstm import LstmDetector
        return LstmDetector()
    raise ValueError(f"Unknown detector: {name}")


@dataclass
class Job:
    job_id: str
    pcap_path: str
    pcap_name: str
    detector: str
    status: JobStatus = "pending"
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    n_flows: int = 0
    n_flagged: int = 0
    n_reports: int = 0
    progress_done: int = 0
    progress_total: int = 0
    flagged: list[FlaggedFlowDTO] = field(default_factory=list)
    reports: list[ThreatReportDTO] = field(default_factory=list)
    error: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def to_summary(self) -> RunSummary:
        return RunSummary(
            job_id=self.job_id,
            pcap_name=self.pcap_name,
            detector=self.detector,
            status=self.status,
            started_at=self.started_at,
            finished_at=self.finished_at,
            n_flows=self.n_flows,
            n_flagged=self.n_flagged,
            n_reports=self.n_reports,
            error=self.error,
        )

    def to_detail(self) -> RunDetail:
        return RunDetail(
            **self.to_summary().model_dump(),
            flagged=list(self.flagged),
            reports=list(self.reports),
            progress_done=self.progress_done,
            progress_total=self.progress_total,
        )


class JobStore:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, pcap_path: str, pcap_name: str, detector: str) -> Job:
        job_id = uuid.uuid4().hex[:12]
        job = Job(
            job_id=job_id,
            pcap_path=pcap_path,
            pcap_name=pcap_name,
            detector=detector,
        )
        with self._lock:
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(
                self._jobs.values(),
                key=lambda j: j.started_at,
                reverse=True,
            )


def run_pipeline(job: Job) -> None:
    """Execute the full pipeline for a job. Updates job state in place."""
    try:
        job.status = "ingesting"
        source = PcapFileSource(job.pcap_path)
        flows = process_packets(source)
        job.n_flows = len(flows)

        if not flows:
            job.status = "done"
            job.finished_at = time.time()
            return

        job.status = "detecting"
        detector = _load_detector(job.detector)
        flagged = detector.flag(flows)
        job.n_flagged = len(flagged)
        job.flagged = [_flagged_to_dto(f) for f in flagged]
        job.progress_total = len(flagged)

        if not flagged:
            job.status = "done"
            job.finished_at = time.time()
            return

        job.status = "investigating"
        for ff in flagged:
            try:
                report = investigate_flow(ff)
                job.reports.append(
                    ThreatReportDTO(
                        flow_key=report.flow_key,
                        severity=report.severity,
                        threat_type=report.threat_type,
                        summary=report.summary,
                        evidence=list(report.evidence),
                        cve_ids=list(report.cve_ids),
                        attack_techniques=list(report.attack_techniques),
                        remediation=report.remediation,
                    )
                )
                job.n_reports += 1
            except Exception as e:
                # One bad flow shouldn't kill the run — log into the report list
                job.reports.append(
                    ThreatReportDTO(
                        flow_key=ff.flow.flow_key,
                        severity="info",
                        threat_type="investigation_failed",
                        summary=f"Agent investigation failed: {e}",
                    )
                )
            job.progress_done += 1

        job.status = "done"
        job.finished_at = time.time()
    except Exception as e:
        job.status = "error"
        job.error = f"{e}\n{traceback.format_exc()}"
        job.finished_at = time.time()


def start_job_in_background(job: Job) -> None:
    thread = threading.Thread(target=run_pipeline, args=(job,), daemon=True)
    thread.start()


# Module-level singleton store
store = JobStore()
