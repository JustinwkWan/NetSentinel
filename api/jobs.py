"""In-memory job store + background runner for pipeline runs."""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field

import config
from api.models import (
    FlaggedFlowDTO,
    FlowDTO,
    JobStatus,
    RunDetail,
    RunSummary,
    ThreatReportDTO,
    TimingDTO,
)
from netsentinel.agent.scheduler import InvestigationResult, investigate_all
from netsentinel.agent.timing import InvestigationTiming
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


def _timing_to_dto(timing: InvestigationTiming) -> TimingDTO:
    return TimingDTO(
        queued_s=timing.queued_s,
        total_s=timing.total_s,
        llm_calls=timing.llm_calls,
        llm_s=timing.llm_s,
        tool_calls=timing.tool_calls,
        tool_s=timing.tool_s,
        input_tokens=timing.input_tokens,
        output_tokens=timing.output_tokens,
    )


def _result_to_dto(result: InvestigationResult) -> ThreatReportDTO:
    timing = _timing_to_dto(result.timing)
    report = result.report
    if report is None:
        # Failed investigations still show up, so the run accounts for them
        return ThreatReportDTO(
            flow_key=result.flagged.flow.flow_key,
            severity="info",
            threat_type="investigation_failed",
            summary=f"Agent investigation failed: {result.error}",
            timing=timing,
        )
    return ThreatReportDTO(
        flow_key=report.flow_key,
        severity=report.severity,
        threat_type=report.threat_type,
        summary=report.summary,
        evidence=list(report.evidence),
        cve_ids=list(report.cve_ids),
        attack_techniques=list(report.attack_techniques),
        remediation=report.remediation,
        timing=timing,
    )


def _load_detector():
    from netsentinel.detection.lstm import LstmDetector
    return LstmDetector()


@dataclass
class Job:
    job_id: str
    pcap_path: str
    pcap_name: str
    status: JobStatus = "pending"
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    n_flows: int = 0
    n_flagged: int = 0
    n_reports: int = 0
    progress_done: int = 0
    progress_total: int = 0
    investigation_s: float | None = None  # wall time of the investigate stage
    flagged: list[FlaggedFlowDTO] = field(default_factory=list)
    reports: list[ThreatReportDTO] = field(default_factory=list)
    error: str | None = None
    # Set once the pcap has been read into memory (or the job failed), so a
    # capture session knows when the file is safe to delete.
    ingested: threading.Event = field(default_factory=threading.Event)

    @property
    def finished(self) -> bool:
        return self.status in ("done", "error")

    def to_summary(self) -> RunSummary:
        return RunSummary(
            job_id=self.job_id,
            pcap_name=self.pcap_name,
            status=self.status,
            started_at=self.started_at,
            finished_at=self.finished_at,
            n_flows=self.n_flows,
            n_flagged=self.n_flagged,
            n_reports=self.n_reports,
            investigation_s=self.investigation_s,
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

    def create(self, pcap_path: str, pcap_name: str) -> Job:
        job_id = uuid.uuid4().hex[:12]
        job = Job(
            job_id=job_id,
            pcap_path=pcap_path,
            pcap_name=pcap_name,
        )
        with self._lock:
            self._jobs[job_id] = job
            self._evict_finished_locked()
        return job

    def _evict_finished_locked(self) -> None:
        """Drop the oldest finished jobs beyond the retention cap.

        Live capture creates a job per rotation, so without a cap the store
        grows for as long as the server runs. Active jobs are never evicted.
        """
        finished = sorted(
            (j for j in self._jobs.values() if j.finished),
            key=lambda j: j.started_at,
        )
        excess = len(finished) - config.API_MAX_JOBS_RETAINED
        for job in finished[:max(0, excess)]:
            del self._jobs[job.job_id]

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
        try:
            flows = process_packets(PcapFileSource(job.pcap_path))
        finally:
            job.ingested.set()
        job.n_flows = len(flows)

        if not flows:
            job.status = "done"
            job.finished_at = time.time()
            return

        job.status = "detecting"
        detector = _load_detector()
        flagged = detector.flag(flows)
        job.n_flagged = len(flagged)
        job.flagged = [_flagged_to_dto(f) for f in flagged]
        job.progress_total = len(flagged)

        if not flagged:
            job.status = "done"
            job.finished_at = time.time()
            return

        job.status = "investigating"
        # Reports are kept in flagged-flow order even though investigations
        # may finish out of order; the callback can fire from worker threads.
        slots: list[ThreatReportDTO | None] = [None] * len(flagged)
        slots_lock = threading.Lock()

        def on_result(index: int, result: InvestigationResult) -> None:
            dto = _result_to_dto(result)
            with slots_lock:
                slots[index] = dto
                job.reports = [r for r in slots if r is not None]
                if result.report is not None:
                    job.n_reports += 1
                job.progress_done += 1

        start = time.perf_counter()
        investigate_all(flagged, on_result=on_result)
        job.investigation_s = time.perf_counter() - start

        job.status = "done"
        job.finished_at = time.time()
    except Exception as e:
        job.status = "error"
        job.error = f"{e}\n{traceback.format_exc()}"
        job.finished_at = time.time()
    finally:
        job.ingested.set()


def start_job_in_background(job: Job) -> None:
    thread = threading.Thread(target=run_pipeline, args=(job,), daemon=True)
    thread.start()


# Module-level singleton store
store = JobStore()
