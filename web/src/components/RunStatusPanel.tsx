import { useEffect, useState } from "react";
import { api, type JobStatus, type RunDetail } from "../api";
import { ReportCard } from "./ReportCard";
import { FlaggedFlowRow } from "./FlaggedFlowRow";

interface Props {
  jobId: string | null;
}

const STATUS_LABEL: Record<JobStatus, string> = {
  pending: "Queued",
  ingesting: "Reading PCAP",
  detecting: "Detecting anomalies",
  investigating: "Investigating flows",
  done: "Done",
  error: "Error",
};

const STATUS_COLOR: Record<JobStatus, string> = {
  pending: "bg-slate-600",
  ingesting: "bg-amber-600",
  detecting: "bg-amber-600",
  investigating: "bg-cyan-600",
  done: "bg-emerald-600",
  error: "bg-rose-600",
};

export function RunStatusPanel({ jobId }: Props) {
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!jobId) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    let timer: number | null = null;

    const poll = async () => {
      try {
        const d = await api.getRun(jobId);
        if (cancelled) return;
        setDetail(d);
        if (d.status !== "done" && d.status !== "error") {
          timer = window.setTimeout(poll, 1500);
        }
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
    };

    setDetail(null);
    setError(null);
    poll();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [jobId]);

  if (!jobId) {
    return (
      <div className="text-slate-500 text-sm">
        Select a PCAP and click "Run pipeline" to start.
      </div>
    );
  }

  if (error) {
    return <div className="text-rose-400 text-sm">{error}</div>;
  }

  if (!detail) {
    return <div className="text-slate-400 text-sm">Loading…</div>;
  }

  const progressPct =
    detail.progress_total > 0
      ? Math.round((detail.progress_done / detail.progress_total) * 100)
      : 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span
            className={`inline-block px-2.5 py-0.5 text-xs font-semibold rounded ${STATUS_COLOR[detail.status]}`}
          >
            {STATUS_LABEL[detail.status]}
          </span>
          <span className="text-xs text-slate-500 font-mono">{detail.job_id}</span>
        </div>
        <div className="text-xs text-slate-400">
          {detail.pcap_name} • {detail.detector}
        </div>
      </div>

      {(detail.status === "investigating" || detail.status === "done") && detail.progress_total > 0 && (
        <div>
          <div className="flex justify-between text-xs text-slate-400 mb-1">
            <span>
              Investigating {detail.progress_done}/{detail.progress_total} flows
            </span>
            <span>{progressPct}%</span>
          </div>
          <div className="h-2 bg-slate-800 rounded overflow-hidden">
            <div
              className="h-full bg-cyan-500 transition-all duration-300"
              style={{ width: `${progressPct}%` }}
            />
          </div>
        </div>
      )}

      <div className="grid grid-cols-3 gap-3 text-center">
        <Stat label="Flows" value={detail.n_flows} />
        <Stat label="Flagged" value={detail.n_flagged} />
        <Stat label="Reports" value={detail.n_reports} />
      </div>

      {detail.error && (
        <pre className="text-xs text-rose-400 bg-rose-950/40 border border-rose-900 rounded p-3 overflow-auto max-h-48 whitespace-pre-wrap">
          {detail.error}
        </pre>
      )}

      {detail.flagged.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-slate-300 mb-2">
            Flagged flows
          </h3>
          <div className="space-y-1.5">
            {detail.flagged.map((f) => (
              <FlaggedFlowRow key={f.flow.flow_key} flagged={f} />
            ))}
          </div>
        </section>
      )}

      {detail.reports.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-slate-300 mb-2">
            Threat reports
          </h3>
          <div className="space-y-3">
            {detail.reports.map((r) => (
              <ReportCard key={r.flow_key} report={r} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded px-3 py-2">
      <div className="text-2xl font-semibold text-slate-100">{value}</div>
      <div className="text-xs text-slate-400 uppercase tracking-wide">{label}</div>
    </div>
  );
}
