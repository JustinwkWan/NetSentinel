import { useEffect, useState } from "react";
import { api, type RunSummary } from "../api";

interface Props {
  currentJobId: string | null;
  onSelect: (jobId: string) => void;
  refreshKey: number;
}

function fmtTime(t: number): string {
  return new Date(t * 1000).toLocaleTimeString();
}

const STATUS_DOT: Record<string, string> = {
  pending: "bg-slate-500",
  ingesting: "bg-amber-500",
  detecting: "bg-amber-500",
  investigating: "bg-cyan-500",
  done: "bg-emerald-500",
  error: "bg-rose-500",
};

export function RunHistory({ currentJobId, onSelect, refreshKey }: Props) {
  const [runs, setRuns] = useState<RunSummary[]>([]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | null = null;

    const tick = async () => {
      try {
        const list = await api.listRuns();
        if (!cancelled) setRuns(list);
      } catch {
        // ignore — backend may not be up yet
      }
      timer = window.setTimeout(tick, 3000);
    };
    tick();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [refreshKey]);

  if (runs.length === 0) {
    return <div className="text-slate-500 text-xs">No runs yet.</div>;
  }

  return (
    <ul className="space-y-1">
      {runs.map((r) => (
        <li key={r.job_id}>
          <button
            type="button"
            onClick={() => onSelect(r.job_id)}
            className={`w-full text-left px-3 py-2 rounded border text-xs flex items-center gap-2 ${
              r.job_id === currentJobId
                ? "bg-slate-800 border-cyan-700"
                : "bg-slate-900 border-slate-800 hover:bg-slate-800/60"
            }`}
          >
            <span
              className={`inline-block w-2 h-2 rounded-full ${STATUS_DOT[r.status] ?? "bg-slate-500"}`}
            />
            <span className="flex-1 truncate text-slate-200">{r.pcap_name}</span>
            <span className="text-slate-500">{fmtTime(r.started_at)}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}
