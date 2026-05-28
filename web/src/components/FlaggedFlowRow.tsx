import type { FlaggedFlowDTO } from "../api";

export function FlaggedFlowRow({ flagged }: { flagged: FlaggedFlowDTO }) {
  const f = flagged.flow;
  return (
    <div className="flex items-center gap-3 bg-slate-800/40 border border-slate-700 rounded px-3 py-2 text-sm">
      <span className="font-mono text-cyan-300 text-xs">{f.flow_key}</span>
      <span className="text-slate-500 text-xs">
        {f.packet_count} pkts · {Math.round(f.byte_count / 1024)} KB
      </span>
      <span className="ml-auto text-amber-400 text-xs italic">{flagged.reason}</span>
      <span className="bg-amber-900/50 text-amber-200 text-xs font-mono px-2 py-0.5 rounded">
        {flagged.anomaly_score.toFixed(2)}
      </span>
    </div>
  );
}
