import { useState } from "react";
import { api } from "../api";

interface Props {
  pcapName: string | null;
  modelMessage: string | null;
  onRunStarted: (jobId: string) => void;
}

export function RunControls({ pcapName, modelMessage, onRunStarted }: Props) {
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const start = async () => {
    if (!pcapName) return;
    setStarting(true);
    setError(null);
    try {
      const summary = await api.createRun(pcapName);
      onRunStarted(summary.job_id);
    } catch (e) {
      setError(String(e));
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="space-y-2">
      <button
        className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 rounded px-4 py-2 text-sm font-medium"
        onClick={start}
        disabled={!pcapName || starting || !!modelMessage}
      >
        {starting ? "Starting…" : "Run pipeline"}
      </button>
      {modelMessage && <div className="text-amber-400 text-xs">{modelMessage}</div>}
      {error && <div className="text-rose-400 text-xs">{error}</div>}
    </div>
  );
}
