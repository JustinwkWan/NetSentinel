import { useState } from "react";
import { api } from "../api";

interface Props {
  pcapName: string | null;
  onRunStarted: (jobId: string) => void;
}

export function RunControls({ pcapName, onRunStarted }: Props) {
  const [detector, setDetector] = useState<"stub" | "lstm">("stub");
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const start = async () => {
    if (!pcapName) return;
    setStarting(true);
    setError(null);
    try {
      const summary = await api.createRun(pcapName, detector);
      onRunStarted(summary.job_id);
    } catch (e) {
      setError(String(e));
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-slate-300">Detector</label>
      <div className="flex gap-2">
        <select
          className="bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
          value={detector}
          onChange={(e) => setDetector(e.target.value as "stub" | "lstm")}
        >
          <option value="stub">Stub (rules)</option>
          <option value="lstm">LSTM autoencoder</option>
        </select>
        <button
          className="flex-1 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 rounded px-4 py-2 text-sm font-medium"
          onClick={start}
          disabled={!pcapName || starting}
        >
          {starting ? "Starting…" : "Run pipeline"}
        </button>
      </div>
      {error && <div className="text-rose-400 text-xs">{error}</div>}
    </div>
  );
}
