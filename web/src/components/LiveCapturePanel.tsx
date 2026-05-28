import { useEffect, useRef, useState } from "react";
import { api, type CaptureStatus } from "../api";

interface Props {
  onActivity: () => void;
}

const STATUS_BADGE: Record<string, string> = {
  stopped: "bg-slate-600",
  running: "bg-emerald-600",
  error: "bg-rose-600",
};

export function LiveCapturePanel({ onActivity }: Props) {
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [iface, setIface] = useState("en0");
  const [detector, setDetector] = useState<"stub" | "lstm">("lstm");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastRunsRef = useRef(0);

  const poll = async () => {
    try {
      const s = await api.captureStatus();
      setStatus(s);
      if (s.runs_triggered !== lastRunsRef.current) {
        lastRunsRef.current = s.runs_triggered;
        onActivity();
      }
    } catch {
      // backend may be momentarily unreachable
    }
  };

  useEffect(() => {
    poll();
    const id = window.setInterval(poll, 3000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const s = await api.captureStart({ iface, duration: 60, files: 10, detector });
      setStatus(s);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    setError(null);
    try {
      const s = await api.captureStop();
      setStatus(s);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const running = status?.status === "running";
  const dumpcapMissing = status && !status.dumpcap_available;

  return (
    <section className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">Live capture</h2>
        {status && (
          <span
            className={`inline-block px-2 py-0.5 text-xs font-semibold rounded ${
              STATUS_BADGE[status.status]
            }`}
          >
            {status.status}
          </span>
        )}
      </div>

      {dumpcapMissing && (
        <div className="text-amber-400 text-xs">
          dumpcap not found — install Wireshark to enable live capture.
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-xs text-slate-400">Interface</label>
        <input
          type="text"
          value={iface}
          onChange={(e) => setIface(e.target.value)}
          disabled={running || busy}
          className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-cyan-500 disabled:opacity-50"
          placeholder="en0"
        />
      </div>

      <div className="space-y-2">
        <label className="block text-xs text-slate-400">Detector</label>
        <select
          value={detector}
          onChange={(e) => setDetector(e.target.value as "stub" | "lstm")}
          disabled={running || busy}
          className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-cyan-500 disabled:opacity-50"
        >
          <option value="stub">Stub (rules)</option>
          <option value="lstm">LSTM autoencoder</option>
        </select>
      </div>

      <div className="text-xs text-slate-500">
        60s windows · 10-file rolling buffer (~10 min)
      </div>

      {running ? (
        <button
          onClick={stop}
          disabled={busy}
          className="w-full bg-rose-600 hover:bg-rose-500 disabled:bg-slate-700 rounded px-4 py-2 text-sm font-medium"
        >
          {busy ? "Stopping…" : "Stop capture"}
        </button>
      ) : (
        <button
          onClick={start}
          disabled={busy || !!dumpcapMissing}
          className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-500 rounded px-4 py-2 text-sm font-medium"
        >
          {busy ? "Starting…" : "Start capture"}
        </button>
      )}

      {running && status && (
        <div className="grid grid-cols-2 gap-2 text-center pt-1">
          <div className="bg-slate-800/60 border border-slate-700 rounded px-2 py-1.5">
            <div className="text-lg font-semibold text-slate-100">
              {status.runs_triggered}
            </div>
            <div className="text-[10px] text-slate-400 uppercase tracking-wide">
              Windows run
            </div>
          </div>
          <div className="bg-slate-800/60 border border-slate-700 rounded px-2 py-1.5">
            <div className="text-xs font-mono text-slate-300 truncate pt-1">
              {status.last_file ?? "—"}
            </div>
            <div className="text-[10px] text-slate-400 uppercase tracking-wide">
              Last window
            </div>
          </div>
        </div>
      )}

      {!running && status?.status === "stopped" && status.files_cleaned > 0 && (
        <div className="text-slate-500 text-xs">
          Cleaned up {status.files_cleaned} capture file
          {status.files_cleaned === 1 ? "" : "s"} on stop.
        </div>
      )}

      {(error || status?.error) && (
        <div className="text-rose-400 text-xs break-words">
          {error || status?.error}
        </div>
      )}
    </section>
  );
}
