import { useEffect, useRef, useState } from "react";
import { api, type CaptureStatus } from "../api";
import { CAPTURE_POLL_MS } from "../polling";

interface Props {
  modelMessage: string | null;
  onActivity: () => void;
}

const STATUS_BADGE: Record<string, string> = {
  stopped: "bg-slate-600",
  running: "bg-emerald-600",
  error: "bg-rose-600",
};

export function LiveCapturePanel({ modelMessage, onActivity }: Props) {
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [iface, setIface] = useState("en0");
  const [saveForTraining, setSaveForTraining] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastRunsRef = useRef(0);
  const onActivityRef = useRef(onActivity);

  useEffect(() => {
    onActivityRef.current = onActivity;
  });

  useEffect(() => {
    let cancelled = false;
    let timer: number | null = null;

    // Chained timeouts rather than setInterval, so a slow response never
    // overlaps the next request.
    const poll = async () => {
      try {
        const s = await api.captureStatus();
        if (cancelled) return;
        setStatus(s);
        if (s.runs_triggered !== lastRunsRef.current) {
          lastRunsRef.current = s.runs_triggered;
          onActivityRef.current();
        }
      } catch {
        // backend may be momentarily unreachable
      }
      if (!cancelled) timer = window.setTimeout(poll, CAPTURE_POLL_MS);
    };

    poll();
    return () => {
      cancelled = true;
      if (timer !== null) window.clearTimeout(timer);
    };
  }, []);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const s = await api.captureStart({
        iface,
        duration: 60,
        files: 10,
        save_for_training: saveForTraining,
      });
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
  // While running, show what the session was started with
  const saving = running && status ? status.save_for_training : saveForTraining;

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
          dumpcap not found - install Wireshark to enable live capture.
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

      <div className="flex items-start gap-3">
        <button
          id="save-for-training"
          type="button"
          role="switch"
          aria-checked={saving}
          aria-describedby="save-for-training-hint"
          onClick={() => setSaveForTraining((v) => !v)}
          disabled={running || busy}
          className={`relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-50 ${
            saving ? "bg-cyan-600" : "bg-slate-700"
          }`}
        >
          <span
            className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
              saving ? "translate-x-4" : "translate-x-0.5"
            }`}
          />
        </button>
        <div>
          <label
            htmlFor="save-for-training"
            className="block text-sm text-slate-200 cursor-pointer select-none"
          >
            Save windows for training
          </label>
          <div id="save-for-training-hint" className="text-xs text-slate-500">
            Keeps each finished window in data/training/
          </div>
        </div>
      </div>

      {status?.save_for_training && (running || status.training_files_saved > 0) && (
        <div className="text-xs text-cyan-300">
          {status.training_files_saved} window
          {status.training_files_saved === 1 ? "" : "s"} saved to data/training/
        </div>
      )}

      {modelMessage && !running && !saveForTraining && (
        <div className="text-amber-400 text-xs">
          No trained model yet. Turn on saving to collect training data.
        </div>
      )}

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
          disabled={busy || !!dumpcapMissing || (!!modelMessage && !saveForTraining)}
          className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-500 rounded px-4 py-2 text-sm font-medium"
        >
          {busy ? "Starting…" : "Start capture"}
        </button>
      )}

      {running && status && (
        <div className="space-y-2 pt-1">
          {!status.analysis_enabled && (
            <div className="text-amber-400 text-xs">
              No trained model - collecting training data only
            </div>
          )}
          <div
            className={`grid gap-2 text-center ${
              status.analysis_enabled ? "grid-cols-2" : "grid-cols-1"
            }`}
          >
            {status.analysis_enabled && (
              <StatTile value={String(status.runs_triggered)} label="Windows run" />
            )}
            <StatTile value={status.last_file ?? "-"} label="Last window" mono />
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

function StatTile({
  value,
  label,
  mono = false,
}: {
  value: string;
  label: string;
  mono?: boolean;
}) {
  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded px-2 py-1.5 min-w-0">
      <div
        className={
          mono
            ? "text-xs font-mono text-slate-300 truncate pt-1"
            : "text-lg font-semibold text-slate-100"
        }
        title={value}
      >
        {value}
      </div>
      <div className="text-[10px] text-slate-400 uppercase tracking-wide">{label}</div>
    </div>
  );
}
