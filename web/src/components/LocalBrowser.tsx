import { useEffect, useState } from "react";
import { api, type LocalDirListing } from "../api";

interface Props {
  onRunStarted: (jobId: string) => void;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function LocalBrowser({ onRunStarted }: Props) {
  const [open, setOpen] = useState(false);
  const [listing, setListing] = useState<LocalDirListing | null>(null);
  const [pathInput, setPathInput] = useState("");
  const [detector, setDetector] = useState<"stub" | "lstm">("stub");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runningPath, setRunningPath] = useState<string | null>(null);

  const browse = async (path?: string) => {
    setLoading(true);
    setError(null);
    try {
      const l = await api.browseLocal(path);
      setListing(l);
      setPathInput(l.path);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (open && !listing) browse();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const run = async (path: string) => {
    setRunningPath(path);
    setError(null);
    try {
      const summary = await api.createRunFromPath(path, detector);
      onRunStarted(summary.job_id);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunningPath(null);
    }
  };

  return (
    <section className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 space-y-3">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between text-sm font-semibold text-slate-200"
      >
        <span>Browse local folder</span>
        <span className="text-slate-500">{open ? "▴" : "▾"}</span>
      </button>

      {open && (
        <div className="space-y-3">
          <div className="flex gap-2">
            <input
              type="text"
              value={pathInput}
              onChange={(e) => setPathInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && browse(pathInput)}
              placeholder="/Users/you/captures"
              className="flex-1 bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-xs font-mono focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={() => browse(pathInput)}
              disabled={loading}
              className="bg-slate-700 hover:bg-slate-600 border border-slate-600 rounded px-3 py-1.5 text-xs"
            >
              Go
            </button>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400">Detector</label>
            <select
              value={detector}
              onChange={(e) => setDetector(e.target.value as "stub" | "lstm")}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="stub">Stub</option>
              <option value="lstm">LSTM</option>
            </select>
          </div>

          {loading && <div className="text-slate-400 text-xs">Loading…</div>}
          {error && <div className="text-rose-400 text-xs break-words">{error}</div>}

          {listing && !loading && (
            <div className="border border-slate-800 rounded max-h-72 overflow-auto divide-y divide-slate-800">
              {listing.parent && (
                <button
                  onClick={() => browse(listing.parent!)}
                  className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 font-mono"
                >
                  📁 ..
                </button>
              )}
              {listing.dirs.map((d) => (
                <button
                  key={d}
                  onClick={() => browse(`${listing.path}/${d}`)}
                  className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 font-mono truncate"
                >
                  📁 {d}
                </button>
              ))}
              {listing.pcaps.map((p) => (
                <div
                  key={p.path}
                  className="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-800/60"
                >
                  <span className="flex-1 text-xs text-cyan-300 font-mono truncate">
                    {p.name}
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {fmtBytes(p.size_bytes)}
                  </span>
                  <button
                    onClick={() => run(p.path)}
                    disabled={runningPath === p.path}
                    className="bg-cyan-700 hover:bg-cyan-600 disabled:bg-slate-700 rounded px-2 py-0.5 text-[11px] font-medium"
                  >
                    {runningPath === p.path ? "…" : "Run"}
                  </button>
                </div>
              ))}
              {listing.dirs.length === 0 && listing.pcaps.length === 0 && (
                <div className="px-3 py-2 text-xs text-slate-500">
                  No subfolders or pcaps here.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
