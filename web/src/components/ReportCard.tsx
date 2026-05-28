import { useState } from "react";
import type { ThreatReportDTO } from "../api";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "bg-rose-700 text-rose-50",
  high: "bg-orange-600 text-orange-50",
  medium: "bg-amber-600 text-amber-50",
  low: "bg-yellow-700 text-yellow-50",
  info: "bg-slate-600 text-slate-100",
};

export function ReportCard({ report }: { report: ThreatReportDTO }) {
  const [open, setOpen] = useState(false);
  const sev = report.severity.toLowerCase();
  const color = SEVERITY_COLOR[sev] ?? SEVERITY_COLOR.info;

  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-slate-800/80"
      >
        <span
          className={`inline-block px-2 py-0.5 text-xs font-semibold rounded uppercase ${color}`}
        >
          {sev}
        </span>
        <span className="flex-1 text-slate-100 text-sm font-medium">
          {report.threat_type}
        </span>
        <span className="font-mono text-cyan-300 text-xs">{report.flow_key}</span>
        <span className="text-slate-500 text-xs">{open ? "▴" : "▾"}</span>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 space-y-3 text-sm">
          <div>
            <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
              Summary
            </div>
            <p className="text-slate-200 whitespace-pre-wrap">{report.summary}</p>
          </div>

          {report.evidence.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
                Evidence
              </div>
              <ul className="list-disc pl-5 text-slate-200 space-y-0.5">
                {report.evidence.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </div>
          )}

          {report.cve_ids.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
                CVEs
              </div>
              <div className="flex flex-wrap gap-1.5">
                {report.cve_ids.map((c) => (
                  <span
                    key={c}
                    className="font-mono text-xs bg-rose-900/40 border border-rose-900 text-rose-200 px-2 py-0.5 rounded"
                  >
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}

          {report.attack_techniques.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
                MITRE ATT&CK
              </div>
              <div className="flex flex-wrap gap-1.5">
                {report.attack_techniques.map((t, i) => (
                  <span
                    key={i}
                    className="font-mono text-xs bg-indigo-900/40 border border-indigo-800 text-indigo-200 px-2 py-0.5 rounded"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {report.remediation && (
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
                Remediation
              </div>
              <p className="text-slate-200 whitespace-pre-wrap">
                {report.remediation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
