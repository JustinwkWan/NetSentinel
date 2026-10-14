export type JobStatus =
  | "pending"
  | "ingesting"
  | "detecting"
  | "investigating"
  | "done"
  | "error";

export interface PcapInfo {
  name: string;
  size_bytes: number;
  modified: number;
}

export interface FlowDTO {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packet_count: number;
  byte_count: number;
  duration: number;
  packet_rate: number;
  mean_packet_size: number;
  flow_key: string;
}

export interface FlaggedFlowDTO {
  flow: FlowDTO;
  anomaly_score: number;
  reason: string;
}

export interface TimingDTO {
  queued_s: number;
  total_s: number;
  llm_calls: number;
  llm_s: number;
  tool_calls: number;
  tool_s: number;
  input_tokens: number;
  output_tokens: number;
}

export interface ThreatReportDTO {
  flow_key: string;
  severity: string;
  threat_type: string;
  summary: string;
  evidence: string[];
  cve_ids: string[];
  attack_techniques: string[];
  remediation: string;
  timing: TimingDTO | null;
}

export interface RunSummary {
  job_id: string;
  pcap_name: string;
  status: JobStatus;
  started_at: number;
  finished_at: number | null;
  n_flows: number;
  n_flagged: number;
  n_reports: number;
  investigation_s: number | null;
  error: string | null;
}

export interface RunDetail extends RunSummary {
  flagged: FlaggedFlowDTO[];
  reports: ThreatReportDTO[];
  progress_done: number;
  progress_total: number;
}

export type CaptureState = "stopped" | "running" | "error";

export interface CaptureStatus {
  status: CaptureState;
  error: string | null;
  iface: string | null;
  duration: number;
  files: number;
  started_at: number | null;
  runs_triggered: number;
  last_file: string | null;
  files_cleaned: number;
  dumpcap_available: boolean;
  save_for_training: boolean;
  analysis_enabled: boolean;
  training_files_saved: number;
}

export interface CaptureStartRequest {
  iface: string;
  duration: number;
  files: number;
  save_for_training: boolean;
}

export interface HealthStatus {
  status: "ok";
  model_ready: boolean;
  model_message: string | null;
}

export interface LocalPcap {
  name: string;
  path: string;
  size_bytes: number;
  modified: number;
}

export interface LocalDirListing {
  path: string;
  parent: string | null;
  dirs: string[];
  pcaps: LocalPcap[];
}

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, statusText: string, detail: string) {
    super(`${status} ${statusText}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
  }
}

// A response body can be read only once, so read it as text and then try
// JSON. FastAPI errors carry `detail` (a string, or a list for 422s); other
// failures (e.g. a proxy 502 while the backend is down) are plain text.
function errorDetail(body: string): string {
  try {
    const detail = (JSON.parse(body) as { detail?: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (detail !== undefined) return JSON.stringify(detail);
  } catch {
    // not JSON; fall through to the raw body
  }
  return body;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, init);
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, errorDetail(await res.text()));
  }
  return res.json() as Promise<T>;
}

export const api = {
  listPcaps: () => req<PcapInfo[]>("/pcaps"),
  uploadPcap: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return req<PcapInfo>("/pcaps/upload", { method: "POST", body: form });
  },
  health: () => req<HealthStatus>("/health"),
  createRun: (pcap_name: string) =>
    req<RunSummary>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pcap_name }),
    }),
  createRunFromPath: (pcap_path: string) =>
    req<RunSummary>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pcap_path }),
    }),
  browseLocal: (path?: string) =>
    req<LocalDirListing>(
      `/local/browse${path ? `?path=${encodeURIComponent(path)}` : ""}`,
    ),
  listRuns: () => req<RunSummary[]>("/runs"),
  getRun: (job_id: string) => req<RunDetail>(`/runs/${job_id}`),
  captureStatus: () => req<CaptureStatus>("/capture/status"),
  captureStart: (body: CaptureStartRequest) =>
    req<CaptureStatus>("/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  captureStop: () =>
    req<CaptureStatus>("/capture/stop", { method: "POST" }),
};
