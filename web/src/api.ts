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

export interface ThreatReportDTO {
  flow_key: string;
  severity: string;
  threat_type: string;
  summary: string;
  evidence: string[];
  cve_ids: string[];
  attack_techniques: string[];
  remediation: string;
}

export interface RunSummary {
  job_id: string;
  pcap_name: string;
  detector: string;
  status: JobStatus;
  started_at: number;
  finished_at: number | null;
  n_flows: number;
  n_flagged: number;
  n_reports: number;
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
  detector: string;
  started_at: number | null;
  runs_triggered: number;
  last_file: string | null;
  files_cleaned: number;
  dumpcap_available: boolean;
}

export interface CaptureStartRequest {
  iface: string;
  duration: number;
  files: number;
  detector: "stub" | "lstm";
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

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, init);
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json()).detail ?? "";
    } catch {
      detail = await res.text();
    }
    throw new Error(`${res.status} ${res.statusText}: ${detail}`);
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
  createRun: (pcap_name: string, detector: "stub" | "lstm") =>
    req<RunSummary>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pcap_name, detector }),
    }),
  createRunFromPath: (pcap_path: string, detector: "stub" | "lstm") =>
    req<RunSummary>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pcap_path, detector }),
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
