import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, type RunDetail } from "../api";
import { RUN_POLL_MS } from "../polling";
import { RunStatusPanel } from "./RunStatusPanel";

const run = (overrides: Partial<RunDetail> = {}): RunDetail => ({
  job_id: "job1",
  pcap_name: "sample.pcap",
  detector: "stub",
  status: "investigating",
  started_at: 1_000_000,
  finished_at: null,
  n_flows: 3,
  n_flagged: 1,
  n_reports: 0,
  investigation_s: null,
  error: null,
  flagged: [],
  reports: [],
  progress_done: 0,
  progress_total: 1,
  ...overrides,
});

const tick = () =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(RUN_POLL_MS);
  });

describe("RunStatusPanel polling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("recovers from a transient failure and keeps polling to completion", async () => {
    vi.spyOn(api, "getRun")
      .mockResolvedValueOnce(run())
      .mockRejectedValueOnce(new ApiError(502, "Bad Gateway", "backend restarting"))
      .mockResolvedValueOnce(run({ status: "done", progress_done: 1 }));

    render(<RunStatusPanel jobId="job1" />);
    await act(async () => {});
    expect(screen.getByText("Investigating flows")).toBeTruthy();

    await tick();
    // The last good state stays visible alongside the retry notice.
    expect(screen.getByText("Investigating flows")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("backend restarting");

    await tick();
    expect(screen.getByText("Done")).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("stops polling when the run no longer exists", async () => {
    const getRun = vi
      .spyOn(api, "getRun")
      .mockRejectedValue(new ApiError(404, "Not Found", "Run not found: job1"));

    render(<RunStatusPanel jobId="job1" />);
    await act(async () => {});
    expect(screen.getByText(/Run not found/)).toBeTruthy();

    await tick();
    await tick();
    expect(getRun).toHaveBeenCalledTimes(1);
  });
});
