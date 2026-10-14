import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, type CaptureStatus } from "../api";
import { LiveCapturePanel } from "./LiveCapturePanel";

const status = (overrides: Partial<CaptureStatus> = {}): CaptureStatus => ({
  status: "stopped",
  error: null,
  iface: null,
  duration: 60,
  files: 10,
  started_at: null,
  runs_triggered: 0,
  last_file: null,
  files_cleaned: 0,
  dumpcap_available: true,
  save_for_training: false,
  analysis_enabled: true,
  training_files_saved: 0,
  ...overrides,
});

describe("LiveCapturePanel training switch", () => {
  beforeEach(() => {
    vi.spyOn(api, "captureStatus").mockResolvedValue(status());
  });

  afterEach(() => cleanup());

  it("sends save_for_training when the switch is on", async () => {
    const start = vi.spyOn(api, "captureStart").mockResolvedValue(
      status({ status: "running", save_for_training: true }),
    );
    render(<LiveCapturePanel modelMessage={null} onActivity={() => {}} />);
    await act(async () => {});

    fireEvent.click(screen.getByRole("switch", { name: /save windows for training/i }));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /start capture/i }));
    });

    expect(start).toHaveBeenCalledWith({
      iface: "en0", duration: 60, files: 10, save_for_training: true,
    });
  });

  it("without a model, start needs the switch on", async () => {
    render(<LiveCapturePanel modelMessage="No model" onActivity={() => {}} />);
    await act(async () => {});
    const startButton = screen.getByRole("button", { name: /start capture/i });

    expect(startButton).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("switch", { name: /save windows for training/i }));
    expect(startButton).toHaveProperty("disabled", false);
  });

  it("shows the collecting-only state and saved count", async () => {
    vi.mocked(api.captureStatus).mockResolvedValue(
      status({
        status: "running", save_for_training: true,
        analysis_enabled: false, training_files_saved: 7,
      }),
    );
    render(<LiveCapturePanel modelMessage="No model" onActivity={() => {}} />);
    await act(async () => {});

    expect(screen.getByText(/collecting training data only/i)).toBeTruthy();
    expect(screen.getByText("7")).toBeTruthy();
  });
});
