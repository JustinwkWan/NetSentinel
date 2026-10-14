import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";
import { useModelStatus } from "./useModelStatus";

function Probe() {
  const message = useModelStatus();
  return <div>{message ?? "ready"}</div>;
}

describe("useModelStatus", () => {
  afterEach(() => cleanup());

  it("re-checks when the window regains focus", async () => {
    vi.spyOn(api, "health")
      .mockResolvedValueOnce({ status: "ok", model_ready: false, model_message: "No model" })
      .mockResolvedValueOnce({ status: "ok", model_ready: true, model_message: null });
    render(<Probe />);
    await act(async () => {});
    expect(screen.getByText("No model")).toBeTruthy();

    // The user trained in a terminal and came back to the dashboard
    await act(async () => {
      window.dispatchEvent(new Event("focus"));
    });

    expect(screen.getByText("ready")).toBeTruthy();
  });
});
