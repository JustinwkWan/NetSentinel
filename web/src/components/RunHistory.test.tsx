import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, type RunSummary } from "../api";
import { HISTORY_POLL_MS } from "../polling";
import { RunHistory } from "./RunHistory";

describe("RunHistory polling", () => {
  let resolvers: Array<(runs: RunSummary[]) => void>;

  beforeEach(() => {
    vi.useFakeTimers();
    resolvers = [];
    vi.spyOn(api, "listRuns").mockImplementation(
      () => new Promise((resolve) => resolvers.push(resolve)),
    );
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  const resolvePending = async () => {
    await act(async () => {
      resolvers.splice(0).forEach((resolve) => resolve([]));
    });
  };

  it("stops polling once unmounted, even after mid-request refreshes", async () => {
    const props = { currentJobId: null, onSelect: () => {} };
    const { rerender, unmount } = render(
      <RunHistory {...props} refreshKey={0} />,
    );
    // Refresh while the first request is still in flight, as live capture
    // does on every new window.
    rerender(<RunHistory {...props} refreshKey={1} />);
    rerender(<RunHistory {...props} refreshKey={2} />);
    await resolvePending();

    unmount();
    const callsAtUnmount = vi.mocked(api.listRuns).mock.calls.length;

    for (let i = 0; i < 5; i++) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(HISTORY_POLL_MS);
      });
      await resolvePending();
    }
    expect(vi.mocked(api.listRuns).mock.calls.length).toBe(callsAtUnmount);
  });

  it("runs exactly one polling loop after refreshes", async () => {
    const props = { currentJobId: null, onSelect: () => {} };
    const { rerender } = render(<RunHistory {...props} refreshKey={0} />);
    rerender(<RunHistory {...props} refreshKey={1} />);
    await resolvePending();
    const before = vi.mocked(api.listRuns).mock.calls.length;

    await act(async () => {
      await vi.advanceTimersByTimeAsync(HISTORY_POLL_MS);
    });
    expect(vi.mocked(api.listRuns).mock.calls.length).toBe(before + 1);
  });
});
