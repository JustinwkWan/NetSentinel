import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";

function stubFetch(body: string, status: number, statusText: string) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(body, { status, statusText })),
  );
}

async function captureError(): Promise<ApiError> {
  try {
    await api.listRuns();
  } catch (e) {
    return e as ApiError;
  }
  throw new Error("expected the request to fail");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api error handling", () => {
  it("surfaces a plain-text error body", async () => {
    stubFetch("upstream connect error", 502, "Bad Gateway");
    const err = await captureError();
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(502);
    expect(err.message).toBe("502 Bad Gateway: upstream connect error");
  });

  it("uses FastAPI's string detail", async () => {
    stubFetch(JSON.stringify({ detail: "Run not found: abc" }), 404, "Not Found");
    const err = await captureError();
    expect(err.status).toBe(404);
    expect(err.message).toBe("404 Not Found: Run not found: abc");
  });

  it("serializes structured validation details", async () => {
    const detail = [{ loc: ["body", "pcap_name"], msg: "bad value" }];
    stubFetch(JSON.stringify({ detail }), 422, "Unprocessable Entity");
    const err = await captureError();
    expect(err.message).toContain(JSON.stringify(detail));
  });
});
