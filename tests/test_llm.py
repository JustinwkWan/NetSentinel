"""Tests for the shared LLM client's per-request deadline."""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import anthropic
import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from netsentinel import llm

DEADLINE_S = 0.5

MESSAGE = {
    "id": "msg_1", "type": "message", "role": "assistant", "model": "m",
    "content": [{"type": "text", "text": "OK"}],
    "stop_reason": "end_turn", "stop_sequence": None,
    "usage": {"input_tokens": 1, "output_tokens": 1},
}


class FakeProvider(BaseHTTPRequestHandler):
    """Mimics DeepSeek under load: headers at once, then a body of empty
    keep-alive lines while the request waits in the provider's queue."""

    queued_s = 0.0  # set per test
    requests = 0

    def do_POST(self):
        type(self).requests += 1
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps(MESSAGE).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            end = time.monotonic() + self.queued_s
            while time.monotonic() < end:
                self.wfile.write(b"\n")
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client gave up, as intended

    def log_message(self, *args):
        pass


@pytest.fixture
def provider():
    FakeProvider.requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeProvider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _client(base_url: str, max_retries: int) -> anthropic.Anthropic:
    transport = llm.DeadlineTransport(deadline_s=DEADLINE_S)
    return anthropic.Anthropic(
        base_url=base_url, api_key="test", max_retries=max_retries,
        # A per-read timeout alone never fires: each keep-alive line resets it.
        http_client=httpx.Client(base_url=base_url, timeout=DEADLINE_S,
                                 transport=transport),
    )


def _ask(client: anthropic.Anthropic):
    return client.messages.create(
        model="m", max_tokens=5, messages=[{"role": "user", "content": "hi"}],
    )


class TestDeadline:
    def test_fast_response_passes_through(self, provider):
        FakeProvider.queued_s = 0.1
        assert _ask(_client(provider, max_retries=0)).content[0].text == "OK"

    def test_keep_alive_stall_is_cut_off_and_retried(self, provider):
        FakeProvider.queued_s = 30.0
        hits_before = llm.deadline_hits()

        start = time.monotonic()
        with pytest.raises(anthropic.APITimeoutError):
            _ask(_client(provider, max_retries=1))
        elapsed = time.monotonic() - start

        assert FakeProvider.requests == 2  # first attempt plus one retry
        assert llm.deadline_hits() - hits_before == 2
        # Two deadlines plus one SDK backoff, nowhere near the 30s stall.
        assert elapsed < 2 * DEADLINE_S + 3

    def test_chat_model_uses_deadline_transport(self, monkeypatch):
        monkeypatch.setattr(config, "LLM_TIMEOUT_SECONDS", 12.0)
        transport = llm.make_chat_model()._client._client._transport
        assert isinstance(transport, llm.DeadlineTransport)
        assert transport.deadline_s == 12.0
