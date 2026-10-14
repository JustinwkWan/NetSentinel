"""Shared LLM client construction: one rate limit and retry policy for all.

Every chat model in the process (agent turns, forced reports, the eval
judge) goes through make_chat_model, so they all draw from the same
process-wide request budget no matter how many investigations run at once.

Rate limiting has two layers:
  - The token bucket below caps how often requests *start*
    (LLM_REQUESTS_PER_SECOND, with bursts of up to LLM_MAX_BURST).
  - The investigation worker pool (netsentinel.agent.scheduler) caps how
    many investigations, and so requests, are *in flight*.
When the provider still answers 429 (or 5xx), the Anthropic SDK retries with
exponential backoff and jitter, honoring Retry-After, up to LLM_MAX_RETRIES.

Each request attempt also has a hard wall-clock deadline (LLM_TIMEOUT_SECONDS).
httpx timeouts are per read, and DeepSeek keeps queued requests open by
sending empty lines for up to 10 minutes, so a per-read timeout never fires
and one queued call can hold a worker for 10 minutes. The deadline turns that
into a timeout, which the SDK retries with backoff like any other.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property

import anthropic
import httpx
from langchain_anthropic import ChatAnthropic
from langchain_core.rate_limiters import InMemoryRateLimiter

import config


@dataclass(frozen=True)
class RateLimiterStats:
    requests: int
    wait_s: float


class MeteredRateLimiter(InMemoryRateLimiter):
    """Token-bucket limiter that also records how long callers waited."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._stats_lock = threading.Lock()
        self._requests = 0
        self._wait_s = 0.0

    def acquire(self, *, blocking: bool = True) -> bool:
        start = time.perf_counter()
        acquired = super().acquire(blocking=blocking)
        waited = time.perf_counter() - start
        with self._stats_lock:
            self._requests += 1
            self._wait_s += waited
        return acquired

    def stats(self) -> RateLimiterStats:
        with self._stats_lock:
            return RateLimiterStats(requests=self._requests, wait_s=self._wait_s)


_deadline_hits = 0
_deadline_hits_lock = threading.Lock()


def deadline_hits() -> int:
    """How many request attempts were cut off by the deadline so far."""
    with _deadline_hits_lock:
        return _deadline_hits


def _record_deadline_hit() -> None:
    global _deadline_hits
    with _deadline_hits_lock:
        _deadline_hits += 1


class _DeadlineByteStream(httpx.SyncByteStream):
    """Response body that raises ReadTimeout once the deadline passes."""

    def __init__(self, stream: httpx.SyncByteStream, deadline: float,
                 request: httpx.Request):
        self._stream = stream
        self._deadline = deadline
        self._request = request

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._stream:
            if time.monotonic() > self._deadline:
                _record_deadline_hit()
                raise httpx.ReadTimeout(
                    "response not complete within the request deadline",
                    request=self._request,
                )
            yield chunk

    def close(self) -> None:
        self._stream.close()


class DeadlineTransport(httpx.HTTPTransport):
    """HTTP transport enforcing a total time limit per request.

    Waiting for headers is bounded by the client's connect/read timeouts;
    reading the body is bounded by the deadline, checked on every chunk.
    """

    def __init__(self, deadline_s: float, **kwargs):
        super().__init__(**kwargs)
        self.deadline_s = deadline_s

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        deadline = time.monotonic() + self.deadline_s
        response = super().handle_request(request)
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_DeadlineByteStream(response.stream, deadline, request),
            extensions=response.extensions,
        )


class DeadlineChatAnthropic(ChatAnthropic):
    """ChatAnthropic whose HTTP client enforces a per-request deadline.

    ChatAnthropic has no public hook for the HTTP client, so this overrides
    the client it builds, keeping its own connection parameters.
    """

    @cached_property
    def _client(self) -> anthropic.Client:
        params = self._client_params
        http_client = httpx.Client(
            base_url=params["base_url"],
            timeout=params.get("timeout"),
            transport=DeadlineTransport(deadline_s=config.LLM_TIMEOUT_SECONDS),
        )
        return anthropic.Client(**params, http_client=http_client)


_rate_limiter: MeteredRateLimiter | None = None
_rate_limiter_lock = threading.Lock()


def get_rate_limiter() -> MeteredRateLimiter:
    """The process-wide limiter shared by every chat model."""
    global _rate_limiter
    with _rate_limiter_lock:
        if _rate_limiter is None:
            _rate_limiter = MeteredRateLimiter(
                requests_per_second=config.LLM_REQUESTS_PER_SECOND,
                max_bucket_size=config.LLM_MAX_BURST,
            )
        return _rate_limiter


def make_chat_model(model: str | None = None, **kwargs) -> DeadlineChatAnthropic:
    """Create a chat model for the configured provider, rate limited."""
    params = {
        "model": model or config.LLM_MODEL,
        "temperature": config.LLM_TEMPERATURE,
        "rate_limiter": get_rate_limiter(),
        "max_retries": config.LLM_MAX_RETRIES,
        "default_request_timeout": config.LLM_TIMEOUT_SECONDS,
        **kwargs,
    }
    if config.LLM_BASE_URL:
        params["base_url"] = config.LLM_BASE_URL
    if config.LLM_API_KEY:
        params["api_key"] = config.LLM_API_KEY
    return DeadlineChatAnthropic(**params)
