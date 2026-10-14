"""Timing instrumentation for agent investigations.

A TimingCallback is attached to one investigation's graph run. LangChain
reports every chat-model and tool run inside the graph to it, so it can time
each LLM round-trip and tool call without touching the graph's nodes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler


@dataclass
class InvestigationTiming:
    """Where the time went for one flow's investigation (seconds)."""

    queued_s: float = 0.0  # waiting for a free worker
    total_s: float = 0.0  # wall time of the investigation itself
    llm_call_s: list[float] = field(default_factory=list)
    tool_call_s: list[float] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def llm_calls(self) -> int:
        return len(self.llm_call_s)

    @property
    def llm_s(self) -> float:
        return sum(self.llm_call_s)

    @property
    def tool_calls(self) -> int:
        return len(self.tool_call_s)

    @property
    def tool_s(self) -> float:
        return sum(self.tool_call_s)


class TimingCallback(BaseCallbackHandler):
    """Records LLM and tool latencies into an InvestigationTiming.

    LLM latency spans the whole model call, so it includes any wait for the
    shared rate limiter. Tools may run on parallel threads, hence the lock.
    """

    def __init__(self, timing: InvestigationTiming):
        self.timing = timing
        self._starts: dict[UUID, float] = {}
        self._lock = threading.Lock()

    def _start(self, run_id: UUID) -> None:
        with self._lock:
            self._starts[run_id] = time.perf_counter()

    def _elapsed(self, run_id: UUID) -> float | None:
        with self._lock:
            start = self._starts.pop(run_id, None)
        return None if start is None else time.perf_counter() - start

    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
        self._start(run_id)

    def on_llm_end(self, response, *, run_id, **kwargs):
        elapsed = self._elapsed(run_id)
        if elapsed is None:
            return
        input_tokens = output_tokens = 0
        for generations in response.generations:
            for gen in generations:
                usage = getattr(getattr(gen, "message", None), "usage_metadata", None)
                if usage:
                    input_tokens += usage.get("input_tokens", 0)
                    output_tokens += usage.get("output_tokens", 0)
        with self._lock:
            self.timing.llm_call_s.append(elapsed)
            self.timing.input_tokens += input_tokens
            self.timing.output_tokens += output_tokens

    def on_llm_error(self, error, *, run_id, **kwargs):
        elapsed = self._elapsed(run_id)
        if elapsed is not None:
            with self._lock:
                self.timing.llm_call_s.append(elapsed)

    def on_tool_start(self, serialized, input_str, *, run_id, **kwargs):
        self._start(run_id)

    def on_tool_end(self, output, *, run_id, **kwargs):
        self._record_tool(run_id)

    def on_tool_error(self, error, *, run_id, **kwargs):
        self._record_tool(run_id)

    def _record_tool(self, run_id: UUID) -> None:
        elapsed = self._elapsed(run_id)
        if elapsed is not None:
            with self._lock:
                self.timing.tool_call_s.append(elapsed)
