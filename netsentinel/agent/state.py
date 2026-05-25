"""Agent state definition for the LangGraph ReAct loop."""

from __future__ import annotations

from typing import Annotated

from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class AgentState(TypedDict):
    """State carried through the LangGraph ReAct graph."""

    messages: Annotated[list, add_messages]
    flow_description: str
    iteration: int
    max_iterations: int
