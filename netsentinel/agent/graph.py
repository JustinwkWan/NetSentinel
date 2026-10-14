"""The LangGraph graph: nodes, edges, routing, state."""

from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

import config
from netsentinel.agent.parsing import (
    as_text,
    as_text_list,
    content_to_text,
    extract_json_object,
)
from netsentinel.agent.prompts import (
    FORCE_REPORT_PROMPT,
    INVESTIGATION_PROMPT,
    SYSTEM_PROMPT,
)
from netsentinel.agent.report import DEFAULT_SEVERITY, SEVERITIES, ThreatReport
from netsentinel.agent.state import AgentState
from netsentinel.agent.tools import TOOLS
from netsentinel.detection.base import FlaggedFlow


def _make_llm(**kwargs):
    """Create a ChatAnthropic instance with the configured provider."""
    params = {
        "model": config.LLM_MODEL,
        "temperature": config.LLM_TEMPERATURE,
        **kwargs,
    }
    if config.LLM_BASE_URL:
        params["base_url"] = config.LLM_BASE_URL
    if config.LLM_API_KEY:
        params["api_key"] = config.LLM_API_KEY
    return ChatAnthropic(**params)


def build_graph():
    """Build and compile the ReAct agent graph.

    agent -> tools -> agent ... until the agent answers without a tool call.
    The iteration cap is checked only after tool results are in, so the
    transcript never ends on an unanswered tool call (the API rejects that).
    """
    llm = _make_llm()
    llm_with_tools = llm.bind_tools(TOOLS)
    # The transcript holds tool_use/tool_result blocks, so tools must stay
    # defined; tool_choice "none" makes the model write the report instead.
    llm_report_only = llm.bind_tools(TOOLS, tool_choice={"type": "none"})

    def agent_node(state: AgentState) -> dict:
        response = llm_with_tools.invoke(state["messages"])
        return {
            "messages": [response],
            "iteration": state["iteration"] + 1,
        }

    def route_after_agent(state: AgentState) -> str:
        last_message = state["messages"][-1]
        if getattr(last_message, "tool_calls", None):
            return "tools"
        return END

    def route_after_tools(state: AgentState) -> str:
        if state["iteration"] >= state["max_iterations"]:
            return "force_report"
        return "agent"

    def force_report_node(state: AgentState) -> dict:
        force_msg = HumanMessage(content=FORCE_REPORT_PROMPT)
        response = llm_report_only.invoke(state["messages"] + [force_msg])
        return {"messages": [response]}

    tool_node = ToolNode(TOOLS)

    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("force_report", force_report_node)

    graph.set_entry_point("agent")
    graph.add_conditional_edges(
        "agent", route_after_agent, {"tools": "tools", END: END}
    )
    graph.add_conditional_edges(
        "tools",
        route_after_tools,
        {"agent": "agent", "force_report": "force_report"},
    )
    graph.add_edge("force_report", END)

    return graph.compile()


_compiled_graph = None


def _get_graph():
    """Return a compiled graph, building it once and reusing."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


def investigate_flow(flagged: FlaggedFlow) -> ThreatReport:
    """Run the agent investigation on a single flagged flow."""
    graph = _get_graph()

    flow = flagged.flow
    flow_desc = (
        f"Source: {flow.src_ip}:{flow.src_port}\n"
        f"Destination: {flow.dst_ip}:{flow.dst_port}\n"
        f"Protocol: {flow.protocol}\n"
        f"Packets: {flow.packet_count}, Bytes: {flow.byte_count}\n"
        f"Duration: {flow.duration:.2f}s\n"
        f"Packet rate: {flow.packet_rate:.1f} pps\n"
        f"Mean packet size: {flow.mean_packet_size:.1f} bytes"
    )

    investigation_msg = INVESTIGATION_PROMPT.format(
        flow_description=flow_desc,
        anomaly_score=flagged.anomaly_score,
        reason=flagged.reason,
    )

    initial_state: AgentState = {
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=investigation_msg),
        ],
        "flow_description": flow_desc,
        "iteration": 0,
        "max_iterations": config.AGENT_MAX_ITERATIONS,
    }

    final_state = graph.invoke(initial_state)

    return _parse_report(final_state, flow.flow_key)


def _parse_report(state: dict, flow_key: str) -> ThreatReport:
    """Extract a ThreatReport from the agent's final message."""
    last_msg = state["messages"][-1]
    content = content_to_text(getattr(last_msg, "content", last_msg))

    data = extract_json_object(content)
    if data:
        severity = as_text(data.get("severity")).strip().lower()
        return ThreatReport(
            flow_key=flow_key,
            severity=severity if severity in SEVERITIES else DEFAULT_SEVERITY,
            threat_type=as_text(data.get("threat_type"), "unknown"),
            summary=as_text(data.get("summary"), content[:200]),
            evidence=as_text_list(data.get("evidence")),
            cve_ids=as_text_list(data.get("cve_ids")),
            attack_techniques=as_text_list(data.get("attack_techniques")),
            remediation=as_text(data.get("remediation")),
        )

    # Fallback: use the raw text as the summary
    return ThreatReport(
        flow_key=flow_key,
        severity=DEFAULT_SEVERITY,
        threat_type="unknown",
        summary=content[:500],
    )
