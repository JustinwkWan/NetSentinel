"""The LangGraph graph: nodes, edges, routing, state."""

from __future__ import annotations

import json
import re

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

import config
from netsentinel.agent.prompts import INVESTIGATION_PROMPT, SYSTEM_PROMPT
from netsentinel.agent.report import ThreatReport
from netsentinel.agent.state import AgentState
from netsentinel.agent.tools import TOOLS
from netsentinel.detection.base import FlaggedFlow


def build_graph():
    """Build and compile the ReAct agent graph."""
    llm = ChatAnthropic(
        model=config.LLM_MODEL,
        temperature=config.LLM_TEMPERATURE,
    )
    llm_with_tools = llm.bind_tools(TOOLS)

    def agent_node(state: AgentState) -> dict:
        response = llm_with_tools.invoke(state["messages"])
        return {
            "messages": [response],
            "iteration": state["iteration"] + 1,
        }

    def should_continue(state: AgentState) -> str:
        if state["iteration"] >= state["max_iterations"]:
            return "force_report"

        last_message = state["messages"][-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"

        return END

    def force_report_node(state: AgentState) -> dict:
        llm_plain = ChatAnthropic(
            model=config.LLM_MODEL,
            temperature=config.LLM_TEMPERATURE,
        )
        force_msg = HumanMessage(
            content=(
                "You have reached the maximum number of investigation steps. "
                "Based on all the information gathered so far, produce your "
                "final threat report now. Respond with a JSON object containing: "
                "severity, threat_type, summary, evidence (list), cve_ids (list), "
                "attack_techniques (list), and remediation."
            )
        )
        response = llm_plain.invoke(state["messages"] + [force_msg])
        return {"messages": [response]}

    tool_node = ToolNode(TOOLS)

    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("force_report", force_report_node)

    graph.set_entry_point("agent")
    graph.add_conditional_edges(
        "agent",
        should_continue,
        {"tools": "tools", "force_report": "force_report", END: END},
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("force_report", END)

    return graph.compile()


def investigate_flow(flagged: FlaggedFlow) -> ThreatReport:
    """Run the agent investigation on a single flagged flow."""
    graph = build_graph()

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
    content = last_msg.content if hasattr(last_msg, "content") else str(last_msg)

    # Try to parse JSON from the response
    try:
        match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", content, re.DOTALL)
        if match:
            data = json.loads(match.group())
            return ThreatReport(
                flow_key=flow_key,
                severity=data.get("severity", "medium"),
                threat_type=data.get("threat_type", "unknown"),
                summary=data.get("summary", content[:200]),
                evidence=data.get("evidence", []),
                cve_ids=data.get("cve_ids", []),
                attack_techniques=data.get("attack_techniques", []),
                remediation=data.get("remediation", ""),
            )
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback: use the raw text as the summary
    return ThreatReport(
        flow_key=flow_key,
        severity="medium",
        threat_type="unknown",
        summary=content[:500] if isinstance(content, str) else str(content)[:500],
    )
