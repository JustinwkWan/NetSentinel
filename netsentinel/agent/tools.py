"""Tool definitions for the agent: cve_lookup and attack_technique_lookup."""

from __future__ import annotations

import json

from langchain_core.tools import tool

from netsentinel.rag.store import RAGStore

_store: RAGStore | None = None


def _get_store() -> RAGStore:
    global _store
    if _store is None:
        _store = RAGStore()
    return _store


def set_store(store: RAGStore) -> None:
    """Allow injecting a RAGStore instance (for testing)."""
    global _store
    _store = store


@tool
def cve_lookup(query: str) -> str:
    """Search for CVE entries related to a network security concern.

    Args:
        query: A description of the vulnerability or suspicious activity to search for.

    Returns:
        Relevant CVE entries with IDs, descriptions, and severity scores.
    """
    try:
        results = _get_store().query_cve(query)
        if not results:
            return "No relevant CVE entries found for this query."
        entries = []
        for r in results:
            meta = r.get("metadata", {})
            entry = {
                "cve_id": meta.get("cve_id", "unknown"),
                "description": r["content"][:500],
                "severity": meta.get("severity", "unknown"),
            }
            entries.append(entry)
        return json.dumps(entries, indent=2)
    except Exception as e:
        return f"No relevant CVE entries found for this query."


@tool
def attack_technique_lookup(query: str) -> str:
    """Search for MITRE ATT&CK techniques matching observed network behavior.

    Args:
        query: A description of the observed behavior or attack pattern.

    Returns:
        Relevant ATT&CK techniques with IDs, names, and descriptions.
    """
    try:
        results = _get_store().query_attack(query)
        if not results:
            return "No relevant ATT&CK techniques found for this query."
        entries = []
        for r in results:
            meta = r.get("metadata", {})
            entry = {
                "technique_id": meta.get("technique_id", "unknown"),
                "name": meta.get("name", "unknown"),
                "description": r["content"][:500],
            }
            entries.append(entry)
        return json.dumps(entries, indent=2)
    except Exception as e:
        return f"No relevant ATT&CK techniques found for this query."


TOOLS = [cve_lookup, attack_technique_lookup]
