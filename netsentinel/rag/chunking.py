"""Natural-boundary chunking for CVE and ATT&CK data.

Design principle: one CVE = one chunk, one ATT&CK technique = one chunk.
No fixed-size text splitting. Each chunk is a complete, self-contained
unit of threat intelligence.
"""

from __future__ import annotations


def chunk_cve(cve_entry: dict) -> dict | None:
    """Chunk a single CVE entry from NVD API response into a document.

    Returns a dict with 'id', 'document', and 'metadata' keys,
    or None if the entry lacks usable data.
    """
    cve_id = cve_entry.get("cve", {}).get("id", "")
    if not cve_id:
        return None

    descriptions = cve_entry.get("cve", {}).get("descriptions", [])
    en_desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            en_desc = d.get("value", "")
            break
    if not en_desc or en_desc.startswith("** REJECT"):
        return None

    # Extract severity from CVSS metrics
    severity = "unknown"
    cvss_score = None
    metrics = cve_entry.get("cve", {}).get("metrics", {})
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = metric_list[0].get("baseSeverity", "").lower()
            if not severity:
                severity = cvss_data.get("baseSeverity", "unknown").lower()
            break

    # Build a rich document combining description with metadata
    doc_parts = [en_desc]
    weaknesses = cve_entry.get("cve", {}).get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    if cwe_ids:
        doc_parts.append(f"Weaknesses: {', '.join(cwe_ids)}")

    return {
        "id": cve_id,
        "document": " ".join(doc_parts),
        "metadata": {
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": cvss_score or 0.0,
        },
    }


def chunk_attack_technique(technique: dict) -> dict | None:
    """Chunk a single ATT&CK technique from STIX data into a document.

    Returns a dict with 'id', 'document', and 'metadata' keys,
    or None if the entry lacks usable data.
    """
    # Extract technique ID from external references
    technique_id = ""
    name = technique.get("name", "")
    external_refs = technique.get("external_references", [])
    for ref in external_refs:
        if ref.get("source_name") == "mitre-attack":
            technique_id = ref.get("external_id", "")
            break
    if not technique_id or not name:
        return None

    description = technique.get("description", "")
    if not description:
        return None

    # Clean up STIX markdown-style formatting
    description = description.replace("(Citation:", "(Ref:")

    # Determine if this is a sub-technique
    is_sub = "." in technique_id

    # Extract platforms and tactics
    platforms = technique.get("x_mitre_platforms", [])
    kill_chain = technique.get("kill_chain_phases", [])
    tactics = [
        phase.get("phase_name", "").replace("-", " ")
        for phase in kill_chain
        if phase.get("kill_chain_name") == "mitre-attack"
    ]

    # Build rich document
    doc_parts = [f"{technique_id}: {name}.", description]
    if tactics:
        doc_parts.append(f"Tactics: {', '.join(tactics)}.")
    if platforms:
        doc_parts.append(f"Platforms: {', '.join(platforms)}.")

    return {
        "id": technique_id,
        "document": " ".join(doc_parts),
        "metadata": {
            "technique_id": technique_id,
            "name": name,
            "is_sub_technique": is_sub,
            "tactics": ", ".join(tactics),
        },
    }
