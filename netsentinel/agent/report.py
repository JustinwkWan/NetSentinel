"""ThreatReport data object and formatting."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ThreatReport:
    """Structured output from the agent's investigation."""

    flow_key: str
    severity: str  # "critical", "high", "medium", "low", "info"
    threat_type: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    remediation: str = ""

    def format(self) -> str:
        lines = [
            f"{'='*60}",
            f"THREAT REPORT: {self.flow_key}",
            f"{'='*60}",
            f"Severity:    {self.severity.upper()}",
            f"Threat Type: {self.threat_type}",
            f"",
            f"Summary:",
            f"  {self.summary}",
        ]
        if self.cve_ids:
            lines.append(f"")
            lines.append(f"Related CVEs: {', '.join(self.cve_ids)}")
        if self.attack_techniques:
            lines.append(f"ATT&CK Techniques: {', '.join(self.attack_techniques)}")
        if self.evidence:
            lines.append(f"")
            lines.append(f"Evidence:")
            for e in self.evidence:
                lines.append(f"  - {e}")
        if self.remediation:
            lines.append(f"")
            lines.append(f"Remediation:")
            lines.append(f"  {self.remediation}")
        lines.append(f"{'='*60}")
        return "\n".join(lines)
