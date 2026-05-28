"""Labeled evaluation dataset: flagged flows with expected classifications.

Each eval case is a FlaggedFlow paired with ground-truth labels that the
LLM-as-judge scores the agent's report against.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord


@dataclass
class EvalCase:
    """A single evaluation case: a flagged flow with expected labels."""

    id: str
    flagged_flow: FlaggedFlow
    expected_severity: str  # "critical", "high", "medium", "low", "info"
    expected_threat_type: str
    expected_keywords: list[str] = field(default_factory=list)
    description: str = ""


def _flow(src_ip, dst_ip, src_port, dst_port, protocol,
          packet_count, byte_count, duration, start_time=1000000.0):
    return FlowRecord(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
        protocol=protocol, packet_count=packet_count, byte_count=byte_count,
        duration=duration, start_time=start_time,
    )


def build_eval_dataset() -> list[EvalCase]:
    """Build the curated evaluation dataset.

    Each case represents a distinct attack pattern or benign anomaly
    that the agent should be able to classify.
    """
    cases = [
        # --- Case 1: Reverse shell on port 4444 ---
        EvalCase(
            id="reverse_shell_4444",
            flagged_flow=FlaggedFlow(
                flow=_flow("192.168.1.10", "10.0.0.99", 60000, 4444, "TCP",
                           25, 12000, 30.0),
                anomaly_score=0.85,
                reason="suspicious destination port 4444",
            ),
            expected_severity="critical",
            expected_threat_type="reverse shell",
            expected_keywords=["reverse shell", "command and control", "C2",
                               "backdoor", "remote access"],
            description="Classic reverse shell on metasploit default port 4444",
        ),

        # --- Case 2: Port scan (high packet rate, many destinations) ---
        EvalCase(
            id="port_scan_31337",
            flagged_flow=FlaggedFlow(
                flow=_flow("172.16.0.5", "192.168.1.10", 12345, 31337, "TCP",
                           5100, 204000, 5.0),
                anomaly_score=0.95,
                reason="suspicious destination port 31337; high packet rate (1020 pps)",
            ),
            expected_severity="high",
            expected_threat_type="port scan",
            expected_keywords=["scan", "reconnaissance", "enumeration", "probe"],
            description="High-rate scan targeting well-known hacker port 31337",
        ),

        # --- Case 3: SSH brute force ---
        EvalCase(
            id="ssh_brute_force",
            flagged_flow=FlaggedFlow(
                flow=_flow("10.0.0.50", "192.168.1.1", 45678, 22, "TCP",
                           8000, 320000, 60.0),
                anomaly_score=0.75,
                reason="high packet rate (133 pps)",
            ),
            expected_severity="high",
            expected_threat_type="brute force",
            expected_keywords=["SSH", "brute force", "credential", "authentication",
                               "password"],
            description="SSH brute force attempt: high packet count to port 22",
        ),

        # --- Case 4: DNS tunneling ---
        EvalCase(
            id="dns_tunnel",
            flagged_flow=FlaggedFlow(
                flow=_flow("192.168.1.20", "8.8.8.8", 50000, 53, "UDP",
                           15000, 9000000, 300.0),
                anomaly_score=0.70,
                reason="high byte rate (30000 B/s)",
            ),
            expected_severity="high",
            expected_threat_type="DNS tunneling",
            expected_keywords=["DNS", "tunnel", "exfiltration", "covert channel",
                               "data transfer"],
            description="Unusually large DNS traffic volume suggesting data tunneling",
        ),

        # --- Case 5: SQL injection / web attack ---
        EvalCase(
            id="web_attack_sql",
            flagged_flow=FlaggedFlow(
                flow=_flow("203.0.113.50", "192.168.1.100", 54321, 80, "TCP",
                           200, 150000, 10.0),
                anomaly_score=0.65,
                reason="high byte rate (15000 B/s)",
            ),
            expected_severity="medium",
            expected_threat_type="web attack",
            expected_keywords=["SQL injection", "web", "HTTP", "injection",
                               "application attack"],
            description="External IP sending large payloads to web server on port 80",
        ),

        # --- Case 6: Data exfiltration ---
        EvalCase(
            id="data_exfiltration",
            flagged_flow=FlaggedFlow(
                flow=_flow("192.168.1.30", "185.100.87.10", 49999, 443, "TCP",
                           500, 50000000, 120.0),
                anomaly_score=0.80,
                reason="high byte rate (416666 B/s)",
            ),
            expected_severity="high",
            expected_threat_type="data exfiltration",
            expected_keywords=["exfiltration", "data transfer", "data theft",
                               "outbound", "large transfer"],
            description="Internal host sending 50MB to external IP over HTTPS",
        ),

        # --- Case 7: Cryptocurrency mining (C2 on unusual port) ---
        EvalCase(
            id="cryptomining_c2",
            flagged_flow=FlaggedFlow(
                flow=_flow("192.168.1.40", "45.33.32.156", 51234, 8888, "TCP",
                           3000, 240000, 600.0),
                anomaly_score=0.60,
                reason="suspicious destination port 8888",
            ),
            expected_severity="medium",
            expected_threat_type="cryptomining",
            expected_keywords=["mining", "cryptominer", "cryptocurrency",
                               "C2", "command and control", "suspicious port"],
            description="Persistent connection to suspicious external IP on port 8888",
        ),

        # --- Case 8: SMTP spam relay ---
        EvalCase(
            id="smtp_spam_relay",
            flagged_flow=FlaggedFlow(
                flow=_flow("192.168.1.50", "10.0.0.25", 55555, 25, "TCP",
                           10000, 5000000, 60.0),
                anomaly_score=0.70,
                reason="high packet rate (166 pps); high byte rate (83333 B/s)",
            ),
            expected_severity="medium",
            expected_threat_type="spam relay",
            expected_keywords=["SMTP", "spam", "email", "relay", "mail"],
            description="Very high volume of SMTP traffic suggesting spam relay",
        ),

        # --- Case 9: ICMP flood / ping of death ---
        EvalCase(
            id="icmp_flood",
            flagged_flow=FlaggedFlow(
                flow=_flow("10.0.0.100", "192.168.1.1", 0, 0, "OTHER",
                           50000, 75000000, 10.0),
                anomaly_score=0.90,
                reason="high packet rate (5000 pps); high byte rate (7500000 B/s)",
            ),
            expected_severity="high",
            expected_threat_type="denial of service",
            expected_keywords=["DoS", "denial of service", "flood", "DDoS",
                               "ICMP", "volumetric"],
            description="Massive packet flood from internal host (potential DoS)",
        ),

        # --- Case 10: Lateral movement (SMB) ---
        EvalCase(
            id="lateral_movement_smb",
            flagged_flow=FlaggedFlow(
                flow=_flow("192.168.1.10", "192.168.1.200", 49999, 445, "TCP",
                           300, 180000, 15.0),
                anomaly_score=0.72,
                reason="high byte rate (12000 B/s)",
            ),
            expected_severity="high",
            expected_threat_type="lateral movement",
            expected_keywords=["lateral movement", "SMB", "internal", "pivot",
                               "spread", "445"],
            description="Internal-to-internal SMB traffic suggesting lateral movement",
        ),
    ]

    return cases
