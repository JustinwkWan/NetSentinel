"""PacketSource interface and implementations."""

from __future__ import annotations

from collections import defaultdict
from typing import Protocol, runtime_checkable

from scapy.all import IP, TCP, UDP, rdpcap

from netsentinel.ingestion.flows import FlowRecord


@runtime_checkable
class PacketSource(Protocol):
    """Source-agnostic interface for packet ingestion."""

    def packets(self) -> list[dict]:
        """Return a list of packet dicts with standardized fields."""
        ...


class PcapFileSource:
    """Reads packets from a .pcap file using scapy."""

    def __init__(self, path: str):
        self.path = path

    def packets(self) -> list[dict]:
        pkts = rdpcap(self.path)
        result = []
        for pkt in pkts:
            parsed = self._parse_packet(pkt)
            if parsed is not None:
                result.append(parsed)
        return result

    @staticmethod
    def _parse_packet(pkt) -> dict | None:
        try:
            if not pkt.haslayer(IP):
                return None

            ip = pkt[IP]
            proto = "OTHER"
            src_port = 0
            dst_port = 0

            if pkt.haslayer(TCP):
                proto = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            return {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "length": len(pkt),
                "timestamp": float(pkt.time),
            }
        except Exception:
            return None


def process_packets(source: PacketSource) -> list[FlowRecord]:
    """Aggregate packets from any source into FlowRecords."""
    packets = source.packets()

    flows: dict[str, dict] = defaultdict(
        lambda: {
            "src_ip": "",
            "dst_ip": "",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "",
            "packet_count": 0,
            "byte_count": 0,
            "start_time": float("inf"),
            "end_time": 0.0,
        }
    )

    for pkt in packets:
        key = f"{pkt['src_ip']}:{pkt['src_port']}->{pkt['dst_ip']}:{pkt['dst_port']}/{pkt['protocol']}"
        flow = flows[key]
        flow["src_ip"] = pkt["src_ip"]
        flow["dst_ip"] = pkt["dst_ip"]
        flow["src_port"] = pkt["src_port"]
        flow["dst_port"] = pkt["dst_port"]
        flow["protocol"] = pkt["protocol"]
        flow["packet_count"] += 1
        flow["byte_count"] += pkt["length"]
        flow["start_time"] = min(flow["start_time"], pkt["timestamp"])
        flow["end_time"] = max(flow["end_time"], pkt["timestamp"])

    records = []
    for flow_data in flows.values():
        duration = flow_data["end_time"] - flow_data["start_time"]
        records.append(
            FlowRecord(
                src_ip=flow_data["src_ip"],
                dst_ip=flow_data["dst_ip"],
                src_port=flow_data["src_port"],
                dst_port=flow_data["dst_port"],
                protocol=flow_data["protocol"],
                packet_count=flow_data["packet_count"],
                byte_count=flow_data["byte_count"],
                duration=max(duration, 0.0),
                start_time=flow_data["start_time"],
            )
        )

    return records
