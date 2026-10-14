"""PacketSource interface and implementations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from scapy.all import IP, TCP, UDP, rdpcap

from netsentinel.ingestion.flows import FlowRecord, PacketRecord

PCAP_SUFFIXES = (".pcap", ".pcapng")


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
            tcp_flags = 0

            if pkt.haslayer(TCP):
                proto = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                tcp_flags = int(pkt[TCP].flags)
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
                "tcp_flags": tcp_flags,
            }
        except Exception:
            return None


def process_packets(source: PacketSource) -> list[FlowRecord]:
    """Group packets from any source into bidirectional FlowRecords.

    Both directions of a connection share one flow. The endpoint that sent
    the earliest packet is the initiator and becomes the flow's src.
    """
    packets = sorted(source.packets(), key=lambda p: p["timestamp"])

    grouped: dict[tuple, list[dict]] = {}
    for pkt in packets:
        a = (pkt["src_ip"], pkt["src_port"])
        b = (pkt["dst_ip"], pkt["dst_port"])
        key = (pkt["protocol"], min(a, b), max(a, b))
        grouped.setdefault(key, []).append(pkt)

    records = []
    for pkts in grouped.values():
        first = pkts[0]
        initiator = (first["src_ip"], first["src_port"])
        sequence = [
            PacketRecord(
                timestamp=p["timestamp"],
                length=p["length"],
                direction=1 if (p["src_ip"], p["src_port"]) == initiator else -1,
                tcp_flags=p["tcp_flags"],
            )
            for p in pkts
        ]
        start = sequence[0].timestamp
        records.append(
            FlowRecord(
                src_ip=first["src_ip"],
                dst_ip=first["dst_ip"],
                src_port=first["src_port"],
                dst_port=first["dst_port"],
                protocol=first["protocol"],
                packet_count=len(sequence),
                byte_count=sum(p.length for p in sequence),
                duration=max(sequence[-1].timestamp - start, 0.0),
                start_time=start,
                packets=sequence,
            )
        )

    return records
