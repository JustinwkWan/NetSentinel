"""PacketSource interface and implementations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from scapy.all import IP, TCP, UDP, rdpcap

from netsentinel.ingestion.flows import FlowRecord, PacketRecord

PCAP_SUFFIXES = (".pcap", ".pcapng")

TCP_SYN = 0x02
TCP_ACK = 0x10
WELL_KNOWN_PORT_LIMIT = 1024  # ports below this are taken to be the server side


@runtime_checkable
class PacketSource(Protocol):
    """Source-agnostic interface for packet ingestion."""

    def packets(self) -> list[dict]:
        """Return a list of packet dicts with standardized fields:
        src_ip, dst_ip, src_port, dst_port, protocol, length, timestamp,
        and tcp_flags (0 for non-TCP packets)."""
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

    Both directions of a connection share one flow, whose src is the
    endpoint that initiated the connection (see _initiator).
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
        initiator = _initiator(pkts)
        a = (first["src_ip"], first["src_port"])
        responder = (first["dst_ip"], first["dst_port"]) if a == initiator else a
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
                src_ip=initiator[0],
                dst_ip=responder[0],
                src_port=initiator[1],
                dst_port=responder[1],
                protocol=first["protocol"],
                packet_count=len(sequence),
                byte_count=sum(p.length for p in sequence),
                duration=max(sequence[-1].timestamp - start, 0.0),
                start_time=start,
                packets=sequence,
            )
        )

    return records


def _initiator(pkts: list[dict]) -> tuple[str, int]:
    """The (ip, port) that opened the connection.

    A capture window can start mid-connection, so the first packet seen may
    be the server's. In order of reliability: the sender of a SYN without
    ACK; else the side not on a well-known port, when exactly one side is;
    else whoever spoke first.
    """
    for p in pkts:
        if p["tcp_flags"] & TCP_SYN and not p["tcp_flags"] & TCP_ACK:
            return (p["src_ip"], p["src_port"])
    first = pkts[0]
    src = (first["src_ip"], first["src_port"])
    dst = (first["dst_ip"], first["dst_port"])
    src_known = src[1] < WELL_KNOWN_PORT_LIMIT
    dst_known = dst[1] < WELL_KNOWN_PORT_LIMIT
    if src_known and not dst_known:
        return dst
    return src
