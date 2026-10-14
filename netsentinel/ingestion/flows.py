"""FlowRecord data object and flow assembly from packets."""

from dataclasses import dataclass, field


@dataclass
class PacketRecord:
    """One packet of a flow, as the sequence detector sees it."""

    timestamp: float  # epoch seconds
    length: int  # frame bytes
    direction: int  # +1 initiator -> responder, -1 responder -> initiator
    tcp_flags: int  # raw TCP flags byte; 0 for UDP and other protocols


@dataclass
class FlowRecord:
    """A bidirectional network flow. src is the endpoint that spoke first."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration: float  # seconds
    start_time: float  # epoch timestamp

    # Derived features (computed after assembly)
    packet_rate: float = 0.0  # packets per second
    mean_packet_size: float = 0.0  # bytes per packet

    # Packets in arrival order, both directions
    packets: list[PacketRecord] = field(default_factory=list, repr=False)

    def __post_init__(self):
        self.packet_rate = (
            self.packet_count / self.duration if self.duration > 0 else 0.0
        )
        self.mean_packet_size = (
            self.byte_count / self.packet_count if self.packet_count > 0 else 0.0
        )

    @property
    def flow_key(self) -> str:
        return f"{_endpoint(self.src_ip, self.src_port)}->{_endpoint(self.dst_ip, self.dst_port)}/{self.protocol}"


def _endpoint(ip: str, port: int) -> str:
    # IPv6 addresses contain colons, so bracket them as in URLs (RFC 3986)
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
