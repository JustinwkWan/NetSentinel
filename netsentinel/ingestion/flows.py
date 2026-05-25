"""FlowRecord data object and flow assembly from packets."""

from dataclasses import dataclass, field


@dataclass
class FlowRecord:
    """A single network flow aggregated from packets."""

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

    def __post_init__(self):
        self.packet_rate = (
            self.packet_count / self.duration if self.duration > 0 else 0.0
        )
        self.mean_packet_size = (
            self.byte_count / self.packet_count if self.packet_count > 0 else 0.0
        )

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"
