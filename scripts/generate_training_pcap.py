"""Generate a PCAP of normal-looking network traffic for LSTM training.

Creates diverse but benign traffic patterns: HTTP, HTTPS, DNS, SSH,
email protocols at typical rates and sizes.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap


def generate_normal_traffic(num_flows: int = 500, base_time: float = 1000000.0):
    """Generate packets representing normal network traffic."""
    packets = []

    # Normal traffic profiles: (dst_port, protocol, pkt_count_range, size_range, label)
    profiles = [
        (80, "TCP", (5, 50), (64, 1500), "HTTP"),
        (443, "TCP", (10, 100), (64, 1500), "HTTPS"),
        (53, "UDP", (1, 3), (40, 512), "DNS"),
        (22, "TCP", (5, 30), (64, 800), "SSH"),
        (25, "TCP", (3, 15), (64, 2000), "SMTP"),
        (993, "TCP", (5, 20), (64, 1200), "IMAPS"),
        (8080, "TCP", (5, 40), (64, 1500), "HTTP-alt"),
        (3306, "TCP", (3, 20), (64, 1000), "MySQL"),
        (5432, "TCP", (3, 20), (64, 1000), "PostgreSQL"),
        (6379, "TCP", (5, 30), (64, 500), "Redis"),
    ]

    # Internal IP ranges
    src_subnets = ["192.168.1", "10.0.0", "172.16.0"]
    dst_subnets = ["93.184.216", "8.8.8", "1.1.1", "142.250.80",
                   "151.101.1", "104.16.0"]

    current_time = base_time

    for _ in range(num_flows):
        profile = random.choice(profiles)
        dst_port, proto, pkt_range, size_range, _label = profile

        src_ip = f"{random.choice(src_subnets)}.{random.randint(2, 254)}"
        dst_ip = f"{random.choice(dst_subnets)}.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)

        num_pkts = random.randint(*pkt_range)
        # Normal inter-packet time: 0.01 to 2.0 seconds
        iat = random.uniform(0.01, 2.0)

        for j in range(num_pkts):
            pkt_size = random.randint(*size_range)
            payload = Raw(b"X" * max(0, pkt_size - 54))

            if proto == "TCP":
                pkt = (
                    Ether()
                    / IP(src=src_ip, dst=dst_ip)
                    / TCP(sport=src_port, dport=dst_port)
                    / payload
                )
            else:
                pkt = (
                    Ether()
                    / IP(src=src_ip, dst=dst_ip)
                    / UDP(sport=src_port, dport=dst_port)
                    / payload
                )

            pkt.time = current_time + j * iat
            packets.append(pkt)

        # Gap between flows
        current_time += num_pkts * iat + random.uniform(0.5, 5.0)

    return packets


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate normal traffic PCAP for LSTM training"
    )
    parser.add_argument(
        "--flows", type=int, default=500, help="Number of flows to generate"
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).resolve().parent.parent / "data" / "pcaps" / "normal_traffic.pcap"),
        help="Output PCAP path",
    )
    args = parser.parse_args()

    random.seed(42)
    print(f"[*] Generating {args.flows} normal traffic flows...")
    packets = generate_normal_traffic(num_flows=args.flows)
    print(f"[*] Generated {len(packets)} packets")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    print(f"[*] Saved to {output_path}")


if __name__ == "__main__":
    main()
