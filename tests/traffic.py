"""Synthetic but protocol-shaped traffic for tests.

Real TCP conversations: handshake, request/response turns with varied
timing, and a FIN close. Anomalies differ in shape (RST replies, one-way
bursts), not just in totals.
"""

from __future__ import annotations

import random

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

CLIENT_NET = "192.168.1"
SERVER_NETS = ["93.184.216", "142.250.80", "151.101.1"]


def _pad(pkt, size: int, ts: float):
    pad = max(0, size - len(pkt))
    if pad:
        pkt = pkt / Raw(b"x" * pad)
    pkt.time = ts
    return pkt


def _tcp(src, dst, sport, dport, flags, size, ts):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return _pad(pkt, size, ts)


def _udp(src, dst, sport, dport, size, ts):
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    return _pad(pkt, size, ts)


def tcp_session(rng: random.Random, start: float, dport: int = 443) -> list:
    client = f"{CLIENT_NET}.{rng.randint(2, 254)}"
    server = f"{rng.choice(SERVER_NETS)}.{rng.randint(1, 254)}"
    sport = rng.randint(49152, 65535)
    rtt = rng.uniform(0.01, 0.08)
    t = start
    pkts = [_tcp(client, server, sport, dport, "S", 74, t)]
    t += rtt
    pkts.append(_tcp(server, client, dport, sport, "SA", 74, t))
    t += 0.001
    pkts.append(_tcp(client, server, sport, dport, "A", 66, t))
    for _ in range(rng.randint(1, 4)):
        t += rng.uniform(0.05, 1.0)
        pkts.append(_tcp(client, server, sport, dport, "PA", rng.randint(200, 600), t))
        t += rtt
        for _ in range(rng.randint(1, 4)):
            pkts.append(_tcp(server, client, dport, sport, "PA", rng.randint(600, 1500), t))
            t += rng.uniform(0.0005, 0.005)
        pkts.append(_tcp(client, server, sport, dport, "A", 66, t))
    t += rng.uniform(0.1, 2.0)
    pkts.append(_tcp(client, server, sport, dport, "FA", 66, t))
    t += rtt
    pkts.append(_tcp(server, client, dport, sport, "FA", 66, t))
    t += 0.001
    pkts.append(_tcp(client, server, sport, dport, "A", 66, t))
    return pkts


def dns_exchange(rng: random.Random, start: float) -> list:
    client = f"{CLIENT_NET}.{rng.randint(2, 254)}"
    sport = rng.randint(49152, 65535)
    return [
        _udp(client, "8.8.8.8", sport, 53, rng.randint(70, 90), start),
        _udp("8.8.8.8", client, 53, sport, rng.randint(100, 300),
             start + rng.uniform(0.005, 0.05)),
    ]


def normal_traffic(n_flows: int, seed: int = 0, start: float = 1_000_000.0) -> list:
    rng = random.Random(seed)
    pkts, t = [], start
    for _ in range(n_flows):
        if rng.random() < 0.3:
            pkts += dns_exchange(rng, t)
        else:
            pkts += tcp_session(rng, t, dport=rng.choice([443, 443, 80, 22]))
        t += rng.uniform(0.05, 0.5)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def port_scan(start: float, ports: range, target: str = "10.0.0.5") -> list:
    """One SYN per port, each answered by an immediate RST."""
    scanner, sport = "192.168.1.66", 40000
    pkts, t = [], start
    for port in ports:
        pkts.append(_tcp(scanner, target, sport, port, "S", 60, t))
        pkts.append(_tcp(target, scanner, port, sport, "RA", 60, t + 0.0002))
        t += 0.001
    return pkts


def exfil_burst(start: float, n: int = 32) -> list:
    """A one-way stream of full-size packets with no replies."""
    src, dst, sport, dport = "192.168.1.77", "203.0.113.9", 51000, 443
    return [_tcp(src, dst, sport, dport, "PA", 1514, start + i * 0.0001) for i in range(n)]


def write_pcap(path, packets) -> None:
    wrpcap(str(path), packets)
