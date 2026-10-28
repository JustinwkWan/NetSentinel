"""Synthetic attack and benign traffic for measuring the detector.

Each scenario builds the packets of one attack instance, shaped like the
real thing on the wire: handshakes, replies, flags, sizes and timing. The
packets go through the real ingestion path (written to a pcap, read back),
so the detector sees them exactly as it would see captured traffic.

These are labeled by construction: a generator called port_scan produces a
port scan. They are not captured attacks, so they show how the detector
responds to each attack's shape, not how it fares against real adversaries.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass

from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

INTERNAL_NET = "192.168.1"
EXTERNAL_NETS = ["203.0.113", "198.51.100", "185.100.87"]


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


def _icmp(src, dst, icmp_type, size, ts):
    pkt = Ether() / IP(src=src, dst=dst) / ICMP(type=icmp_type)
    return _pad(pkt, size, ts)


def _internal(rng: random.Random) -> str:
    return f"{INTERNAL_NET}.{rng.randint(2, 254)}"


def _external(rng: random.Random) -> str:
    return f"{rng.choice(EXTERNAL_NETS)}.{rng.randint(1, 254)}"


def _ephemeral(rng: random.Random) -> int:
    return rng.randint(49152, 65535)


def _handshake(client, server, sport, dport, t, rtt) -> tuple[list, float]:
    pkts = [
        _tcp(client, server, sport, dport, "S", 74, t),
        _tcp(server, client, dport, sport, "SA", 74, t + rtt),
        _tcp(client, server, sport, dport, "A", 66, t + rtt + 0.001),
    ]
    return pkts, t + rtt + 0.001


def _close(client, server, sport, dport, t, rtt) -> list:
    return [
        _tcp(client, server, sport, dport, "FA", 66, t),
        _tcp(server, client, dport, sport, "FA", 66, t + rtt),
        _tcp(client, server, sport, dport, "A", 66, t + rtt + 0.001),
    ]


# --- Attacks ---------------------------------------------------------------

def port_scan(rng: random.Random, start: float) -> list:
    """SYN to 100 ports of one host; closed ports answer with RST."""
    scanner, target = _internal(rng), _internal(rng)
    sport = _ephemeral(rng)
    pkts, t = [], start
    for port in rng.sample(range(1, 10000), 100):
        pkts.append(_tcp(scanner, target, sport, port, "S", 60, t))
        pkts.append(_tcp(target, scanner, port, sport, "RA", 60, t + 0.0003))
        t += rng.uniform(0.0005, 0.003)
    return pkts


def stealth_scan(rng: random.Random, start: float) -> list:
    """SYN to 100 ports behind a firewall that drops them: no replies."""
    scanner, target = _external(rng), _internal(rng)
    sport = _ephemeral(rng)
    pkts, t = [], start
    for port in rng.sample(range(1, 10000), 100):
        pkts.append(_tcp(scanner, target, sport, port, "S", 60, t))
        t += rng.uniform(0.0005, 0.003)
    return pkts


def syn_flood(rng: random.Random, start: float) -> list:
    """SYNs from spoofed sources to a web server, which answers SYN/ACK."""
    target = _internal(rng)
    pkts, t = [], start
    for _ in range(200):
        src, sport = _external(rng), _ephemeral(rng)
        pkts.append(_tcp(src, target, sport, 80, "S", 60, t))
        pkts.append(_tcp(target, src, 80, sport, "SA", 60, t + 0.0002))
        t += rng.uniform(0.0001, 0.0005)
    return pkts


def ssh_brute_force(rng: random.Random, start: float) -> list:
    """30 quick SSH logins: banners, key exchange, a failed password, close."""
    attacker, target = _external(rng), _internal(rng)
    pkts, t = [], start
    for _ in range(30):
        sport, rtt = _ephemeral(rng), rng.uniform(0.02, 0.06)
        hs, t = _handshake(attacker, target, sport, 22, t, rtt)
        pkts += hs
        exchange = [
            (target, attacker, 22, sport, rng.randint(90, 110)),  # server banner
            (attacker, target, sport, 22, rng.randint(80, 100)),  # client banner
            (attacker, target, sport, 22, rng.randint(1200, 1500)),  # KEXINIT
            (target, attacker, 22, sport, rng.randint(1000, 1200)),  # KEXINIT
            (attacker, target, sport, 22, rng.randint(100, 120)),  # ECDH init
            (target, attacker, 22, sport, rng.randint(500, 700)),  # ECDH reply
            (attacker, target, sport, 22, rng.randint(130, 160)),  # password
            (target, attacker, 22, sport, rng.randint(80, 100)),  # auth failure
        ]
        for src, dst, sp, dp, size in exchange:
            t += rtt
            pkts.append(_tcp(src, dst, sp, dp, "PA", size, t))
        t += rtt
        pkts.append(_tcp(target, attacker, 22, sport, "RA", 66, t))
        t += rng.uniform(0.05, 0.3)
    return pkts


def reverse_shell(rng: random.Random, start: float) -> list:
    """A compromised host calls out to port 4444 and runs typed commands."""
    victim, attacker = _internal(rng), _external(rng)
    sport, rtt = _ephemeral(rng), rng.uniform(0.03, 0.1)
    pkts, t = _handshake(victim, attacker, sport, 4444, start, rtt)
    for _ in range(40):
        t += rng.uniform(1.0, 5.0)  # the operator types the next command
        pkts.append(_tcp(attacker, victim, 4444, sport, "PA", rng.randint(60, 120), t))
        t += rtt
        for _ in range(rng.randint(1, 3)):
            pkts.append(_tcp(victim, attacker, sport, 4444, "PA",
                             rng.randint(100, 1500), t))
            t += rng.uniform(0.001, 0.01)
    return pkts


def dns_tunnel(rng: random.Random, start: float) -> list:
    """Data smuggled in long DNS queries and TXT answers to one resolver."""
    client, resolver = _internal(rng), "8.8.8.8"
    sport = _ephemeral(rng)
    pkts, t = [], start
    for _ in range(64):
        pkts.append(_udp(client, resolver, sport, 53, rng.randint(200, 255), t))
        t += rng.uniform(0.01, 0.04)
        pkts.append(_udp(resolver, client, 53, sport, rng.randint(250, 500), t))
        t += rng.uniform(0.02, 0.2)
    return pkts


def exfiltration(rng: random.Random, start: float) -> list:
    """A bulk one-way upload of full-size packets, acked by the receiver."""
    src, dst = _internal(rng), _external(rng)
    sport, rtt = _ephemeral(rng), rng.uniform(0.02, 0.08)
    pkts, t = _handshake(src, dst, sport, 443, start, rtt)
    for i in range(400):
        t += rng.uniform(0.0001, 0.0004)
        pkts.append(_tcp(src, dst, sport, 443, "PA", 1514, t))
        if i % 2:
            pkts.append(_tcp(dst, src, 443, sport, "A", 66, t + rtt))
    return pkts


def icmp_flood(rng: random.Random, start: float) -> list:
    """1,000 large echo requests in about a second; few get answered."""
    attacker, target = _external(rng), _internal(rng)
    pkts, t = [], start
    for _ in range(1000):
        pkts.append(_icmp(attacker, target, 8, 1042, t))
        if rng.random() < 0.1:
            pkts.append(_icmp(target, attacker, 0, 1042, t + 0.0005))
        t += rng.uniform(0.0005, 0.0015)
    return pkts


# --- Benign control --------------------------------------------------------

def benign_web(rng: random.Random, start: float) -> list:
    """Ordinary sessions in the same synthetic style as the attacks.

    If the detector flags these too, it is reacting to the generator, not
    to attack shapes, and the attack numbers mean little.
    """
    pkts, t = [], start
    for _ in range(20):
        if rng.random() < 0.3:
            client, sport = _internal(rng), _ephemeral(rng)
            pkts.append(_udp(client, "8.8.8.8", sport, 53, rng.randint(70, 90), t))
            pkts.append(_udp("8.8.8.8", client, 53, sport, rng.randint(100, 300),
                             t + rng.uniform(0.005, 0.05)))
        else:
            pkts += _web_session(rng, t)
        t += rng.uniform(0.05, 0.5)
    return pkts


def _web_session(rng: random.Random, start: float) -> list:
    client, server = _internal(rng), _external(rng)
    sport, rtt = _ephemeral(rng), rng.uniform(0.01, 0.08)
    dport = rng.choice([443, 443, 80])
    pkts, t = _handshake(client, server, sport, dport, start, rtt)
    for _ in range(rng.randint(1, 4)):
        t += rng.uniform(0.05, 1.0)
        pkts.append(_tcp(client, server, sport, dport, "PA", rng.randint(200, 600), t))
        t += rtt
        for _ in range(rng.randint(1, 4)):
            pkts.append(_tcp(server, client, dport, sport, "PA",
                             rng.randint(600, 1500), t))
            t += rng.uniform(0.0005, 0.005)
        pkts.append(_tcp(client, server, sport, dport, "A", 66, t))
    t += rng.uniform(0.1, 2.0)
    return pkts + _close(client, server, sport, dport, t, rtt)


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    generate: Callable[[random.Random, float], list]


ATTACK_SCENARIOS = [
    Scenario("port_scan", "SYN scan of 100 ports, closed ports reply RST", port_scan),
    Scenario("stealth_scan", "SYN scan of 100 firewalled ports, no replies",
             stealth_scan),
    Scenario("syn_flood", "200 spoofed SYNs to port 80", syn_flood),
    Scenario("ssh_brute_force", "30 failed SSH logins", ssh_brute_force),
    Scenario("reverse_shell", "Interactive shell to port 4444", reverse_shell),
    Scenario("dns_tunnel", "Data in long DNS queries and answers", dns_tunnel),
    Scenario("exfiltration", "One-way bulk upload over 443", exfiltration),
    Scenario("icmp_flood", "1,000 large pings in about a second", icmp_flood),
]

BENIGN_CONTROL = Scenario(
    "benign_synthetic", "Normal web and DNS sessions, same generator style",
    benign_web,
)
