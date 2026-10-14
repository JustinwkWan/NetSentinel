"""Tests for packet parsing and bidirectional flow assembly."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.ingestion.flows import PacketRecord
from netsentinel.ingestion.sources import PcapFileSource, process_packets
from tests.traffic import dns_exchange, tcp_session, write_pcap


class ListSource:
    def __init__(self, packets: list[dict]):
        self._packets = packets

    def packets(self) -> list[dict]:
        return self._packets


def _pkt(src, sport, dst, dport, ts, length=100, proto="TCP", flags=0):
    return {"src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": proto, "length": length, "timestamp": ts, "tcp_flags": flags}


class TestBidirectionalFlows:
    def test_both_directions_form_one_flow(self):
        flows = process_packets(ListSource([
            _pkt("10.0.0.1", 50000, "1.1.1.1", 443, 1.0, length=74, flags=0x02),
            _pkt("1.1.1.1", 443, "10.0.0.1", 50000, 1.1, length=74, flags=0x12),
            _pkt("10.0.0.1", 50000, "1.1.1.1", 443, 1.2, length=66, flags=0x10),
        ]))
        assert len(flows) == 1
        flow = flows[0]
        assert (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port) == (
            "10.0.0.1", 50000, "1.1.1.1", 443)
        assert flow.packet_count == 3
        assert flow.byte_count == 214
        assert flow.duration == 1.2 - 1.0
        assert [p.direction for p in flow.packets] == [1, -1, 1]
        assert [p.tcp_flags for p in flow.packets] == [0x02, 0x12, 0x10]

    def test_initiator_is_first_sender_even_if_listed_late(self):
        flows = process_packets(ListSource([
            _pkt("1.1.1.1", 443, "10.0.0.1", 50000, 2.0),
            _pkt("10.0.0.1", 50000, "1.1.1.1", 443, 1.0),
        ]))
        assert flows[0].src_ip == "10.0.0.1"
        assert [p.timestamp for p in flows[0].packets] == [1.0, 2.0]
        assert [p.direction for p in flows[0].packets] == [1, -1]

    def test_different_protocols_stay_separate(self):
        flows = process_packets(ListSource([
            _pkt("10.0.0.1", 5000, "1.1.1.1", 443, 1.0, proto="TCP"),
            _pkt("10.0.0.1", 5000, "1.1.1.1", 443, 1.0, proto="UDP"),
        ]))
        assert len(flows) == 2

    def test_packets_are_packet_records(self):
        flows = process_packets(ListSource([_pkt("a", 1, "b", 2, 1.0)]))
        assert flows[0].packets == [PacketRecord(1.0, 100, 1, 0)]


class TestInitiator:
    def test_syn_sender_is_initiator_even_if_not_first_seen(self):
        flows = process_packets(ListSource([
            _pkt("1.1.1.1", 8080, "10.0.0.1", 50000, 1.0, flags=0x10),  # stray ACK
            _pkt("10.0.0.1", 50000, "1.1.1.1", 8080, 1.1, flags=0x02),  # SYN
        ]))
        assert (flows[0].src_ip, flows[0].src_port) == ("10.0.0.1", 50000)
        assert [p.direction for p in flows[0].packets] == [-1, 1]

    def test_mid_connection_window_uses_well_known_port_as_server(self):
        # A long connection split by a capture window: the first packet seen
        # is the server's reply, and there is no SYN.
        flows = process_packets(ListSource([
            _pkt("1.1.1.1", 443, "10.0.0.1", 50000, 1.0, flags=0x18),
            _pkt("10.0.0.1", 50000, "1.1.1.1", 443, 1.1, flags=0x10),
        ]))
        assert flows[0].flow_key == "10.0.0.1:50000->1.1.1.1:443/TCP"
        assert [p.direction for p in flows[0].packets] == [-1, 1]

    def test_udp_reply_seen_first_uses_well_known_port_as_server(self):
        flows = process_packets(ListSource([
            _pkt("8.8.8.8", 53, "10.0.0.1", 51000, 1.0, proto="UDP"),
        ]))
        assert flows[0].flow_key == "10.0.0.1:51000->8.8.8.8:53/UDP"

    def test_both_high_ports_fall_back_to_first_sender(self):
        flows = process_packets(ListSource([
            _pkt("1.1.1.1", 5223, "10.0.0.1", 50000, 1.0, flags=0x18),
        ]))
        assert flows[0].src_ip == "1.1.1.1"


class TestPcapParsing:
    def test_tcp_flags_and_udp_zero_flags(self, tmp_path):
        rng = random.Random(1)
        pcap = tmp_path / "t.pcap"
        write_pcap(pcap, tcp_session(rng, 100.0) + dns_exchange(rng, 200.0))

        flows = process_packets(PcapFileSource(str(pcap)))

        by_proto = {f.protocol: f for f in flows}
        assert set(by_proto) == {"TCP", "UDP"}
        tcp = by_proto["TCP"]
        assert tcp.packets[0].tcp_flags == 0x02  # SYN
        assert tcp.packets[1].tcp_flags == 0x12  # SYN-ACK
        assert tcp.packets[1].direction == -1
        assert all(p.tcp_flags == 0 for p in by_proto["UDP"].packets)
