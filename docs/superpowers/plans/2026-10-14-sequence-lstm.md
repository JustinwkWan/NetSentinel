# Sequence LSTM Detector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the LSTM detector into a real per-packet sequence model, trained on the user's own captured traffic, and make it the only detector.

**Architecture:** Ingestion merges both directions of a connection into one `FlowRecord` that carries an ordered `packets` list.
The detector encodes each flow's first 32 packets as 8-feature steps and scores them with a masked LSTM autoencoder.
Live capture can save finished windows into `data/training/`, which `scripts/train_lstm.py` trains on.
The stub detector and every detector selector are removed.

**Tech Stack:** Python 3.14, scapy, PyTorch, FastAPI, pytest; React 19 + TypeScript + Tailwind + Vitest.

**Spec:** `docs/superpowers/specs/2026-10-14-sequence-lstm-design.md`

## Global Constraints

- Never use the em dash character in code, comments, copy, or docs. Use a plain "-".
- All tunables live in `config.py`; no magic numbers in code.
- Data objects are plain dataclasses; contracts use `typing.Protocol`.
- Python commands run inside the venv: prefix with `source venv/bin/activate &&`.
- Web commands run from `web/`: `npm test`, `npm run lint`, `npm run build`.
- Work on branch `feature/sequence-lstm`, not `main`. Commit messages carry no AI co-author line.
- No-model message, verbatim: `No compatible LSTM model. Collect training data with the dashboard's 'Save windows for training' toggle, then run: python scripts/train_lstm.py`
- `CHECKPOINT_FORMAT_VERSION = 2`; `LSTM_MAX_SEQ_LEN = 32`; `LSTM_MIN_TRAINING_FLOWS = 500`; `LSTM_SCORE_BATCH_SIZE = 256`; `TRAINING_DIR = DATA_DIR / "training"`.
- `TRAINING_EXCLUDE_PORTS = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345}`.

## Review Focus

- A flow with zero packets (e.g. built by `eval/dataset.py` without packets) reaching the detector: it must be skipped, not crash scoring. Pinned in Task 2.
- A checkpoint file that is corrupt or not a dict: must surface the no-model message, not a stack trace. Pinned in Task 2.
- The same window being saved twice (stop re-scans files the watcher already saw): must not raise or double count. Pinned in Task 5.
- Training paths that mix files, directories, and non-pcap files: only `.pcap`/`.pcapng` files are used. Pinned in Task 3.
- A packet whose timestamp is earlier than the previous one in the same flow: the gap must clamp to 0, never `log1p` of a negative. Pinned in Task 2.

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `config.py` | Modify | New training/sequence settings, remove stub and detector settings |
| `netsentinel/ingestion/flows.py` | Modify | `PacketRecord`, `FlowRecord.packets` |
| `netsentinel/ingestion/sources.py` | Modify | TCP flags parsing, bidirectional grouping, `PCAP_SUFFIXES` |
| `netsentinel/detection/lstm.py` | Rewrite | Encoding, batching, masked model, checkpoint loading, detector |
| `netsentinel/detection/stub.py` | Delete | - |
| `netsentinel/detection/__init__.py` | Modify | Drop stub export |
| `scripts/train_lstm.py` | Rewrite | Multi-pcap training with exclusion filter |
| `scripts/generate_training_pcap.py` | Delete | - |
| `scripts/watch_and_run.sh` | Modify | Drop `DETECTOR` |
| `netsentinel/cli.py` | Modify | LSTM only, clean no-model exit |
| `api/models.py`, `api/jobs.py`, `api/main.py` | Modify | Drop `detector`, 409s, `/health` model status |
| `api/capture.py` | Modify | Training toggle, analysis-disabled mode |
| `web/src/api.ts` | Modify | Types and calls without `detector`, `health()` |
| `web/src/App.tsx` | Modify | Fetch model status, pass to panels |
| `web/src/components/RunControls.tsx`, `LocalBrowser.tsx`, `RunStatusPanel.tsx` | Modify | Drop detector UI, show no-model message |
| `web/src/components/LiveCapturePanel.tsx` | Modify | Training switch, saved counter, collecting-only state |
| `tests/traffic.py` | Create | Realistic synthetic traffic builders for tests |
| `tests/test_ingestion.py` | Create | Ingestion tests |
| `tests/test_detection.py`, `tests/test_training.py` | Rewrite | Detector and training tests |
| `tests/test_api.py`, `tests/test_scheduler.py` | Modify | Drop detector, add toggle and 409 tests |
| `tests/test_cli.py` | Create | CLI no-model exit |
| `web/src/components/LiveCapturePanel.test.tsx` | Create | Switch behavior |
| `README.md`, `CLAUDE.md`, `.gitignore` | Modify | Docs and ignore rules |

---

### Task 0: Branch

- [ ] **Step 1: Create the branch**

```bash
git checkout -b feature/sequence-lstm
```

---

### Task 1: Bidirectional flows with packet sequences

**Files:**
- Modify: `config.py`
- Modify: `netsentinel/ingestion/flows.py`
- Modify: `netsentinel/ingestion/sources.py`
- Create: `tests/traffic.py`
- Create: `tests/test_ingestion.py`

**Interfaces:**
- Produces: `PacketRecord(timestamp: float, length: int, direction: int, tcp_flags: int)`; `FlowRecord.packets: list[PacketRecord]` (default empty, `repr=False`); packet dicts gain `"tcp_flags": int`; `PCAP_SUFFIXES = (".pcap", ".pcapng")` in `netsentinel/ingestion/sources.py`.
- Produces (tests): `tests/traffic.py` with `tcp_session`, `dns_exchange`, `normal_traffic`, `port_scan`, `exfil_burst`, `write_pcap`.

- [ ] **Step 1: Add config settings**

In `config.py`, under `# Paths`, add after `CHROMA_DIR`:

```python
TRAINING_DIR = DATA_DIR / "training"  # live-capture windows saved for LSTM training
```

Below `LSTM_MODEL_PATH`, add:

```python
LSTM_MAX_SEQ_LEN = 32  # packets per flow the model sees, from the start of the flow
LSTM_SCORE_BATCH_SIZE = 256  # flows scored per forward pass
LSTM_MIN_TRAINING_FLOWS = 500  # training refuses smaller datasets

# Flows on these ports are never learned as normal traffic
TRAINING_EXCLUDE_PORTS = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345}
```

Leave `DETECTOR_TYPE`, `LSTM_ANOMALY_THRESHOLD`, and the `STUB_*` settings in place; Task 4 removes them once nothing uses them.

- [ ] **Step 2: Create test traffic builders**

Create `tests/traffic.py`:

```python
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


def _tcp(src, dst, sport, dport, flags, size, ts):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    pad = max(0, size - len(pkt))
    if pad:
        pkt = pkt / Raw(b"x" * pad)
    pkt.time = ts
    return pkt


def _udp(src, dst, sport, dport, size, ts):
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    pad = max(0, size - len(pkt))
    if pad:
        pkt = pkt / Raw(b"x" * pad)
    pkt.time = ts
    return pkt


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
```

- [ ] **Step 3: Write failing ingestion tests**

Create `tests/test_ingestion.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `source venv/bin/activate && pytest tests/test_ingestion.py -v`
Expected: FAIL with `ImportError: cannot import name 'PacketRecord'`.

- [ ] **Step 5: Implement data objects**

Replace `netsentinel/ingestion/flows.py` with:

```python
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
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"
```

- [ ] **Step 6: Implement parsing and grouping**

In `netsentinel/ingestion/sources.py`:

Replace the imports and add the suffix constant:

```python
from __future__ import annotations

from typing import Protocol, runtime_checkable

from scapy.all import IP, TCP, UDP, rdpcap

from netsentinel.ingestion.flows import FlowRecord, PacketRecord

PCAP_SUFFIXES = (".pcap", ".pcapng")
```

In `_parse_packet`, set `tcp_flags = 0` next to `src_port = 0`, set `tcp_flags = int(pkt[TCP].flags)` inside the TCP branch, and add `"tcp_flags": tcp_flags,` to the returned dict.

Replace `process_packets` with:

```python
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
```

Remove the now-unused `from collections import defaultdict`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `source venv/bin/activate && pytest tests/test_ingestion.py -v`
Expected: 5 passed.

- [ ] **Step 8: Use the shared suffix constant in the API**

In `api/main.py`, delete `PCAP_SUFFIXES = (".pcap", ".pcapng")` and add `from netsentinel.ingestion.sources import PCAP_SUFFIXES` to the imports.

- [ ] **Step 9: Commit**

```bash
git add config.py netsentinel/ingestion api/main.py tests/traffic.py tests/test_ingestion.py
git commit -m "Group flows bidirectionally and keep per-packet sequences"
```

---

### Task 2: Sequence LSTM model and detector

**Files:**
- Rewrite: `netsentinel/detection/lstm.py`
- Rewrite: `tests/test_detection.py`

**Interfaces:**
- Consumes: `FlowRecord.packets`, `PacketRecord` (Task 1); `config.LSTM_MAX_SEQ_LEN`, `config.LSTM_SCORE_BATCH_SIZE`, `config.LSTM_MODEL_PATH`.
- Produces, all in `netsentinel.detection.lstm`:
  - `NUM_STEP_FEATURES = 8`, `NUM_STANDARDIZED = 2`, `CHECKPOINT_FORMAT_VERSION = 2`, `DEFAULT_HIDDEN_SIZE = 32`, `DEFAULT_NUM_LAYERS = 1`, `NO_MODEL_MESSAGE: str`
  - `class ModelNotTrainedError(RuntimeError)`
  - `encode_flow(flow: FlowRecord, max_len: int) -> torch.Tensor` shape `(n, 8)`
  - `standardize(seq: Tensor, means: list[float], stds: list[float]) -> Tensor`
  - `batch_sequences(seqs: list[Tensor]) -> tuple[Tensor, Tensor]` (x `(B, T, 8)`, lengths `(B,)` long)
  - `sequence_errors(x: Tensor, recon: Tensor, lengths: Tensor) -> Tensor` shape `(B,)`
  - `class FlowLSTMAutoencoder(nn.Module)`: `__init__(input_size=8, hidden_size=32, num_layers=1)`, `forward(x, lengths) -> Tensor`
  - `load_checkpoint(path: str | Path | None = None) -> dict` (raises `ModelNotTrainedError`)
  - `model_status(path: str | Path | None = None) -> str | None` (None when ready)
  - `class LstmDetector`: `__init__(model_path=None, threshold=None)`, `score(flows) -> list[float]`, `flag(flows) -> list[FlaggedFlow]`

- [ ] **Step 1: Write failing detector tests**

Replace `tests/test_detection.py` with:

```python
"""Tests for the sequence LSTM detector."""

from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.detection.base import Detector, FlaggedFlow
from netsentinel.detection.lstm import (
    CHECKPOINT_FORMAT_VERSION,
    NO_MODEL_MESSAGE,
    NUM_STANDARDIZED,
    FlowLSTMAutoencoder,
    LstmDetector,
    ModelNotTrainedError,
    batch_sequences,
    encode_flow,
    model_status,
    sequence_errors,
)
from netsentinel.ingestion.flows import FlowRecord, PacketRecord


def _flow(packets: list[PacketRecord], protocol: str = "TCP") -> FlowRecord:
    return FlowRecord("10.0.0.1", "1.1.1.1", 50000, 443, protocol,
                      len(packets), sum(p.length for p in packets), 1.0,
                      packets[0].timestamp if packets else 0.0, packets=packets)


def _handshake() -> list[PacketRecord]:
    return [PacketRecord(10.0, 74, 1, 0x02), PacketRecord(10.5, 74, -1, 0x12),
            PacketRecord(10.5, 66, 1, 0x10)]


def _save_checkpoint(path: Path, threshold: float = 1.0, **overrides) -> None:
    torch.manual_seed(0)
    model = FlowLSTMAutoencoder(hidden_size=8)
    checkpoint = {
        "format_version": CHECKPOINT_FORMAT_VERSION,
        "model_state_dict": model.state_dict(),
        "hidden_size": 8,
        "num_layers": 1,
        "max_seq_len": 32,
        "feature_means": [0.0] * NUM_STANDARDIZED,
        "feature_stds": [1.0] * NUM_STANDARDIZED,
        "threshold": threshold,
    }
    checkpoint.update(overrides)
    torch.save(checkpoint, path)


class TestEncodeFlow:
    def test_features_of_known_packets(self):
        rows = encode_flow(_flow(_handshake()), max_len=32)
        assert rows.shape == (3, 8)
        assert rows[0].tolist() == pytest.approx(
            [math.log1p(74), 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0])
        assert rows[1].tolist() == pytest.approx(
            [math.log1p(74), math.log1p(0.5), -1.0, 1.0, 1.0, 0.0, 0.0, 0.0])

    def test_udp_has_no_tcp_bits(self):
        rows = encode_flow(_flow([PacketRecord(1.0, 80, 1, 0)], "UDP"), max_len=32)
        assert rows[0, 3:].tolist() == [0.0] * 5

    def test_truncates_to_max_len(self):
        pkts = [PacketRecord(float(i), 100, 1, 0) for i in range(50)]
        assert encode_flow(_flow(pkts), max_len=32).shape == (32, 8)

    def test_out_of_order_timestamp_gap_is_zero(self):
        pkts = [PacketRecord(5.0, 100, 1, 0), PacketRecord(4.0, 100, -1, 0)]
        assert encode_flow(_flow(pkts), max_len=32)[1, 1].item() == 0.0


class TestMasking:
    def test_padding_does_not_change_a_flows_error(self):
        torch.manual_seed(0)
        model = FlowLSTMAutoencoder(hidden_size=8).eval()
        short = torch.randn(3, 8)
        long = torch.randn(20, 8)

        with torch.no_grad():
            x1, l1 = batch_sequences([short])
            alone = sequence_errors(x1, model(x1, l1), l1)[0]
            x2, l2 = batch_sequences([short, long])
            padded = sequence_errors(x2, model(x2, l2), l2)[0]

        assert padded.item() == pytest.approx(alone.item(), rel=1e-5)


class TestCheckpointLoading:
    def test_missing_checkpoint_raises_no_model(self, tmp_path):
        with pytest.raises(ModelNotTrainedError, match="Save windows for training"):
            LstmDetector(model_path=tmp_path / "missing.pt")

    def test_old_format_checkpoint_is_rejected(self, tmp_path):
        path = tmp_path / "old.pt"
        torch.save({"model_state_dict": {}, "feature_means": [0.0] * 7}, path)
        assert model_status(path) == NO_MODEL_MESSAGE

    def test_corrupt_checkpoint_is_rejected(self, tmp_path):
        path = tmp_path / "corrupt.pt"
        path.write_bytes(b"not a checkpoint")
        assert NO_MODEL_MESSAGE in model_status(path)

    def test_ready_checkpoint_has_no_status_message(self, tmp_path):
        path = tmp_path / "m.pt"
        _save_checkpoint(path)
        assert model_status(path) is None


class TestLstmDetector:
    def test_satisfies_protocol(self, tmp_path):
        path = tmp_path / "m.pt"
        _save_checkpoint(path)
        assert isinstance(LstmDetector(model_path=path), Detector)

    def test_threshold_controls_flagging(self, tmp_path):
        path = tmp_path / "m.pt"
        _save_checkpoint(path, threshold=1e6)  # far above any real error
        flow = _flow(_handshake())

        assert LstmDetector(model_path=path).flag([flow]) == []
        flagged = LstmDetector(model_path=path, threshold=0.0).flag([flow])
        assert len(flagged) == 1
        assert isinstance(flagged[0], FlaggedFlow)
        assert flagged[0].flow is flow
        assert 0.0 < flagged[0].anomaly_score <= 1.0
        assert "LSTM" in flagged[0].reason

    def test_flows_without_packets_are_skipped(self, tmp_path):
        path = tmp_path / "m.pt"
        _save_checkpoint(path)
        detector = LstmDetector(model_path=path, threshold=0.0)
        assert detector.flag([_flow([])]) == []

    def test_scores_match_across_batch_sizes(self, tmp_path, monkeypatch):
        path = tmp_path / "m.pt"
        _save_checkpoint(path)
        flows = [_flow([PacketRecord(float(j), 100 + i, 1, 0) for j in range(1 + i % 7)])
                 for i in range(10)]
        detector = LstmDetector(model_path=path)
        expected = detector.score(flows)
        monkeypatch.setattr("config.LSTM_SCORE_BATCH_SIZE", 3)
        assert detector.score(flows) == pytest.approx(expected, rel=1e-5)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source venv/bin/activate && pytest tests/test_detection.py -v`
Expected: FAIL with `ImportError` (e.g. `cannot import name 'CHECKPOINT_FORMAT_VERSION'`).

- [ ] **Step 3: Rewrite the detector module**

Replace `netsentinel/detection/lstm.py` with:

```python
"""LstmDetector - LSTM autoencoder over per-packet sequences.

Each flow becomes the time-ordered sequence of its first max_seq_len
packets. One step is one packet, described by STEP_FEATURES. The model
learns to reconstruct sequences of normal traffic, so flows it
reconstructs poorly are flagged.
"""

from __future__ import annotations

import math
from pathlib import Path

import torch
import torch.nn as nn
from torch.nn.utils.rnn import pack_padded_sequence, pad_sequence

import config
from netsentinel.detection.base import FlaggedFlow
from netsentinel.ingestion.flows import FlowRecord

STEP_FEATURES = [
    "log_size", "log_gap", "direction", "is_tcp", "syn", "fin", "rst", "psh",
]
NUM_STEP_FEATURES = len(STEP_FEATURES)
# The leading features are unbounded and standardized with training
# statistics; the rest are already in [-1, 1].
NUM_STANDARDIZED = 2

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08

CHECKPOINT_FORMAT_VERSION = 2
DEFAULT_HIDDEN_SIZE = 32
DEFAULT_NUM_LAYERS = 1

NO_MODEL_MESSAGE = (
    "No compatible LSTM model. Collect training data with the dashboard's "
    "'Save windows for training' toggle, then run: python scripts/train_lstm.py"
)


class ModelNotTrainedError(RuntimeError):
    """No checkpoint, or one this detector version cannot use."""


def encode_flow(flow: FlowRecord, max_len: int) -> torch.Tensor:
    """Feature rows for the flow's first max_len packets: shape (n, 8)."""
    is_tcp = 1.0 if flow.protocol == "TCP" else 0.0
    rows = []
    prev_ts = None
    for pkt in flow.packets[:max_len]:
        gap = 0.0 if prev_ts is None else max(0.0, pkt.timestamp - prev_ts)
        prev_ts = pkt.timestamp
        flags = pkt.tcp_flags
        rows.append([
            math.log1p(pkt.length),
            math.log1p(gap),
            float(pkt.direction),
            is_tcp,
            float(bool(flags & TCP_SYN)),
            float(bool(flags & TCP_FIN)),
            float(bool(flags & TCP_RST)),
            float(bool(flags & TCP_PSH)),
        ])
    return torch.tensor(rows, dtype=torch.float32).reshape(-1, NUM_STEP_FEATURES)


def standardize(seq: torch.Tensor, means: list[float],
                stds: list[float]) -> torch.Tensor:
    """Standardize the unbounded leading features with training stats."""
    out = seq.clone()
    m = torch.tensor(means, dtype=torch.float32)
    s = torch.clamp(torch.tensor(stds, dtype=torch.float32), min=1e-8)
    out[:, :NUM_STANDARDIZED] = (out[:, :NUM_STANDARDIZED] - m) / s
    return out


def batch_sequences(
    seqs: list[torch.Tensor],
) -> tuple[torch.Tensor, torch.Tensor]:
    """Zero-pad to the longest sequence: x (B, T, 8) and lengths (B,)."""
    lengths = torch.tensor([len(s) for s in seqs], dtype=torch.long)
    return pad_sequence(seqs, batch_first=True), lengths


def sequence_errors(x: torch.Tensor, recon: torch.Tensor,
                    lengths: torch.Tensor) -> torch.Tensor:
    """Mean squared error per sequence over its real steps only: (B,)."""
    steps = torch.arange(x.size(1), device=x.device)
    mask = (steps[None, :] < lengths[:, None].to(x.device)).float()
    step_err = ((x - recon) ** 2).mean(dim=2)
    return (step_err * mask).sum(dim=1) / lengths.to(x.device).float()


class FlowLSTMAutoencoder(nn.Module):
    """Encoder LSTM reads a packet sequence into a fixed-size state; the
    decoder LSTM rebuilds the sequence from that state alone."""

    def __init__(self, input_size: int = NUM_STEP_FEATURES,
                 hidden_size: int = DEFAULT_HIDDEN_SIZE,
                 num_layers: int = DEFAULT_NUM_LAYERS):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.encoder = nn.LSTM(input_size=input_size, hidden_size=hidden_size,
                               num_layers=num_layers, batch_first=True)
        # The decoder is driven only by the encoder state; its input is zeros.
        self.decoder = nn.LSTM(input_size=1, hidden_size=hidden_size,
                               num_layers=num_layers, batch_first=True)
        self.output_layer = nn.Linear(hidden_size, input_size)

    def forward(self, x: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        """x: (B, T, input_size), lengths: (B,). Returns (B, T, input_size)."""
        packed = pack_padded_sequence(x, lengths.cpu(), batch_first=True,
                                      enforce_sorted=False)
        _, (hidden, cell) = self.encoder(packed)
        batch_size, seq_len, _ = x.shape
        decoder_input = torch.zeros(batch_size, seq_len, 1, device=x.device)
        decoder_output, _ = self.decoder(decoder_input, (hidden, cell))
        return self.output_layer(decoder_output)


def load_checkpoint(path: str | Path | None = None) -> dict:
    """Load a format 2 checkpoint, or raise ModelNotTrainedError."""
    path = Path(path or config.LSTM_MODEL_PATH)
    if not path.exists():
        raise ModelNotTrainedError(NO_MODEL_MESSAGE)
    try:
        checkpoint = torch.load(path, map_location="cpu", weights_only=True)
    except Exception as e:
        raise ModelNotTrainedError(
            f"{NO_MODEL_MESSAGE} (could not read {path}: {e})"
        ) from e
    if (not isinstance(checkpoint, dict)
            or checkpoint.get("format_version") != CHECKPOINT_FORMAT_VERSION):
        raise ModelNotTrainedError(NO_MODEL_MESSAGE)
    return checkpoint


def model_status(path: str | Path | None = None) -> str | None:
    """None when a usable model exists, else the message explaining why not."""
    try:
        load_checkpoint(path)
    except ModelNotTrainedError as e:
        return str(e)
    return None


class LstmDetector:
    """Flags flows whose packet sequence the autoencoder reconstructs poorly.

    Satisfies the Detector Protocol: flag(flows) -> list[FlaggedFlow].
    """

    def __init__(self, model_path: str | Path | None = None,
                 threshold: float | None = None):
        checkpoint = load_checkpoint(model_path)
        self.model = FlowLSTMAutoencoder(
            hidden_size=checkpoint["hidden_size"],
            num_layers=checkpoint["num_layers"],
        )
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()
        self.max_seq_len = checkpoint["max_seq_len"]
        self.feature_means = checkpoint["feature_means"]
        self.feature_stds = checkpoint["feature_stds"]
        self.threshold = (
            threshold if threshold is not None else checkpoint["threshold"]
        )

    def score(self, flows: list[FlowRecord]) -> list[float]:
        """Reconstruction error per flow. Every flow must have packets."""
        seqs = [
            standardize(encode_flow(f, self.max_seq_len),
                        self.feature_means, self.feature_stds)
            for f in flows
        ]
        scores: list[float] = []
        batch_size = config.LSTM_SCORE_BATCH_SIZE
        for start in range(0, len(seqs), batch_size):
            x, lengths = batch_sequences(seqs[start:start + batch_size])
            with torch.no_grad():
                recon = self.model(x, lengths)
            scores.extend(sequence_errors(x, recon, lengths).tolist())
        return scores

    def flag(self, flows: list[FlowRecord]) -> list[FlaggedFlow]:
        # Flows assembled without packets (e.g. hand-built ones) cannot be scored
        scorable = [f for f in flows if f.packets]
        flagged = []
        for flow, score in zip(scorable, self.score(scorable)):
            if score > self.threshold:
                flagged.append(
                    FlaggedFlow(
                        flow=flow,
                        anomaly_score=min(1.0, score / (score + self.threshold)),
                        reason=f"LSTM sequence anomaly score {score:.4f} "
                               f"(threshold {self.threshold:.4f})",
                    )
                )
        return flagged
```

Note: with `threshold=0.0` and `score > 0`, `score / (score + 0)` is `1.0`, which stays inside `(0, 1]`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `source venv/bin/activate && pytest tests/test_detection.py -v`
Expected: 13 passed.
`tests/test_training.py` still targets the old training script and fails until Task 3 replaces both.

- [ ] **Step 5: Commit**

```bash
git add netsentinel/detection/lstm.py tests/test_detection.py
git commit -m "Rewrite LSTM detector as a per-packet sequence autoencoder"
```

---

### Task 3: Training on captured traffic

**Files:**
- Rewrite: `scripts/train_lstm.py`
- Rewrite: `tests/test_training.py`
- Delete: `scripts/generate_training_pcap.py`, `data/pcaps/normal_traffic.pcap`

**Interfaces:**
- Consumes: everything Task 2 produces; `process_packets`, `PcapFileSource`, `PCAP_SUFFIXES` (Task 1); `config.TRAINING_DIR`, `config.TRAINING_EXCLUDE_PORTS`, `config.LSTM_MIN_TRAINING_FLOWS`, `config.LSTM_MAX_SEQ_LEN`.
- Produces in `scripts.train_lstm`:
  - `class TrainingDataError(RuntimeError)`
  - `find_pcaps(paths: list[str | Path]) -> list[Path]`
  - `is_excluded(flow: FlowRecord) -> bool`
  - `fit(model, train_x, train_len, val_x, val_len, epochs, batch_size, learning_rate) -> tuple[dict[str, Tensor], float]`
  - `train_model(paths: list[str | Path] | None = None, output_path: str | Path | None = None, epochs: int = 50, batch_size: int = 32, learning_rate: float = 1e-3, hidden_size: int = DEFAULT_HIDDEN_SIZE, min_flows: int | None = None) -> dict` with keys `n_files, n_flows, n_excluded, threshold, best_val_loss, output_path`

- [ ] **Step 1: Write failing training tests**

Replace `tests/test_training.py` with:

```python
"""Tests for LSTM training on captured traffic."""

from __future__ import annotations

import copy
import statistics
import sys
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.detection.lstm import (
    CHECKPOINT_FORMAT_VERSION,
    FlowLSTMAutoencoder,
    LstmDetector,
    batch_sequences,
)
from netsentinel.ingestion.sources import PcapFileSource, process_packets
from scripts.train_lstm import TrainingDataError, find_pcaps, fit, train_model
from tests.traffic import exfil_burst, normal_traffic, port_scan, write_pcap


def _random_batch(n: int, seed: int = 0):
    gen = torch.Generator().manual_seed(seed)
    seqs = [torch.randn(int(torch.randint(1, 10, (1,), generator=gen)), 8,
                        generator=gen) for _ in range(n)]
    return batch_sequences(seqs)


class TestFit:
    def test_best_state_is_detached_from_live_weights(self):
        torch.manual_seed(0)
        model = FlowLSTMAutoencoder(hidden_size=8)
        x, lengths = _random_batch(40)

        best_state, _ = fit(model, x[:32], lengths[:32], x[32:], lengths[32:],
                            epochs=2, batch_size=8, learning_rate=1e-2)
        snapshot = copy.deepcopy(best_state)
        with torch.no_grad():
            for param in model.parameters():
                param.add_(1.0)

        for name, tensor in best_state.items():
            assert torch.equal(tensor, snapshot[name]), name


class TestFindPcaps:
    def test_mixes_files_and_directories_and_skips_other_files(self, tmp_path):
        d = tmp_path / "windows"
        d.mkdir()
        (d / "a.pcapng").write_bytes(b"")
        (d / "b.pcap").write_bytes(b"")
        (d / "notes.txt").write_bytes(b"")
        single = tmp_path / "c.pcap"
        single.write_bytes(b"")

        found = find_pcaps([d, single, tmp_path / "missing.pcap"])

        assert [p.name for p in found] == ["a.pcapng", "b.pcap", "c.pcap"]


class TestTrainModel:
    def test_no_pcaps_explains_how_to_collect(self, tmp_path):
        with pytest.raises(TrainingDataError, match="Save windows for training"):
            train_model([tmp_path], output_path=tmp_path / "m.pt")

    def test_too_few_flows_is_refused(self, tmp_path):
        write_pcap(tmp_path / "w.pcap", normal_traffic(20, seed=1))
        with pytest.raises(TrainingDataError, match="at least 500"):
            train_model([tmp_path], output_path=tmp_path / "m.pt")

    def test_excluded_ports_are_not_learned(self, tmp_path):
        write_pcap(tmp_path / "w.pcap",
                   normal_traffic(60, seed=2) + port_scan(2_000_000.0, range(4440, 4450)))
        summary = train_model([tmp_path], output_path=tmp_path / "m.pt",
                              epochs=1, min_flows=10)
        assert summary["n_excluded"] == 1  # port 4444
        assert summary["n_flows"] == 60 + 9

    def test_checkpoint_round_trip(self, tmp_path):
        torch.manual_seed(0)
        write_pcap(tmp_path / "w.pcap", normal_traffic(80, seed=3))
        model_path = tmp_path / "m.pt"

        summary = train_model([tmp_path], output_path=model_path, epochs=2,
                              batch_size=16, hidden_size=8, min_flows=10)

        checkpoint = torch.load(model_path, weights_only=True)
        assert checkpoint["format_version"] == CHECKPOINT_FORMAT_VERSION
        assert checkpoint["max_seq_len"] == 32
        detector = LstmDetector(model_path=model_path)
        assert detector.model.hidden_size == 8
        assert detector.threshold == pytest.approx(summary["threshold"])

    def test_anomalies_score_higher_than_unseen_normal_traffic(self, tmp_path):
        torch.manual_seed(0)
        train_dir = tmp_path / "train"
        train_dir.mkdir()
        write_pcap(train_dir / "w.pcap", normal_traffic(400, seed=4))
        model_path = tmp_path / "m.pt"
        train_model([train_dir], output_path=model_path, epochs=30,
                    batch_size=32, min_flows=100)

        held_out = tmp_path / "held_out.pcap"
        write_pcap(held_out, normal_traffic(100, seed=99))
        attacks = tmp_path / "attacks.pcap"
        write_pcap(attacks, port_scan(3_000_000.0, range(20, 60)) +
                   exfil_burst(3_000_100.0))

        detector = LstmDetector(model_path=model_path)
        normal = detector.score(process_packets(PcapFileSource(str(held_out))))
        anomalous = detector.score(process_packets(PcapFileSource(str(attacks))))

        assert statistics.median(anomalous) > 2 * statistics.median(normal)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source venv/bin/activate && pytest tests/test_training.py -v`
Expected: FAIL with `ImportError: cannot import name 'TrainingDataError'`.

- [ ] **Step 3: Rewrite the training script**

Replace `scripts/train_lstm.py` with:

```python
"""Train the sequence LSTM autoencoder on captured normal traffic.

By default trains on every pcap in data/training/, which the dashboard's
'Save windows for training' toggle fills during live capture.
"""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import torch
from torch.utils.data import DataLoader, TensorDataset

import config
from netsentinel.detection.lstm import (
    CHECKPOINT_FORMAT_VERSION,
    DEFAULT_HIDDEN_SIZE,
    NUM_STANDARDIZED,
    FlowLSTMAutoencoder,
    batch_sequences,
    encode_flow,
    sequence_errors,
    standardize,
)
from netsentinel.ingestion.flows import FlowRecord
from netsentinel.ingestion.sources import PCAP_SUFFIXES, PcapFileSource, process_packets

COLLECT_HINT = (
    "Start a live capture in the dashboard with 'Save windows for training' "
    f"turned on to collect normal traffic into {config.TRAINING_DIR}."
)


class TrainingDataError(RuntimeError):
    """The training data is missing or too small to train on."""


def find_pcaps(paths: list[str | Path]) -> list[Path]:
    """Expand files and directories into pcap files, in a stable order."""
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found.extend(sorted(
                p for p in path.iterdir()
                if p.is_file() and p.suffix.lower() in PCAP_SUFFIXES
            ))
        elif path.is_file() and path.suffix.lower() in PCAP_SUFFIXES:
            found.append(path)
    return found


def is_excluded(flow: FlowRecord) -> bool:
    """Flows that must never be learned as normal traffic."""
    return (flow.src_port in config.TRAINING_EXCLUDE_PORTS
            or flow.dst_port in config.TRAINING_EXCLUDE_PORTS)


def fit(
    model: FlowLSTMAutoencoder,
    train_x: torch.Tensor,
    train_len: torch.Tensor,
    val_x: torch.Tensor,
    val_len: torch.Tensor,
    epochs: int,
    batch_size: int,
    learning_rate: float,
) -> tuple[dict[str, torch.Tensor], float]:
    """Train the autoencoder and return (best_state, best_val_loss).

    best_state is a detached copy: state_dict() returns references to the
    live parameters, which later optimizer steps would silently overwrite.
    """
    loader = DataLoader(TensorDataset(train_x, train_len),
                        batch_size=batch_size, shuffle=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)

    best_val_loss = float("inf")
    best_state = None
    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        for batch_x, batch_len in loader:
            optimizer.zero_grad()
            loss = sequence_errors(batch_x, model(batch_x, batch_len), batch_len).mean()
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch_x.size(0)
        train_loss /= len(train_x)

        model.eval()
        with torch.no_grad():
            val_loss = sequence_errors(val_x, model(val_x, val_len), val_len).mean().item()

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = copy.deepcopy(model.state_dict())

        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"    Epoch {epoch + 1:3d}/{epochs}: "
                  f"train_loss={train_loss:.6f}, val_loss={val_loss:.6f}")

    return best_state, best_val_loss


def train_model(
    paths: list[str | Path] | None = None,
    output_path: str | Path | None = None,
    epochs: int = 50,
    batch_size: int = 32,
    learning_rate: float = 1e-3,
    hidden_size: int = DEFAULT_HIDDEN_SIZE,
    min_flows: int | None = None,
) -> dict:
    """Train on every flow in the given pcaps and save a checkpoint."""
    paths = paths if paths else [config.TRAINING_DIR]
    output_path = Path(output_path or config.LSTM_MODEL_PATH)
    min_flows = config.LSTM_MIN_TRAINING_FLOWS if min_flows is None else min_flows
    max_len = config.LSTM_MAX_SEQ_LEN

    pcaps = find_pcaps(paths)
    if not pcaps:
        raise TrainingDataError(f"No pcap files found in {', '.join(map(str, paths))}. {COLLECT_HINT}")

    print(f"[*] Reading {len(pcaps)} pcap file(s)...")
    flows: list[FlowRecord] = []
    n_excluded = 0
    for pcap in pcaps:
        for flow in process_packets(PcapFileSource(str(pcap))):
            if is_excluded(flow):
                n_excluded += 1
            else:
                flows.append(flow)
    print(f"[*] {len(flows)} flows kept, {n_excluded} excluded")

    if len(flows) < min_flows:
        raise TrainingDataError(
            f"Found {len(flows)} usable flows; training needs at least {min_flows}. "
            f"Collect more traffic. {COLLECT_HINT}"
        )

    raw = [encode_flow(f, max_len) for f in flows]
    steps = torch.cat(raw)[:, :NUM_STANDARDIZED]
    feature_means = steps.mean(dim=0).tolist()
    feature_stds = steps.std(dim=0).tolist()
    x, lengths = batch_sequences(
        [standardize(s, feature_means, feature_stds) for s in raw]
    )

    order = torch.randperm(len(x))
    x, lengths = x[order], lengths[order]
    n_train = int(0.9 * len(x))
    train_x, train_len = x[:n_train], lengths[:n_train]
    val_x, val_len = x[n_train:], lengths[n_train:]

    model = FlowLSTMAutoencoder(hidden_size=hidden_size)
    print(f"[*] Training ({n_train} train, {len(x) - n_train} val, "
          f"{epochs} epochs, batch {batch_size}, lr {learning_rate})...")
    best_state, best_val_loss = fit(model, train_x, train_len, val_x, val_len,
                                    epochs, batch_size, learning_rate)

    # Threshold: mean + 3 standard deviations of training-set errors
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        errors = sequence_errors(train_x, model(train_x, train_len), train_len)
    threshold = (errors.mean() + 3 * errors.std()).item()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "format_version": CHECKPOINT_FORMAT_VERSION,
            "model_state_dict": best_state,
            "hidden_size": model.hidden_size,
            "num_layers": model.num_layers,
            "max_seq_len": max_len,
            "feature_means": feature_means,
            "feature_stds": feature_stds,
            "threshold": threshold,
            "best_val_loss": best_val_loss,
            "epochs": epochs,
            "training_files": [p.name for p in pcaps],
            "n_flows": len(flows),
            "n_excluded": n_excluded,
        },
        str(output_path),
    )
    print(f"[*] Saved {output_path} (threshold {threshold:.6f}, "
          f"best val loss {best_val_loss:.6f})")

    return {
        "n_files": len(pcaps),
        "n_flows": len(flows),
        "n_excluded": n_excluded,
        "threshold": threshold,
        "best_val_loss": best_val_loss,
        "output_path": str(output_path),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Train the sequence LSTM detector on captured normal traffic"
    )
    parser.add_argument(
        "paths", nargs="*",
        help=f"pcap files or directories (default: {config.TRAINING_DIR})",
    )
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--hidden-size", type=int, default=DEFAULT_HIDDEN_SIZE)
    parser.add_argument("--output", default=None, help="Model output path")
    args = parser.parse_args()

    try:
        train_model(
            paths=args.paths,
            output_path=args.output,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
            hidden_size=args.hidden_size,
        )
    except TrainingDataError as e:
        print(f"[!] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Delete the synthetic generator and its output**

```bash
git rm scripts/generate_training_pcap.py
rm -f data/pcaps/normal_traffic.pcap
```

In `.gitignore`, replace the line `data/pcaps/normal_traffic.pcap` with `data/training/`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `source venv/bin/activate && pytest tests/test_training.py -v`
Expected: 7 passed.
If `test_anomalies_score_higher_than_unseen_normal_traffic` fails, do not loosen the assertion. Print both score lists, find out why the model does not separate them (features, standardization, masking), and fix the cause.

- [ ] **Step 6: Commit**

```bash
git add scripts/train_lstm.py tests/test_training.py .gitignore
git commit -m "Train the sequence LSTM on captured traffic with an exclusion filter"
```

---

### Task 4: LSTM as the only detector (backend and CLI)

**Files:**
- Delete: `netsentinel/detection/stub.py`
- Modify: `netsentinel/detection/__init__.py`, `netsentinel/cli.py`, `api/models.py`, `api/jobs.py`, `api/main.py`, `scripts/watch_and_run.sh`
- Modify: `tests/test_api.py`, `tests/test_scheduler.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `LstmDetector`, `ModelNotTrainedError`, `model_status` (Task 2).
- Produces: `api.jobs._load_detector() -> LstmDetector` (no arguments); `JobStore.create(pcap_path: str, pcap_name: str) -> Job`; `Job` without `detector`; `RunSummary`/`RunRequest` without `detector`; `GET /health -> {"status": "ok", "model_ready": bool, "model_message": str | None}`; `POST /runs` returns 409 with the no-model message when `lstm.model_status()` is not None.
- API code calls `lstm.model_status()` through the module (`from netsentinel.detection import lstm`) so tests can monkeypatch `netsentinel.detection.lstm.model_status`.

- [ ] **Step 1: Write failing API and CLI tests**

In `tests/test_api.py`:

Replace every `store.create(f"/p{i}", f"p{i}", "stub")` with `store.create(f"/p{i}", f"p{i}")`, `store.create("/p3", "p3", "stub")` with `store.create("/p3", "p3")`, and remove `detector="stub"` from the `Job(...)` in `test_failed_ingest_still_signals_ingested`.

Add after the `pcap_dir` fixture:

```python
@pytest.fixture
def model_ready(monkeypatch):
    monkeypatch.setattr("netsentinel.detection.lstm.model_status", lambda path=None: None)


@pytest.fixture
def no_model(monkeypatch):
    from netsentinel.detection.lstm import NO_MODEL_MESSAGE
    monkeypatch.setattr("netsentinel.detection.lstm.model_status",
                        lambda path=None: NO_MODEL_MESSAGE)
    return NO_MODEL_MESSAGE


class TestModelReadiness:
    def test_health_reports_missing_model(self, no_model):
        body = TestClient(app).get("/health").json()
        assert body == {"status": "ok", "model_ready": False, "model_message": no_model}

    def test_health_reports_ready_model(self, model_ready):
        body = TestClient(app).get("/health").json()
        assert body == {"status": "ok", "model_ready": True, "model_message": None}

    def test_run_without_model_is_refused(self, no_model, pcap_dir):
        (pcap_dir / "x.pcap").write_bytes(b"")
        res = TestClient(app).post("/runs", json={"pcap_name": "x.pcap"})
        assert res.status_code == 409
        assert res.json()["detail"] == no_model
```

In `tests/test_scheduler.py::TestRunPipelineOrdering::test_reports_follow_flagged_order`, change the monkeypatch to `monkeypatch.setattr("api.jobs._load_detector", lambda: FlagAll())` and remove `detector="stub"` from the `Job(...)` call.

Create `tests/test_cli.py`:

```python
"""Tests for the CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from netsentinel import cli


def test_missing_model_exits_with_instructions(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "LSTM_MODEL_PATH", tmp_path / "missing.pt")
    monkeypatch.setattr(sys, "argv", ["netsentinel", str(tmp_path / "any.pcap")])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    assert "python scripts/train_lstm.py" in capsys.readouterr().out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source venv/bin/activate && pytest tests/test_api.py tests/test_scheduler.py tests/test_cli.py -v`
Expected: FAIL (`TypeError` on `store.create` arity / `_load_detector` arity, `/health` body mismatch, CLI `--detector` default still referencing removed `config.DETECTOR_TYPE`).

- [ ] **Step 3: Remove the stub detector**

```bash
git rm netsentinel/detection/stub.py
```

Replace `netsentinel/detection/__init__.py` with:

```python
from netsentinel.detection.base import Detector, FlaggedFlow

__all__ = ["Detector", "FlaggedFlow"]

# LstmDetector is imported lazily to avoid torch import at startup
```

In `config.py`, delete the `# Detection` block (`DETECTOR_TYPE`), `LSTM_ANOMALY_THRESHOLD`, and the `# StubDetector thresholds` block with its three `STUB_*` settings.

- [ ] **Step 4: Update the CLI**

In `netsentinel/cli.py`: delete `import config`, the `StubDetector` import, the `DETECTORS` dict, and the `--detector` argument. Add `from netsentinel.detection.lstm import LstmDetector, ModelNotTrainedError`. Load the detector before ingesting so a missing model fails fast:

```python
    args = parser.parse_args()

    try:
        detector = LstmDetector()
    except ModelNotTrainedError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"[*] Loading PCAP: {args.pcap}")
```

and replace the old `detector_cls = ...; detector = detector_cls()` lines with nothing (keep `flagged = detector.flag(flows)`).

- [ ] **Step 5: Update API models**

In `api/models.py`: delete `detector: Literal["stub", "lstm"] = "stub"` from `RunRequest`, `detector: str` from `RunSummary`, `detector: Literal["stub", "lstm"] = "lstm"` from `CaptureStartRequest`, and `detector: str = "lstm"` from `CaptureStatus`. Add:

```python
class HealthStatus(BaseModel):
    status: Literal["ok"] = "ok"
    model_ready: bool
    model_message: str | None = None
```

- [ ] **Step 6: Update jobs**

In `api/jobs.py`: replace `_load_detector` with

```python
def _load_detector():
    from netsentinel.detection.lstm import LstmDetector
    return LstmDetector()
```

Remove the `detector: str` field from `Job`, `detector=self.detector,` from `to_summary`, and the `detector` parameter and argument from `JobStore.create`. In `run_pipeline`, call `_load_detector()`.

- [ ] **Step 7: Update the API routes**

In `api/main.py`: add `HealthStatus` to the `api.models` imports and `from netsentinel.detection import lstm`.

Replace `health` with:

```python
@app.get("/health", response_model=HealthStatus)
def health() -> HealthStatus:
    message = lstm.model_status()
    return HealthStatus(model_ready=message is None, model_message=message)
```

In `create_run`, after the `pcap_name`/`pcap_path` validation and before resolving paths, add:

```python
    message = lstm.model_status()
    if message is not None:
        raise HTTPException(409, message)
```

and change the `store.create(...)` call to `store.create(pcap_path=str(path), pcap_name=pcap_name)`.

In `capture_start`, remove `detector=req.detector,` (Task 5 adds the new argument).

In `api/capture.py`, remove the `detector` parameter from `start`, the `self.detector` field and its assignment, `detector=self.detector,` in `_submit_rotations`, and `"detector": self.detector,` in `snapshot`. In `tests/test_api.py`, change every `mgr.start(iface=..., duration=60, files=10, detector="stub")` to drop the `detector` argument.

- [ ] **Step 8: Update the watch script**

In `scripts/watch_and_run.sh`: delete the `DETECTOR` lines in the header comment (both the variable description and the `DETECTOR=stub` usage example), the `DETECTOR="${DETECTOR:-lstm}"` line, `detector: $DETECTOR` from the echo, and change the curl body to `-d "{\"pcap_name\":\"${name}\"}"`.

- [ ] **Step 9: Run the whole Python suite**

Run: `source venv/bin/activate && pytest tests/ -v`
Expected: all pass. Grep for leftovers: `grep -rn -i "stub\|DETECTOR_TYPE\|STUB_\|LSTM_ANOMALY_THRESHOLD" --include="*.py" --include="*.sh" . | grep -v venv` returns nothing except unrelated test helpers named `stubFetch` in `web/`.

- [ ] **Step 10: Commit**

```bash
git add -A config.py netsentinel api scripts tests
git commit -m "Make the LSTM the only detector and refuse runs without a model"
```

---

### Task 5: Save capture windows for training (backend)

**Files:**
- Modify: `api/capture.py`, `api/models.py`, `api/main.py`
- Modify: `tests/test_api.py`

**Interfaces:**
- Consumes: `lstm.model_status`, `ModelNotTrainedError` (Task 2); `config.TRAINING_DIR`.
- Produces: `CaptureManager.start(iface: str, duration: int, files: int, save_for_training: bool = False) -> None` raising `ModelNotTrainedError` when no model and `save_for_training` is False; snapshot keys `save_for_training: bool`, `training_files_saved: int`, `analysis_enabled: bool`; `CaptureStartRequest.save_for_training: bool = False`; `POST /capture/start` returns 409 on `ModelNotTrainedError`.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_api.py`:

```python
@pytest.fixture
def training_dir(tmp_path, monkeypatch):
    d = tmp_path / "training"
    monkeypatch.setattr(config, "TRAINING_DIR", d)
    return d


class TestTrainingCapture:
    def _finish(self, mgr, submitted):
        mgr.stop()
        for job in submitted:
            job.ingested.set()
        if mgr._cleanup_thread is not None:
            mgr._cleanup_thread.join(timeout=5)

    def test_saved_windows_survive_cleanup(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10, save_for_training=True)
        assert _wait_for(lambda: len(list(pcap_dir.glob("live_*.pcapng"))) == 2)
        self._finish(mgr, fake_dumpcap)

        assert list(pcap_dir.glob("live_*.pcapng")) == []
        assert sorted(p.name for p in training_dir.iterdir()) == [
            "live_00001_20261013000000.pcapng", "live_00002_20261013000000.pcapng"]
        snap = mgr.snapshot()
        assert snap["training_files_saved"] == 2
        assert snap["save_for_training"] is True
        assert len(fake_dumpcap) == 2  # analysis still ran

    def test_toggle_off_saves_nothing(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10)
        assert _wait_for(lambda: len(list(pcap_dir.glob("live_*.pcapng"))) == 2)
        self._finish(mgr, fake_dumpcap)
        assert not training_dir.exists() or list(training_dir.iterdir()) == []

    def test_no_model_collects_without_analysis(
        self, fake_dumpcap, pcap_dir, training_dir, no_model
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10, save_for_training=True)
        assert mgr.snapshot()["analysis_enabled"] is False
        assert _wait_for(lambda: len(list(pcap_dir.glob("live_*.pcapng"))) == 2)
        self._finish(mgr, fake_dumpcap)

        assert fake_dumpcap == []
        assert len(list(training_dir.iterdir())) == 2
        assert mgr.snapshot()["runs_triggered"] == 0

    def test_no_model_without_toggle_is_refused(self, fake_dumpcap, no_model):
        res = TestClient(app).post("/capture/start", json={"iface": "en0"})
        assert res.status_code == 409
        assert res.json()["detail"] == no_model

    def test_already_saved_window_is_not_saved_twice(
        self, fake_dumpcap, pcap_dir, training_dir, model_ready
    ):
        mgr = CaptureManager()
        mgr.start(iface="en0", duration=60, files=10, save_for_training=True)
        assert _wait_for(lambda: len(list(pcap_dir.glob("live_*.pcapng"))) == 2)
        # The watcher saw the closed window; stop rescans every file.
        assert _wait_for(lambda: mgr.snapshot()["training_files_saved"] == 1)
        self._finish(mgr, fake_dumpcap)
        assert mgr.snapshot()["training_files_saved"] == 2
```

Add `model_ready` to the existing `TestCaptureManager` tests that call `mgr.start(...)` successfully (`test_capture_progresses_despite_heavy_stderr`, `test_stop_analyzes_final_window_and_waits_for_ingest`, `test_startup_failure_reports_dumpcap_error`) by adding it to their parameter lists.

- [ ] **Step 2: Run tests to verify they fail**

Run: `source venv/bin/activate && pytest tests/test_api.py -v -k "Training or Capture"`
Expected: FAIL with `TypeError: start() got an unexpected keyword argument 'save_for_training'`.

- [ ] **Step 3: Implement the toggle in the capture manager**

In `api/capture.py`:

Add `import os` to the imports and `from netsentinel.detection import lstm` after `from api.jobs import ...`. Update the module docstring's first paragraph to end with: "Finished windows can also be saved to config.TRAINING_DIR for LSTM training; without a trained model, a capture can only collect training data."

In `__init__`, replace the job-tracking line with:

```python
        # Rotation files already handled this session, and the job analyzing
        # each one (only when analysis is enabled)
        self._seen_files: set[str] = set()
        self._jobs_by_file: dict[str, Job] = {}
```

and add to the public state:

```python
        self.save_for_training: bool = False
        self.analysis_enabled: bool = True
        self.training_files_saved: int = 0
```

Change the signature to `def start(self, iface: str, duration: int, files: int, save_for_training: bool = False) -> None:` and, right after the "already running" check, add:

```python
            analysis_enabled = lstm.model_status() is None
            if not analysis_enabled and not save_for_training:
                raise lstm.ModelNotTrainedError(lstm.NO_MODEL_MESSAGE)
```

In the block that sets state after a successful launch, add:

```python
            self.save_for_training = save_for_training
            self.analysis_enabled = analysis_enabled
            self.training_files_saved = 0
            self._seen_files = set()
```

Replace `_submit_rotations` with:

```python
    def _submit_rotations(self, include_current: bool) -> None:
        """Handle each rotation file once: save it for training and/or
        start a job analyzing it.

        While dumpcap runs, the newest file is still being written, so it is
        skipped unless include_current is set (after dumpcap has exited).
        """
        files = sorted(config.PCAP_DIR.glob(f"{CAPTURE_PREFIX}_*.pcapng"))
        if not include_current:
            files = files[:-1]
        for path in files:
            if path.name in self._seen_files:
                continue
            self._seen_files.add(path.name)
            self.last_file = path.name
            if self.save_for_training:
                self._save_for_training(path)
            if self.analysis_enabled:
                job = store.create(pcap_path=str(path), pcap_name=path.name)
                start_job_in_background(job)
                self._jobs_by_file[path.name] = job
                self.runs_triggered += 1

    def _save_for_training(self, path: Path) -> None:
        """Keep a training copy that outlives the ring buffer and cleanup.

        A hard link costs no time or space; copy when linking is impossible
        (e.g. the training dir is on another filesystem).
        """
        config.TRAINING_DIR.mkdir(parents=True, exist_ok=True)
        target = config.TRAINING_DIR / path.name
        if target.exists():
            return
        try:
            os.link(path, target)
        except OSError:
            shutil.copy2(path, target)
        self.training_files_saved += 1
```

Add to the `snapshot` dict:

```python
                "save_for_training": self.save_for_training,
                "analysis_enabled": self.analysis_enabled,
                "training_files_saved": self.training_files_saved,
```

- [ ] **Step 4: Expose it in the API**

In `api/models.py`, add `save_for_training: bool = False` to `CaptureStartRequest`, and to `CaptureStatus` add:

```python
    save_for_training: bool = False
    analysis_enabled: bool = True
    training_files_saved: int = 0
```

In `api/main.py`, update `capture_start`:

```python
@app.post("/capture/start", response_model=CaptureStatus)
def capture_start(req: CaptureStartRequest) -> CaptureStatus:
    try:
        manager.start(
            iface=req.iface,
            duration=req.duration,
            files=req.files,
            save_for_training=req.save_for_training,
        )
    except lstm.ModelNotTrainedError as e:
        raise HTTPException(409, str(e))
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    return CaptureStatus(**manager.snapshot())
```

The `ModelNotTrainedError` clause must come first because it subclasses `RuntimeError`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `source venv/bin/activate && pytest tests/ -v`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add api tests/test_api.py
git commit -m "Let live capture save finished windows for LSTM training"
```

---

### Task 6: Dashboard

**Files:**
- Modify: `web/src/api.ts`, `web/src/App.tsx`
- Modify: `web/src/components/RunControls.tsx`, `LocalBrowser.tsx`, `RunStatusPanel.tsx`, `LiveCapturePanel.tsx`
- Modify: `web/src/components/RunStatusPanel.test.tsx`
- Create: `web/src/components/LiveCapturePanel.test.tsx`

**Interfaces:**
- Consumes: `/health`, `/runs`, `/capture/*` shapes from Tasks 4 and 5.
- Produces: `api.health(): Promise<HealthStatus>`; `api.createRun(pcap_name)`; `api.createRunFromPath(pcap_path)`; components take `modelMessage: string | null`.

- [ ] **Step 1: Write a failing panel test**

Create `web/src/components/LiveCapturePanel.test.tsx`:

```tsx
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, type CaptureStatus } from "../api";
import { LiveCapturePanel } from "./LiveCapturePanel";

const status = (overrides: Partial<CaptureStatus> = {}): CaptureStatus => ({
  status: "stopped",
  error: null,
  iface: null,
  duration: 60,
  files: 10,
  started_at: null,
  runs_triggered: 0,
  last_file: null,
  files_cleaned: 0,
  dumpcap_available: true,
  save_for_training: false,
  analysis_enabled: true,
  training_files_saved: 0,
  ...overrides,
});

describe("LiveCapturePanel training switch", () => {
  beforeEach(() => {
    vi.spyOn(api, "captureStatus").mockResolvedValue(status());
  });

  afterEach(() => cleanup());

  it("sends save_for_training when the switch is on", async () => {
    const start = vi.spyOn(api, "captureStart").mockResolvedValue(
      status({ status: "running", save_for_training: true }),
    );
    render(<LiveCapturePanel modelMessage={null} onActivity={() => {}} />);
    await act(async () => {});

    fireEvent.click(screen.getByRole("switch", { name: /save windows for training/i }));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /start capture/i }));
    });

    expect(start).toHaveBeenCalledWith({
      iface: "en0", duration: 60, files: 10, save_for_training: true,
    });
  });

  it("without a model, start needs the switch on", async () => {
    render(<LiveCapturePanel modelMessage="No model" onActivity={() => {}} />);
    await act(async () => {});
    const startButton = screen.getByRole("button", { name: /start capture/i });

    expect(startButton).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("switch", { name: /save windows for training/i }));
    expect(startButton).toHaveProperty("disabled", false);
  });

  it("shows the collecting-only state and saved count", async () => {
    vi.mocked(api.captureStatus).mockResolvedValue(
      status({
        status: "running", save_for_training: true,
        analysis_enabled: false, training_files_saved: 7,
      }),
    );
    render(<LiveCapturePanel modelMessage="No model" onActivity={() => {}} />);
    await act(async () => {});

    expect(screen.getByText(/collecting training data only/i)).toBeTruthy();
    expect(screen.getByText("7")).toBeTruthy();
  });
});
```

In `web/src/components/RunStatusPanel.test.tsx`, delete the `detector: "stub",` line from the `run` fixture.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd web && npm test`
Expected: FAIL (no `switch` role, unknown `modelMessage` prop / type errors on new status fields).

- [ ] **Step 3: Update the API client**

In `web/src/api.ts`:
- Delete `detector: string;` from `RunSummary` and from `CaptureStatus`, and `detector: "stub" | "lstm";` from `CaptureStartRequest`.
- Add to `CaptureStatus`: `save_for_training: boolean;`, `analysis_enabled: boolean;`, `training_files_saved: number;`.
- Add to `CaptureStartRequest`: `save_for_training: boolean;`.
- Add:

```ts
export interface HealthStatus {
  status: "ok";
  model_ready: boolean;
  model_message: string | null;
}
```

- In `api`, add `health: () => req<HealthStatus>("/health"),` and change the run calls to:

```ts
  createRun: (pcap_name: string) =>
    req<RunSummary>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pcap_name }),
    }),
  createRunFromPath: (pcap_path: string) =>
    req<RunSummary>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pcap_path }),
    }),
```

- [ ] **Step 4: Fetch model status in the app shell**

In `web/src/App.tsx`, import `useEffect` and `api`, and add inside `App`:

```tsx
  // null = ready (or not yet known); otherwise why runs are unavailable
  const [modelMessage, setModelMessage] = useState<string | null>(null);

  useEffect(() => {
    api
      .health()
      .then((h) => setModelMessage(h.model_ready ? null : h.model_message))
      .catch(() => {
        // backend unreachable: run attempts will surface the real error
      });
  }, []);
```

Pass `modelMessage={modelMessage}` to `RunControls`, `LocalBrowser`, and `LiveCapturePanel`.

- [ ] **Step 5: Simplify RunControls**

Replace `web/src/components/RunControls.tsx` with:

```tsx
import { useState } from "react";
import { api } from "../api";

interface Props {
  pcapName: string | null;
  modelMessage: string | null;
  onRunStarted: (jobId: string) => void;
}

export function RunControls({ pcapName, modelMessage, onRunStarted }: Props) {
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const start = async () => {
    if (!pcapName) return;
    setStarting(true);
    setError(null);
    try {
      const summary = await api.createRun(pcapName);
      onRunStarted(summary.job_id);
    } catch (e) {
      setError(String(e));
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="space-y-2">
      <button
        className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 rounded px-4 py-2 text-sm font-medium"
        onClick={start}
        disabled={!pcapName || starting || !!modelMessage}
      >
        {starting ? "Starting…" : "Run pipeline"}
      </button>
      {modelMessage && <div className="text-amber-400 text-xs">{modelMessage}</div>}
      {error && <div className="text-rose-400 text-xs">{error}</div>}
    </div>
  );
}
```

- [ ] **Step 6: Update LocalBrowser and RunStatusPanel**

In `web/src/components/LocalBrowser.tsx`:
- Add `modelMessage: string | null;` to `Props` and destructure it.
- Delete the `detector` state, the whole `<div className="flex items-center gap-2">` block containing the Detector label and select, and pass only `path` to `api.createRunFromPath(path)`.
- Below the path input row, add `{modelMessage && <div className="text-amber-400 text-xs">{modelMessage}</div>}`.
- Change each per-file Run button's `disabled` to `disabled={runningPath === p.path || !!modelMessage}` and add `disabled:text-slate-500` to its class list.

In `web/src/components/RunStatusPanel.tsx` line 97, change `{detail.pcap_name} • {detail.detector}` to `{detail.pcap_name}`.

- [ ] **Step 7: Add the training switch to LiveCapturePanel**

In `web/src/components/LiveCapturePanel.tsx`:
- Change `Props` to `{ modelMessage: string | null; onActivity: () => void; }` and destructure `modelMessage`.
- Replace the `detector` state with `const [saveForTraining, setSaveForTraining] = useState(false);`.
- In `start`, call `api.captureStart({ iface, duration: 60, files: 10, save_for_training: saveForTraining })`.
- Delete the Detector label/select block and put this in its place:

```tsx
      <div className="flex items-start gap-3">
        <button
          type="button"
          role="switch"
          aria-checked={running ? status!.save_for_training : saveForTraining}
          aria-label="Save windows for training"
          onClick={() => setSaveForTraining((v) => !v)}
          disabled={running || busy}
          className={`relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-50 ${
            (running ? status!.save_for_training : saveForTraining)
              ? "bg-cyan-600"
              : "bg-slate-700"
          }`}
        >
          <span
            className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
              (running ? status!.save_for_training : saveForTraining)
                ? "translate-x-4"
                : "translate-x-0.5"
            }`}
          />
        </button>
        <div>
          <div className="text-sm text-slate-200">Save windows for training</div>
          <div className="text-xs text-slate-500">
            Keeps each finished window in data/training/
          </div>
        </div>
      </div>

      {modelMessage && !running && (
        <div className="text-amber-400 text-xs">
          No trained model yet. Turn on saving to collect training data.
        </div>
      )}
```

- Start button: `disabled={busy || !!dumpcapMissing || (!!modelMessage && !saveForTraining)}`.
- Replace the running stats grid with:

```tsx
      {running && status && (
        <div className="space-y-2 pt-1">
          {!status.analysis_enabled && (
            <div className="text-amber-400 text-xs">
              No trained model - collecting training data only
            </div>
          )}
          <div
            className="grid gap-2 text-center"
            style={{
              gridTemplateColumns: `repeat(${
                1 + Number(status.analysis_enabled) + Number(status.save_for_training)
              }, minmax(0, 1fr))`,
            }}
          >
            {status.analysis_enabled && (
              <StatTile value={String(status.runs_triggered)} label="Windows run" />
            )}
            {status.save_for_training && (
              <StatTile value={String(status.training_files_saved)} label="Saved" />
            )}
            <StatTile value={status.last_file ?? "-"} label="Last window" mono />
          </div>
        </div>
      )}
```

and add below the component:

```tsx
function StatTile({ value, label, mono = false }: { value: string; label: string; mono?: boolean }) {
  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded px-2 py-1.5 min-w-0">
      <div
        className={
          mono
            ? "text-xs font-mono text-slate-300 truncate pt-1"
            : "text-lg font-semibold text-slate-100"
        }
        title={value}
      >
        {value}
      </div>
      <div className="text-[10px] text-slate-400 uppercase tracking-wide">{label}</div>
    </div>
  );
}
```

Also replace the existing em dash in the "dumpcap not found" message with " - ".

- [ ] **Step 8: Run web checks**

Run: `cd web && npm test && npm run lint && npm run build`
Expected: all tests pass, no lint errors, build succeeds.

- [ ] **Step 9: Commit**

```bash
git add web/src
git commit -m "Dashboard: drop detector pickers, add training switch and model status"
```

---

### Task 7: Documentation

**Files:**
- Modify: `README.md`, `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md**

In `CLAUDE.md`:
- Architecture item 2 becomes: `**Detection** (`netsentinel/detection/`) - `Detector` Protocol implemented by `LstmDetector`, an LSTM autoencoder over per-packet sequences (first 32 packets of each bidirectional flow); outputs `FlaggedFlow``.
- Under Key Design Decisions add: `- **Detector training data:** real traffic saved by live capture's "Save windows for training" toggle into `data/training/` (gitignored). Flows on `TRAINING_EXCLUDE_PORTS` are never learned as normal.`
- Under Conventions, change the gitignore bullet to mention both `data/chroma/` and `data/training/`.
- Under Commands, replace the run line comment and add training: `python scripts/train_lstm.py  # trains on data/training/`.

- [ ] **Step 2: Update README.md**

- Replace mentions of the stub detector and the detector dropdown with the LSTM as the only detector.
- Add a "Training the detector" section: start live capture with "Save windows for training" on, use the machine normally for 1-2 hours (at least about 30 minutes to reach 500 flows), stop, run `python scripts/train_lstm.py`, reload the dashboard.
- Describe the per-packet features (size, gap, direction, TCP flags) in the design section, and that flows are bidirectional.
- Remove `generate_training_pcap.py` and `normal_traffic.pcap` from the project tree and add `data/training/`.
- One sentence per line, no em dashes.

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "Document the sequence LSTM and training data workflow"
```

---

### Task 8: End-to-end verification

This needs real traffic. Pause here and ask Justin to collect it.

- [ ] **Step 1: Start servers** (see memory `phase5_servers.md`: uvicorn on 8765, Vite on 5173). Stop any capture already running first.

- [ ] **Step 2: No-model state in the browser.** With no format 2 checkpoint, open the dashboard and confirm: the New run button is disabled with the amber message, Local browser Run buttons are disabled, Live capture Start is disabled until the switch is on. Screenshot each panel and check alignment, spacing, and wrapping at the 20rem sidebar width.

- [ ] **Step 3: Collect.** Start capture with the switch on. Confirm "collecting training data only", the Saved tile counting up, and files appearing in `data/training/`. Ask Justin to use the machine normally for at least 30 minutes (ideally 1-2 hours), then stop. Confirm `data/pcaps/live_*` is cleaned and `data/training/` keeps every window.

- [ ] **Step 4: Train.** `source venv/bin/activate && python scripts/train_lstm.py`. Record file, flow, and excluded counts and the threshold.

- [ ] **Step 5: Analyze.** Reload the dashboard. Run `sample_suspicious.pcap`; confirm its scan/attack flows are flagged and investigated. Start a fresh capture without the switch, let 2-3 windows analyze, and record the fraction of flows flagged (target: a small minority). Inspect a few flagged flows' reasons.

- [ ] **Step 6: Full checks.** `pytest tests/`, `cd web && npm test && npm run lint && npm run build`, and `python -m eval.harness` (compare to the 85% baseline).

- [ ] **Step 7: Report** results with numbers, including anything that fell short.
