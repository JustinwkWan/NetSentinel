# Sequence LSTM Detector - Design

Date: 2026-10-14
Status: Draft, awaiting review

## Goal

Make the LSTM detector do real sequence modeling.
Today it feeds the 7 summary statistics of one flow to the LSTM as if they were 7 time steps.
That order is arbitrary, so the recurrence models nothing temporal.
After this change, each time step is one packet of the flow, in arrival order, described by a tuple of per-packet features.

Secondary goals:

- Train on real traffic from the user's own network, collected through the dashboard.
- Make the LSTM the only detector, removing the Phase 1 stub from every user-facing surface.
- Lay the groundwork for safe periodic retraining (self-improvement) without building the scheduler yet.

## Success criteria

- The retrained model passes most flows of a held-out window of the user's own normal traffic.
- The model flags the flows in `data/pcaps/sample_suspicious.pcap`.
- The dashboard, CLI, and API work with the LSTM as the only detector.
- With no compatible model present, every surface reports a clear "train the model" message instead of a stack trace.
- `pytest tests/` and the web test suite pass, and the eval harness shows no regression against the current 85%.

## Out of scope

- Automatic or scheduled retraining.
- Filtering training data by agent verdicts or human feedback.
- Changes to `scripts/live_capture.sh` (the CLI capture path does not get the training toggle).
- Per-host flow sequences (sequences of flows over time).

## 1. Training data collection

### Dashboard

The Live capture panel gets a "Save windows for training" toggle below the interface field.
It is off by default and disabled while a capture is running.
While a capture runs with the toggle on, the panel shows a counter: "N windows saved to data/training/".

### API

`CaptureStartRequest` gains `save_for_training: bool = False`.
`CaptureStatus` gains `save_for_training: bool` and `training_files_saved: int`.

### Backend

When the capture watcher picks up a closed rotation file in `CaptureManager._submit_rotations`, and the toggle is on, it places the file into `config.TRAINING_DIR` (`data/training/`).
It uses `os.link` (a hard link: instant, no extra disk space) and falls back to `shutil.copy2` if linking fails, e.g. across filesystems.
The ring buffer and the stop cleanup only unlink the `data/pcaps/` entry, so the training copy survives.
The file is closed when the watcher sees it, and the ring keeps it for about 10 rotations, so there is no race with deletion.
Rotation names include a timestamp, so names never collide across sessions.

`data/training/` is added to `.gitignore` because it contains the user's private traffic.

### No-model behavior during capture

If no compatible model exists when a capture starts:

- With the toggle on, the capture runs, saves windows, and does not submit analysis jobs.
  `CaptureStatus` gains `analysis_enabled: bool`, and the panel shows "No trained model - collecting training data only".
- With the toggle off, `/capture/start` returns a 409 with the "train the model" message, since the capture would do nothing useful.

## 2. Ingestion: bidirectional flows with packet sequences

### Flow grouping

Both directions of a connection go into one flow.
The canonical key is the unordered pair of `(ip, port)` endpoints plus the protocol.
The endpoint that sent the first packet seen is the initiator and becomes `src_ip`/`src_port`, so `flow_key` keeps its `src:port->dst:port/proto` format.

### Data objects

New dataclass in `netsentinel/ingestion/flows.py`:

```python
@dataclass
class PacketRecord:
    timestamp: float   # epoch seconds
    length: int        # frame bytes
    direction: int     # +1 initiator -> responder, -1 responder -> initiator
    tcp_flags: int     # raw TCP flags byte; 0 for UDP and other protocols
```

`FlowRecord` gains `packets: list[PacketRecord] = field(default_factory=list)`, in arrival order.
`packet_count` and `byte_count` become totals over both directions.
All existing fields stay, so the agent prompt, API DTOs, and reports are unchanged.

### Packet parsing

`PcapFileSource._parse_packet` adds `tcp_flags` (`int(pkt[TCP].flags)`, or 0) to the packet dict.

### Known side effect

Flow counts roughly halve and per-flow totals combine both directions.
`flow_key` values for responses disappear because they merge into the initiator's flow.
Tests that assert on flow counts or keys are updated accordingly.

## 3. Model

### Per-packet features (one time step)

| # | Feature | Encoding |
|---|---|---|
| 1 | Packet size | `log1p(length)` |
| 2 | Gap since previous packet in the flow | `log1p(seconds)`, 0 for the first packet |
| 3 | Direction | +1 / -1 |
| 4 | Is TCP | 1 / 0 |
| 5-8 | SYN, FIN, RST, PSH flags | 1 / 0 each, 0 for non-TCP |

Features 1 and 2 are standardized with means and standard deviations computed on the training set and stored in the checkpoint.
Features 3-8 are already bounded and are not standardized.
ACK is omitted because nearly every TCP packet after the handshake carries it, so it adds no signal.
Most real traffic is QUIC over UDP, so size, timing, and direction carry most of the signal, and flags are a TCP-only bonus.

### Sequence shape

Each flow becomes a sequence of its first `config.LSTM_MAX_SEQ_LEN` (32) packets.
Shorter sequences are zero-padded to the longest sequence in their batch (at most 32) and carry a length.
The model uses `pack_padded_sequence`, and the reconstruction loss is masked so padded steps never count.
Input tensor shape: `(batch, longest length in batch, 8)`.
The checkpoint records the `max_seq_len` it was trained with, and the detector encodes flows with that value rather than the current config.

### Architecture

`FlowLSTMAutoencoder` keeps the encoder-decoder shape, with `input_size=8`:

- Encoder LSTM over the packed sequence, producing a final hidden and cell state.
- Decoder LSTM, initialized from the encoder state, fed zeros for `seq_len` steps.
- Linear projection from hidden size to 8 features per step.

The anomaly score of a flow is the mean squared reconstruction error over its real (unpadded) steps.

### Checkpoint

The checkpoint stores `format_version: 2`, `hidden_size`, `num_layers`, `max_seq_len`, feature means and standard deviations, `threshold`, and training metadata (training files, flow counts, excluded flow count).
`LstmDetector` refuses checkpoints without `format_version == 2` and raises `ModelNotTrainedError` with the message "No compatible LSTM model. Collect training data with the dashboard's 'Save windows for training' toggle, then run: python scripts/train_lstm.py".
A missing checkpoint raises the same error.

## 4. Training

`scripts/train_lstm.py`:

- Takes zero or more paths; each path is a pcap file or a directory searched for `*.pcap` and `*.pcapng`.
- With no paths, it uses every pcap in `config.TRAINING_DIR`.
- If no pcaps are found, it exits with instructions for collecting data with the toggle.
- Ingests each file, then drops flows whose either port is in `config.TRAINING_EXCLUDE_PORTS` (the former stub suspicious-port list).
  The stub's packet-rate and byte-rate rules are deliberately not used: legitimate video and download streams trip them, and excluding those would teach the model that streaming is abnormal.
- Requires at least `config.LSTM_MIN_TRAINING_FLOWS` (500) flows after filtering, and exits with a "collect more data" message otherwise.
- Splits 90/10 into train and validation sets, keeps the best validation state, and sets the threshold to mean + 3 standard deviations of training-set errors (unchanged method).
- Prints the number of files, flows, excluded flows, and the threshold.

`scripts/generate_training_pcap.py` is deleted.
Its synthetic flows are one-way, evenly spaced, and carry a SYN flag on every packet, so they would train the sequence model on unrealistic behavior.
Its untracked output, `data/pcaps/normal_traffic.pcap`, is deleted too, along with its `.gitignore` entry.

## 5. Removing the stub detector

The stub detector was a Phase 1 placeholder.
It is removed everywhere:

- `netsentinel/detection/stub.py` and its export in `netsentinel/detection/__init__.py`.
- `config.DETECTOR_TYPE` and the `STUB_*` settings (the port list moves to `TRAINING_EXCLUDE_PORTS`).
- The `--detector` CLI flag in `netsentinel/cli.py`.
- The `detector` field on run requests, run summaries, and capture requests and statuses in `api/models.py`, and `_load_detector` in `api/jobs.py`.
- The Detector dropdowns in `RunControls`, `LocalBrowser`, and `LiveCapturePanel`, the `detector` fields in `web/src/api.ts`, and the detector label in `RunStatusPanel`.
- The `DETECTOR` variable in `scripts/watch_and_run.sh`.
- Stub tests in `tests/test_detection.py`, and stub usage in `tests/test_api.py` and `tests/test_scheduler.py`, which switch to a small fake detector or a tiny trained model fixture.

The `Detector` Protocol stays, so a future detector can be added without touching callers.

### No-model behavior for runs

- API: creating a run when no compatible model exists returns 409 with the `ModelNotTrainedError` message.
- Dashboard: the run panels show that message in place of the Run button when `/health` (extended with `model_ready: bool` and `model_message`) reports no model.
- CLI: prints the message and exits with code 1.

## 6. Configuration

New and changed settings in `config.py`:

```python
TRAINING_DIR = DATA_DIR / "training"
LSTM_MAX_SEQ_LEN = 32
LSTM_MIN_TRAINING_FLOWS = 500
TRAINING_EXCLUDE_PORTS = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345}
LSTM_SCORE_BATCH_SIZE = 256
```

Removed: `DETECTOR_TYPE`, `STUB_SUSPICIOUS_PORTS`, `STUB_HIGH_PACKET_RATE`, `STUB_HIGH_BYTE_RATE`, and `LSTM_ANOMALY_THRESHOLD` (every format 2 checkpoint carries its own calibrated threshold).

## 7. Testing

Unit tests:

- Bidirectional grouping: request and response packets form one flow, the initiator is `src`, directions are +1 and -1.
- TCP flags are parsed; UDP packets get 0.
- Feature encoding of one known packet sequence, including the zero gap on the first packet.
- Padding and masking: a padded sequence and the same sequence unpadded get the same score.
- Checkpoint round trip: train on a tiny fixture, save, load, same scores.
- Old or missing checkpoint raises `ModelNotTrainedError`.
- Training excludes flows on excluded ports.

API tests:

- `save_for_training` places closed rotations in the training dir, and those files survive stop cleanup.
- Capture without a model: 409 with the toggle off; capture runs with analysis disabled with the toggle on.
- Run creation without a model returns 409.

End to end:

1. Start a live capture from the dashboard with the toggle on and no model, and confirm the "collecting training data only" state and saved windows.
2. Train with `python scripts/train_lstm.py` on the collected windows.
3. Run the LSTM on a held-out normal window and on `sample_suspicious.pcap` from the dashboard, and inspect flagged flows and reports.
4. Check every changed panel in the browser for layout and copy.
5. Run `pytest tests/`, the web tests, and `python -m eval.harness`.

## 8. Documentation

README and CLAUDE.md are updated: the LSTM as the only detector, the training data workflow, the new feature design, and removal of the stub and the synthetic generator.
