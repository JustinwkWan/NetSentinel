# NetSentinel

An AI agent for network security that ingests PCAP files (or live traffic), detects anomalous network flows, and autonomously investigates each flagged flow using a ReAct-style agent loop backed by CVE and MITRE ATT&CK threat intelligence. The output is structured threat reports, viewable in a web dashboard or from the CLI.

## Architecture

```
PCAP file / live capture
   |
   v
[ Ingestion ] ---> FlowRecords (aggregated network flows)
   |
   v
[ Detection ] ---> FlaggedFlows (anomalous flows with scores)
   |
   v
[ Agent (LangGraph ReAct loop) ]
   |--- cve_lookup tool ---------> [ RAG Store (ChromaDB) ]
   |--- attack_technique_lookup -> [ RAG Store (ChromaDB) ]
   |
   v
[ Structured Threat Reports ]
   |
   +--> CLI output
   +--> FastAPI backend ---> React dashboard
```

**4 core layers:**

1. **Ingestion** - Reads PCAP/pcapng files via a source-agnostic `PacketSource` interface and groups packets into bidirectional `FlowRecord` objects: both directions of a connection form one flow, which keeps its packets in arrival order.
2. **Detection** - `LstmDetector`, an LSTM autoencoder over per-packet sequences, flags flows whose packet sequence it cannot reconstruct well. It is trained on your own normal traffic (see [Train the detector](#train-the-detector)).
3. **Agent** - LangGraph ReAct loop that investigates each flagged flow. The agent chooses which tools to call, reacts to results, and decides when to produce its report. Hard iteration cap as a guardrail.
4. **RAG** - ChromaDB vector store of CVE entries and MITRE ATT&CK techniques, chunked on natural boundaries (one CVE = one chunk, one technique = one chunk).

Plus two peer layers built on top:

- **Evaluation** (`eval/`) - LLM-as-judge harness that scores agent reports against a labeled dataset with bias mitigations (rubric scoring, anti-verbosity, swappable judge model).
- **Web app** (`api/` + `web/`) - FastAPI backend and React dashboard for running the pipeline, browsing local pcaps, and driving live capture from the browser.

## Tech Stack

- **Language:** Python (core) + TypeScript (frontend)
- **Packet handling:** scapy
- **Anomaly detection:** PyTorch (LSTM autoencoder)
- **Vector store:** ChromaDB
- **Agent orchestration:** LangGraph (ReAct loop)
- **LLM:** Anthropic Claude API (DeepSeek supported via the Anthropic-compatible endpoint)
- **Backend API:** FastAPI + Uvicorn
- **Frontend:** React + Vite + Tailwind CSS
- **Live capture:** dumpcap (Wireshark) ring buffer
- **CLI entry point:** `netsentinel/cli.py`

## Setup

### Prerequisites

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com/) (or a DeepSeek key - see Configuration)
- Node.js 18+ and npm - only for the web dashboard
- Wireshark / `dumpcap` - only for live capture

### Installation

```bash
# Clone the repository
git clone https://github.com/JustinwkWan/NetSentinel.git
cd NetSentinel

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root with your API key:

```bash
cp .env.example .env
# Edit .env and add your API key
```

```
ANTHROPIC_API_KEY=your-api-key-here
```

**Using DeepSeek (or another Anthropic-compatible provider):** set the model,
base URL, and key instead. NetSentinel talks to any Anthropic-compatible
endpoint via `langchain-anthropic`.

```
LLM_MODEL=deepseek-v4-pro
LLM_BASE_URL=https://api.deepseek.com/anthropic
DEEPSEEK_API_KEY=your-deepseek-key
```

All tunable settings (model names, retrieval `k`, agent iteration cap,
detector thresholds, paths) live in `config.py` - no magic numbers scattered
through the code.

### Build the RAG Store

Before running the pipeline, build the ChromaDB vector store with threat intelligence data:

```bash
python scripts/build_rag_store.py
```

This creates a ChromaDB collection at `data/chroma/` with CVE entries (and ATT&CK techniques in Phase 2).

## Usage

### Run the pipeline on a PCAP file

```bash
python -m netsentinel.cli <path-to-pcap>
```

The detector needs a trained model first; see [Train the detector](#train-the-detector).

Example with the included sample:

```bash
python -m netsentinel.cli data/pcaps/sample_suspicious.pcap
```

The pipeline will:
1. Parse the PCAP and assemble network flows
2. Flag flows whose packet sequence the LSTM reconstructs poorly
3. Investigate each flagged flow using the AI agent
4. Print structured threat reports

### Train the detector

The LSTM learns what normal traffic looks like on your network, so it is trained on traffic you capture yourself.

1. Start the web app (see below) and open the **Live capture** panel.
2. Turn on **Save windows for training** and start the capture.
   Each finished 60-second window is kept in `data/training/` (gitignored).
   Without a trained model the capture only collects data and skips analysis.
3. Use your machine normally for 1-2 hours.
   Training needs at least 500 flows, which usually takes about 30 minutes.
4. Stop the capture and train:

```bash
python scripts/train_lstm.py              # trains on every pcap in data/training/
python scripts/train_lstm.py path/to/dir  # or on specific pcaps or folders
```

5. Reload the dashboard; runs and live analysis are now enabled.

Retrain the same way whenever your normal traffic changes.
Flows on known-malicious ports (`TRAINING_EXCLUDE_PORTS` in `config.py`) are never learned as normal.

**What the model sees:** each flow's first 32 packets, in order.
Each packet is one step with 8 features: log size, log gap since the previous packet, direction (initiator or responder), whether it is TCP, and the SYN, FIN, RST, and PSH flags.
A flow whose sequence the autoencoder reconstructs worse than the calibrated threshold (mean + 3 standard deviations of training error) is flagged.

### Run the demo

```bash
python scripts/run_demo.py
```

### Web app (dashboard)

The web app provides a browser UI for running the pipeline and viewing reports
without parsing terminal output. It has two parts: a FastAPI backend and a
React/Vite frontend.

```bash
# Terminal 1 - backend (http://127.0.0.1:8765)
source venv/bin/activate
uvicorn api.main:app --host 127.0.0.1 --port 8765 --reload

# Terminal 2 - frontend (http://localhost:5173)
cd web
npm install      # first time only
npm run dev
```

Open http://localhost:5173. From the dashboard you can:

- **Run from `data/pcaps/`** - pick a bundled pcap from the list, or upload one.
- **Browse a local folder** - point the backend at any folder on your machine and run a pcap in place (no copy).
- **Live capture** - start/stop a rolling capture; each completed window is auto-analyzed.
- **View reports** - severity, threat type, summary, CVEs, ATT&CK techniques, and remediation per flagged flow, plus a run history.

The frontend proxies `/api/*` to the backend (see `web/vite.config.ts`).

### Live capture

Capture live traffic into a rolling pcapng ring buffer and analyze each window
as it completes. Two ways to drive it:

**From the dashboard** - use the "Live capture" panel (Start/Stop, interface,
and the "Save windows for training" switch). The backend manages `dumpcap` and
auto-runs the pipeline on each closed rotation, cleaning up the capture files
on stop. With the switch on, each window is also kept in `data/training/`.

**From the CLI** - two standalone scripts:

```bash
# Terminal A - capture 60s windows, 10-file rolling buffer (~10 min)
sudo ./scripts/live_capture.sh

# Terminal B - run the pipeline on each completed window
./scripts/watch_and_run.sh
```

> **macOS note:** packet capture needs raw-socket access. Either run with `sudo`,
> or `sudo chmod +r /dev/bpf*` once per boot. Installing Wireshark's ChmodBPF
> helper grants this automatically. Set `CAPTURE_IFACE` if `en0` isn't your
> active interface.

### Evaluation harness

Score the agent's reports against a labeled dataset using an LLM-as-judge with
bias mitigations (rubric-based scoring, anti-verbosity instruction, swappable
judge model via `EVAL_JUDGE_MODEL`).

```bash
# Run the full eval set
python -m eval.harness --save

# Run specific cases
python -m eval.harness --cases reverse_shell_4444 ssh_brute_force
```

Results print a per-case breakdown plus aggregate scores, and `--save` writes
raw results to `data/eval/eval_results.json`.

### Detector metrics

Measure the LSTM detector on its own: how often it flags normal traffic it has never seen, and how many attacks it catches.

```bash
python -m eval.detector_metrics
```

It trains a separate model on the earlier windows in `data/training/` and holds out the latest 15% (`--holdout`) as unseen normal traffic, so the production model is untouched.
Attacks are synthetic, generated by `eval/attack_traffic.py` and read back through the real ingestion path.
An attack counts as caught when any of its flows is flagged.
A synthetic benign control shows whether the detector reacts to the generator rather than to attack shapes.
Pass `--model PATH` to measure an existing checkpoint on the windows it was not trained on.
Results print as a table and save to `data/eval/detector_metrics.json`.

### Investigation performance

Flagged flows are investigated in parallel on one shared worker pool, and every LLM call goes through one shared rate limiter.
Tune them in `config.py`:

| Setting | Controls |
|---|---|
| `INVESTIGATION_MAX_CONCURRENCY` | Investigations running at once, across all runs |
| `LLM_REQUESTS_PER_SECOND`, `LLM_MAX_BURST` | How often LLM requests may start |
| `LLM_MAX_RETRIES`, `LLM_TIMEOUT_SECONDS` | Retries with backoff on 429/5xx, and per-request timeout |

Measure where the time goes (makes real LLM calls):

```bash
python scripts/benchmark_investigations.py --label before
python scripts/benchmark_investigations.py --label after
python scripts/benchmark_investigations.py --compare data/benchmarks/before-*.json data/benchmarks/after-*.json
```

### Run tests

```bash
pytest tests/
```

## Project Structure

```
NetSentinel/
├── config.py                    # Central config (model, k values, thresholds)
├── data/
│   ├── pcaps/                   # Sample + live-capture PCAP files
│   ├── training/                # Capture windows saved for LSTM training (gitignored)
│   ├── threat_intel/            # Raw CVE/ATT&CK data
│   ├── chroma/                  # ChromaDB store (gitignored, built by script)
│   └── eval/                    # Eval results (gitignored)
├── netsentinel/
│   ├── cli.py                   # CLI entry point
│   ├── ingestion/
│   │   ├── sources.py           # PacketSource interface, PcapFileSource
│   │   └── flows.py             # FlowRecord dataclass
│   ├── detection/
│   │   ├── base.py              # Detector Protocol, FlaggedFlow
│   │   └── lstm.py              # LstmDetector (per-packet sequence LSTM autoencoder)
│   ├── rag/
│   │   ├── store.py             # ChromaDB query interface
│   │   ├── chunking.py          # Natural-boundary chunkers
│   │   └── build_store.py       # Download + chunk + embed CVE/ATT&CK
│   └── agent/
│       ├── graph.py             # LangGraph ReAct graph
│       ├── state.py             # Agent state definition
│       ├── tools.py             # cve_lookup, attack_technique_lookup
│       ├── prompts.py           # System and investigation prompts
│       └── report.py            # ThreatReport dataclass
├── eval/                        # Evaluation harness (LLM-as-judge)
│   ├── dataset.py               # Labeled eval cases
│   ├── judge.py                 # Rubric-based judge with bias mitigations
│   ├── harness.py               # Runs agent + judge over the dataset
│   ├── report.py                # Aggregate scoring + summary
│   ├── detector_metrics.py      # False alarm and detection rates for the LSTM
│   └── attack_traffic.py        # Synthetic attack traffic for detector metrics
├── api/                         # FastAPI backend
│   ├── main.py                  # Routes: pcaps, runs, capture, local browse
│   ├── jobs.py                  # Background job store + pipeline orchestrator
│   ├── capture.py               # Live-capture manager (dumpcap ring buffer)
│   └── models.py                # Pydantic schemas
├── web/                         # React + Vite + Tailwind dashboard
│   └── src/
│       ├── api.ts               # Typed API client
│       └── components/          # PcapSelector, RunControls, LiveCapturePanel, …
├── scripts/
│   ├── build_rag_store.py       # Build the RAG store
│   ├── train_lstm.py            # Train the LSTM detector on data/training/
│   ├── run_demo.py              # Run the demo
│   ├── live_capture.sh          # dumpcap rolling-window capture
│   └── watch_and_run.sh         # Auto-run pipeline on each captured window
└── tests/
```

## Build Phases

- [x] **Phase 1** - Skeleton end-to-end agent (PCAP -> StubDetector -> minimal RAG -> LangGraph loop -> report)
- [x] **Phase 2** - Full RAG layer (real CVE/ATT&CK data, natural chunking, second tool)
- [x] **Phase 3** - LSTM autoencoder detector over per-packet sequences, trained on captured normal traffic
- [x] **Phase 4** - Evaluation harness with LLM-as-judge (rubric scoring + bias mitigations)
- [x] **Phase 5** - Web dashboard (FastAPI + React), live capture, and local-folder browsing

## Design Decisions

- **Retrieval:** top-k of 3-5, never 20. Chunks follow natural boundaries (one CVE = one chunk).
- **Agent loop:** Hard iteration cap as guardrail. Terminal action is an explicit "produce report" step.
- **Tools return structured, concise results** - never raw document dumps.
- **Tools fail gracefully** - return "no relevant results" message, never raise exceptions.
- **Source-agnostic ingestion** - `PacketSource` protocol allows swapping in live capture without touching downstream code.
- **Detector protocol** - the pipeline depends only on `Detector.flag()`, so a different detector can be added without touching callers.
- **Real sequences, real traffic** - the LSTM reads packets in time order (size, timing, direction, flags), not a fixed list of flow totals, and it trains on the user's own captured traffic rather than synthetic data.
- **Eval judge bias mitigations** - rubric-based scoring (not holistic preference), explicit anti-verbosity instruction, and a judge model that can differ from the agent model.
- **Live capture via ring buffer** - `dumpcap` owns rotation and retention (a rolling window of fixed-size windows); the watcher only triggers analysis on closed files. Files are cleaned up on stop.
- **Local-first web app** - backend binds to localhost and can run pcaps in place from any local folder, no upload/copy required.

See [Design.md](Design.md) for the full technical design document.
