# NetSentinel

An AI agent for network security that ingests PCAP files, detects anomalous network flows, and autonomously investigates each flagged flow using a ReAct-style agent loop backed by CVE and MITRE ATT&CK threat intelligence. The output is structured threat reports.

## Architecture

```
PCAP file
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
```

**4 layers:**

1. **Ingestion** - Reads PCAP files via a source-agnostic `PacketSource` interface, aggregates packets into `FlowRecord` objects with derived features (packet rate, mean packet size).
2. **Detection** - Flags anomalous flows using a `Detector` protocol. Currently uses `StubDetector` (rule-based); LSTM detector planned for Phase 3.
3. **Agent** - LangGraph ReAct loop that investigates each flagged flow. The agent chooses which tools to call, reacts to results, and decides when to produce its report. Hard iteration cap as a guardrail.
4. **RAG** - ChromaDB vector store of CVE entries and MITRE ATT&CK techniques, chunked on natural boundaries (one CVE = one chunk, one technique = one chunk).

## Tech Stack

- **Language:** Python
- **Packet handling:** scapy
- **Anomaly detection:** PyTorch (LSTM, Phase 3)
- **Vector store:** ChromaDB
- **Agent orchestration:** LangGraph (ReAct loop)
- **LLM:** Anthropic Claude API
- **CLI entry point:** `netsentinel/cli.py`

## Setup

### Prerequisites

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com/)

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

Create a `.env` file in the project root with your Anthropic API key:

```bash
cp .env.example .env
# Edit .env and add your API key
```

```
ANTHROPIC_API_KEY=your-api-key-here
```

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

Example with the included sample:

```bash
python -m netsentinel.cli data/pcaps/sample_suspicious.pcap
```

The pipeline will:
1. Parse the PCAP and assemble network flows
2. Flag suspicious flows (suspicious ports, high packet rates)
3. Investigate each flagged flow using the AI agent
4. Print structured threat reports

### Run the demo

```bash
python scripts/run_demo.py
```

### Run tests

```bash
pytest tests/
```

## Project Structure

```
netsentinel/
├── config.py                    # Central config (model, k values, thresholds)
├── data/
│   ├── pcaps/                   # Sample PCAP files
│   ├── threat_intel/            # Raw CVE/ATT&CK data
│   └── chroma/                  # ChromaDB store (gitignored, built by script)
├── netsentinel/
│   ├── ingestion/
│   │   ├── sources.py           # PacketSource interface, PcapFileSource
│   │   └── flows.py             # FlowRecord dataclass
│   ├── detection/
│   │   ├── base.py              # Detector Protocol, FlaggedFlow
│   │   └── stub.py              # StubDetector (rule-based)
│   ├── rag/
│   │   └── store.py             # ChromaDB query interface
│   └── agent/
│       ├── graph.py             # LangGraph ReAct graph
│       ├── state.py             # Agent state definition
│       ├── tools.py             # cve_lookup, attack_technique_lookup
│       ├── prompts.py           # System and investigation prompts
│       └── report.py            # ThreatReport dataclass
├── eval/                        # Evaluation harness (Phase 4)
├── scripts/
│   ├── build_rag_store.py       # Build the RAG store
│   └── run_demo.py              # Run the demo
└── tests/
```

## Build Phases

- [x] **Phase 1** - Skeleton end-to-end agent (PCAP -> StubDetector -> minimal RAG -> LangGraph loop -> report)
- [ ] **Phase 2** - Full RAG layer (real CVE/ATT&CK data, natural chunking, second tool)
- [ ] **Phase 3** - Swap in LSTM detector
- [ ] **Phase 4** - Evaluation harness with LLM-as-judge
- [ ] **Phase 5** - Polish/add-backs (dashboard, live capture, deployment)

## Design Decisions

- **Retrieval:** top-k of 3-5, never 20. Chunks follow natural boundaries (one CVE = one chunk).
- **Agent loop:** Hard iteration cap as guardrail. Terminal action is an explicit "produce report" step.
- **Tools return structured, concise results** - never raw document dumps.
- **Tools fail gracefully** - return "no relevant results" message, never raise exceptions.
- **Source-agnostic ingestion** - `PacketSource` protocol allows swapping in live capture without touching downstream code.
- **Detector protocol** - LSTM swaps in as a one-line config change.

See [Design.md](Design.md) for the full technical design document.
