# CLAUDE.md — NetSentinel

## Project Overview

NetSentinel is an MVP AI agent for network security. It ingests PCAP files, detects anomalous network flows, and autonomously investigates each flagged flow using a ReAct-style agent loop backed by CVE and MITRE ATT&CK threat intelligence. The output is structured threat reports.

## Tech Stack

- **Language:** Python (entire project)
- **Packet handling:** PyShark
- **Anomaly detection:** PyTorch (LSTM model)
- **Vector store:** ChromaDB
- **Agent orchestration:** LangGraph (ReAct loop)
- **LLM:** Anthropic Claude API (agent reasoning + eval judge)
- **CLI entry point:** `netsentinel/cli.py`

## Architecture (4 layers)

1. **Ingestion** (`netsentinel/ingestion/`) — `process_packets(source) -> list[FlowRecord]`, source-agnostic via `PacketSource` interface
2. **Detection** (`netsentinel/detection/`) — `Detector` Protocol with `StubDetector` (rules) and `LstmDetector` (PyTorch); outputs `FlaggedFlow`
3. **Agent** (`netsentinel/agent/`) — LangGraph ReAct graph with tools `cve_lookup` and `attack_technique_lookup`; produces `ThreatReport`
4. **RAG** (`netsentinel/rag/`) — ChromaDB collection of CVE + MITRE ATT&CK data, chunked on natural boundaries (one CVE = one chunk, one technique = one chunk)

Evaluation harness lives in `eval/` as a peer package.

## Build Phases

- **Phase 1:** Skeleton end-to-end agent (PCAP → StubDetector → minimal RAG → LangGraph loop → report)
- **Phase 2:** Full RAG layer (real CVE/ATT&CK data, natural chunking, second tool)
- **Phase 3:** Swap in LSTM detector
- **Phase 4:** Evaluation harness with LLM-as-judge
- **Phase 5:** Polish/add-backs (dashboard, live capture, deployment)

## Key Design Decisions

- **Retrieval:** top-k of 3–5, never 20. Chunk on natural boundaries, not fixed-size splits.
- **Agent loop:** hard iteration cap as guardrail. Terminal action is explicit "produce report" step.
- **Tools return structured, concise results** — never raw document dumps.
- **Tools fail gracefully** — return "no relevant results" message, never raise exceptions that kill the graph.
- **No Reflexion/self-critique in MVP** — no ground-truth signal at runtime to make it useful.
- **Eval judge uses bias mitigations** — position swap, anti-verbosity instruction, rubric-based scoring, different model family from agent when feasible.

## Conventions

- All config (model names, k values, iteration cap, paths) lives in `config.py`. No magic numbers scattered in code.
- Data objects (`FlowRecord`, `FlaggedFlow`, `ThreatReport`) are plain Python dataclasses.
- Interfaces use `typing.Protocol` for duck-typed contracts (e.g., `Detector`, `PacketSource`).
- Tests live in `tests/` and mirror the package structure.
- The `data/chroma/` directory is gitignored (built by `scripts/build_rag_store.py`).

## Commands

```bash
# Run the main pipeline
python -m netsentinel.cli <path-to-pcap>

# Build the RAG store
python scripts/build_rag_store.py

# Run the demo
python scripts/run_demo.py

# Run tests
pytest tests/

# Run evaluation
python -m eval.harness
```

## Out of Scope for MVP

- Live packet capture (deferred to Phase 5; interface is ready)
- React dashboard / WebSocket alerts
- Conversational chat interface
- AWS deployment / CI/CD
- Self-RAG / Corrective RAG (upgrade path documented, gated on eval results)
