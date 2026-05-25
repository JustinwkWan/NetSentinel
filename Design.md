# NetSentinel — Technical Design Document

**Project:** NetSentinel, an MVP AI agent for network security
**Author:** Justin Wan
**Status:** Design / pre-implementation
**Purpose:** Portfolio project for new-grad SWE / GenAI applications

---

## 1. Overview and Goals

### What it is

NetSentinel is a LangGraph-based AI agent that investigates suspicious network activity. It ingests network traffic, runs an LSTM anomaly detector to flag suspicious flows, then autonomously investigates each flagged flow: it queries a retrieval store of CVE and MITRE ATT&CK data through tools, decides what threat intelligence is relevant, classifies the severity of the flow, and produces a structured threat report. The agent runs a ReAct-style loop, deciding for itself whether it needs another lookup before concluding.

The system is Python throughout. The core stack is PyShark for packet handling, PyTorch for the LSTM detector, ChromaDB for the vector store, LangGraph for agent orchestration, an LLM API for the agent's reasoning, and a custom evaluation harness.

### What this MVP is, precisely

The MVP is the smallest version of NetSentinel that is a *real, working agent* and not a demo script. That means the agent genuinely decides its own path: it chooses which tools to call, reacts to what they return, and decides when it has enough to conclude. The detection and ingestion layers exist to feed the agent something real to investigate; they are deliberately not the focus.

### What is explicitly out of scope for the MVP

These were in the original NetSentinel vision and are intentionally deferred. Each is a clean, independent add-back, not a rewrite.

- **Live packet capture as the built input path.** The MVP ingests PCAP files. However, the ingestion layer is built behind a *source-agnostic interface* (see Section 3) so that a live-capture source can be plugged in later without touching the rest of the system. Live capture is deferred because it is a demo liability, not a technical one: demoing it requires elevated permissions, a live interface seeing interesting traffic, and malicious-looking activity happening at the moment of the demo. PCAP input makes the demo deterministic and shippable. Live capture is the first post-MVP add-back.
- **The React dashboard and WebSocket real-time alerts.** The MVP's interface is a command-line entry point that takes a PCAP and prints structured threat reports. A dashboard is polish, not core.
- **The conversational chat interface.** The MVP produces structured reports; it does not hold a conversation about them. Conversational follow-up is a later layer.
- **AWS deployment and CI/CD.** The MVP runs locally. Deployment is a final-phase add-back.

### The staged path back to the full vision

The build is sequenced so there is always something that works (see Section 5). The add-backs, in priority order after the MVP is complete: (1) live-capture source plugged into the existing ingestion interface, (2) a minimal dashboard over the existing report output, (3) deployment with Docker and a cloud target. None of these is on the critical path to a working, demoable agent.

### Success criteria for the MVP

- Given a PCAP file, the system produces a structured threat report for each flagged flow.
- The agent demonstrably runs a multi-step loop: it calls tools, reacts to results, and terminates on its own judgment, with a hard iteration cap as a guardrail.
- The retrieval layer is backed by real CVE and MITRE ATT&CK data, with a deliberate chunking strategy.
- There is an evaluation harness that runs the agent against a small labeled set and reports measured behavior.

---

## 2. Relevant Research, Connected to Build Decisions

This section does not re-summarize the literature. The companion reference, *The Modern AI Engineering Stack*, already covers these papers with their results, ablations, and limitations. What follows is specific: for each paper that bears on a NetSentinel design decision, what the paper implies *for this build*.

### ReAct (Yao et al., 2022) — the agent loop itself

NetSentinel's agent is a ReAct loop, directly. The investigation flow is reason → act → observe → repeat: the agent reasons about a flagged flow, acts by calling a retrieval tool, observes what came back, and reasons again about whether it needs more.

Two concrete implications. First, the documented ReAct failure mode is the repetitive loop, where the agent regenerates the same thought and action. NetSentinel handles this in the orchestrator, not by hoping the model behaves: a hard iteration cap, and the agent's terminal action being an explicit "produce the report" step rather than an open-ended stop. Second, ReAct's other failure mode is unhelpful retrievals leading the reasoning astray. This is why the retrieval tools (Section 3) return concise, structured results rather than dumping raw documents into context, and why the eval harness (below) scores trajectory quality, not just the final answer, so a "right report, bad reasoning path" case is visible.

### Reflexion / evaluator-optimizer (Shinn et al., 2023) — deliberately *not* in the MVP

The tempting move is to have the agent self-critique its threat report and retry. The MVP does not do this, and the reason is in Reflexion's own ablations: verbal self-reflection without a ground-truth signal *degrades* performance — the agent talks itself into a worse answer. NetSentinel's MVP has no reliable per-flow ground-truth signal at runtime (that is exactly what the agent is trying to produce). Adding a self-critique loop now would be cargo-culting the pattern. Reflexion stays a post-MVP candidate, and only if a real verification signal can be introduced. This is itself a strong interview point: knowing when *not* to use a pattern.

### Original RAG (Lewis et al., 2020) and Lost in the Middle (Liu et al., 2023) — chunking and retrieval design

The CVE/ATT&CK retrieval store is the part of NetSentinel that most needs deliberate design, and these two papers drive it.

From the original RAG paper: retrieval and generation are separable, and a degenerate single-shot retrieval at query time is the common production shape. NetSentinel's MVP uses exactly that degenerate shape on purpose — single retrieval per tool call, off-the-shelf embeddings — because it is sufficient and the agent loop, not the retriever, is the project's point.

From Lost in the Middle, three concrete build decisions:

- **Chunk along natural boundaries.** One CVE entry is one chunk; one ATT&CK technique is one chunk. No naive fixed-size text splitting. A retrieved chunk should be a complete, self-contained unit of threat intelligence.
- **Retrieve few, not many.** The paper's retriever-reader curves saturate fast, and middle-of-context information is used poorly. NetSentinel retrieves a small top-k (in the range of 3–5) per tool call rather than stuffing 20 chunks in.
- **Place retrieved content at context boundaries.** When tool results re-enter the agent's context, the orchestrator places them where the model attends best, not buried in the middle of a long history.

### Self-RAG and Corrective RAG (Asai et al., 2023; Yan et al., 2024) — retrieval evaluation, deferred with a known upgrade path

Self-RAG (the model critiques its own retrievals via special tokens) and Corrective RAG (a retrieval evaluator re-queries when confidence is low) are the natural upgrades when naive retrieval returns junk. The MVP does not include either: Self-RAG needs base-model fine-tuning that is out of scope, and CRAG adds a moving part before the basic loop is proven. But this is a *known* upgrade path, not an oversight. If eval (Phase 4) shows the agent acting on bad retrievals, CRAG is the first thing to add: it is cheap and it slots into the existing tool layer. Documenting this as a deliberate, evidence-gated decision is more honest than building it speculatively.

### LLM-as-judge biases (Zheng et al., 2023) — how the eval harness is designed

The Phase 4 eval harness will use an LLM to judge the agent's threat reports against expected classifications. The documented judge biases shape that harness directly:

- **Position bias:** when comparing or scoring, swap orderings and require consistency; otherwise treat it as a tie.
- **Verbosity bias:** the judge prompt explicitly instructs against rewarding longer reports, and scoring is against a rubric (did it identify the right severity, did it cite relevant threat intel) rather than holistic preference.
- **Self-enhancement bias:** where feasible, the judge model is a different family than the agent's model.
- **The headline caution:** LLM-as-judge output is a noisy estimator, not ground truth. The eval set's labels are human-set; the judge measures agreement with those labels, and the harness reports that framing honestly.

### Anthropic's "Building Effective Agents" (Schluntz & Zhang, 2024) — what NetSentinel actually is

Against the five workflow patterns, NetSentinel is a genuine **agent**, not a workflow: the LLM dynamically directs its own tool usage and decides when it is done. It is not prompt chaining (the path is not fixed) and it is not pure routing.

The essay's central discipline — start simple, add complexity only when needed — is the spine of the build plan in Section 5. It also argues for starting with direct LLM API calls before adopting a framework. NetSentinel uses LangGraph deliberately rather than reflexively: the project needs LangGraph's stateful loop and checkpointing, and "I can speak to LangGraph" is an explicit resume goal. But the design keeps the agent loop legible enough that the underlying prompt/response cycle is never obscured.

### A note on the LSTM and the systems-reliability math

One non-paper point worth recording, from the reference doc's tool-use section: per-step reliability compounds badly over a trajectory (a 95% per-call success rate over 10 steps is ~60% end-to-end). NetSentinel's MVP keeps the agent's trajectories short (a small handful of tool calls per flow, enforced by the iteration cap) precisely so end-to-end reliability stays acceptable. This is also why the LSTM is sequenced *after* the agent loop is proven (Phase 3): the detector is not on the agent's critical path, and proving the loop against a trivial stub detector first de-risks the whole project.

---

## 3. Architecture

### Layers and data flow

```
PCAP file
   │
   ▼
┌──────────────────────────────────────────┐
│ Layer 1: Ingestion                       │
│  process_packets(source) -> [FlowRecord] │   source-agnostic interface
└──────────────────────────────────────────┘
   │  list of FlowRecord
   ▼
┌──────────────────────────────────────────┐
│ Layer 2: Detection                       │
│  detector.flag(flows) -> [FlaggedFlow]   │   stub first, LSTM later
└──────────────────────────────────────────┘
   │  flows with anomaly scores + metadata
   ▼
┌──────────────────────────────────────────┐
│ Layer 3: Agent Orchestration (LangGraph) │
│  ReAct loop over each FlaggedFlow        │
│   ├─ tool: cve_lookup                    │
│   └─ tool: attack_technique_lookup       │
│         │                                │
│         ▼                                │
│  ┌────────────────────────────────────┐  │
│  │ Layer 4: RAG store (ChromaDB)      │  │
│  │  CVE entries + MITRE ATT&CK        │  │
│  │  chunked on natural boundaries     │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
   │  structured ThreatReport per flow
   ▼
┌──────────────────────────────────────────┐
│ Output: structured reports (CLI / JSON)  │
└──────────────────────────────────────────┘

   Evaluation harness runs the whole pipeline
   against a labeled flow set and scores it.
```

### Layer 1 — Ingestion

The single most important interface in the project. Ingestion exposes one function:

```
process_packets(source: PacketSource) -> list[FlowRecord]
```

`PacketSource` is an abstraction. In the MVP there is exactly one implementation, `PcapFileSource`, which reads a `.pcap` with PyShark. The post-MVP `LiveCaptureSource` implements the same interface. Nothing downstream of ingestion knows or cares which source produced the flows.

A `FlowRecord` is a plain data object: source/destination IPs and ports, protocol, packet count, byte count, flow duration, start timestamp, and a small set of derived features (packet rate, mean packet size). These are the features the detector consumes.

### Layer 2 — Detection

Detection exposes one interface:

```
class Detector(Protocol):
    def flag(self, flows: list[FlowRecord]) -> list[FlaggedFlow]: ...
```

Two implementations over the life of the build. `StubDetector` (Phase 1) flags flows by a transparent rule — e.g. unusual destination ports, abnormal packet rates — and exists purely so the agent has something real to investigate while the loop is being built. `LstmDetector` (Phase 3) wraps the CAPP LSTM behind the identical interface. A `FlaggedFlow` is a `FlowRecord` plus an anomaly score and a short reason string.

Because both detectors satisfy the same `Protocol`, swapping the LSTM in is a one-line change in the entry point and a config flag. The agent layer never changes.

### Layer 3 — Agent Orchestration

A LangGraph graph implementing a ReAct loop. State carried through the graph: the `FlaggedFlow` under investigation, the running message history, the list of tool results gathered so far, and an iteration counter.

The loop: the agent node receives the current state and decides on an action — call a tool, or produce the final report. If it calls a tool, the tool node executes it, appends the result to state, increments the counter, and returns to the agent node. If the counter hits the cap, the graph routes to a forced-report node. The terminal action produces a `ThreatReport`.

Tools, in the MVP:

- `cve_lookup(query)` — retrieves relevant CVE entries from the RAG store.
- `attack_technique_lookup(query)` — retrieves relevant MITRE ATT&CK techniques from the RAG store.

Both tools return concise, structured results (not raw document dumps) for the context-hygiene reasons in Section 2. Tools fail gracefully: a retrieval that finds nothing returns a clean "no relevant results" message the agent can react to, never an exception that kills the graph.

A `ThreatReport` is structured: the flow it concerns, an assigned severity, the threat intelligence the agent judged relevant (with identifiers), the agent's reasoning summary, and a remediation recommendation.

### Layer 4 — RAG store

A ChromaDB collection built once, offline, by an ingestion script. Sources: CVE entries from the NIST NVD API, and MITRE ATT&CK technique descriptions. Chunking is on natural boundaries — one CVE per chunk, one technique per chunk — per Section 2. Embeddings are off-the-shelf for the MVP. The store is queried only through the two tools; the agent never touches ChromaDB directly.

### Evaluation harness

A standalone runner (Section 5, Phase 4) that takes a labeled set of flagged flows with expected classifications, runs the full agent pipeline over each, and scores the agent's reports — both the final classification and the trajectory quality. Judge design follows the bias mitigations in Section 2.

---

## 4. File Structure

```
netsentinel/
├── README.md                    # project overview, setup, demo instructions
├── DESIGN.md                    # this document
├── requirements.txt             # pinned dependencies
├── .env.example                 # template for LLM API key, config (no secrets committed)
├── config.py                    # central config: model names, k values, iteration cap, paths
│
├── data/
│   ├── pcaps/                   # sample PCAP files for demo and testing
│   │   └── README.md            # provenance of each sample capture
│   ├── threat_intel/            # raw downloaded CVE / ATT&CK data before ingestion
│   └── chroma/                  # persisted ChromaDB store (gitignored; built by script)
│
├── netsentinel/                 # main package
│   ├── __init__.py
│   │
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── sources.py           # PacketSource interface, PcapFileSource (LiveCaptureSource later)
│   │   ├── flows.py             # FlowRecord data object, flow assembly from packets
│   │   └── features.py          # derived feature extraction (packet rate, mean size, etc.)
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── base.py              # Detector Protocol, FlaggedFlow data object
│   │   ├── stub.py              # StubDetector — rule-based, Phase 1
│   │   └── lstm.py              # LstmDetector — wraps CAPP model, Phase 3
│   │
│   ├── rag/
│   │   ├── __init__.py
│   │   ├── build_store.py       # offline script: download + chunk + embed + persist to Chroma
│   │   ├── chunking.py          # natural-boundary chunking for CVE and ATT&CK
│   │   └── store.py             # thin query interface over the ChromaDB collection
│   │
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── graph.py             # the LangGraph graph: nodes, edges, routing, state
│   │   ├── state.py             # agent state definition
│   │   ├── tools.py             # cve_lookup, attack_technique_lookup tool definitions
│   │   ├── prompts.py           # system prompt and any templated prompts
│   │   └── report.py            # ThreatReport data object + formatting
│   │
│   └── cli.py                   # entry point: takes a PCAP path, runs pipeline, prints reports
│
├── eval/
│   ├── __init__.py
│   ├── dataset.py               # labeled flagged-flow set + expected classifications
│   ├── harness.py               # runs the agent over the set, collects results
│   ├── judge.py                 # LLM-as-judge scoring with bias mitigations
│   └── report.py                # produces the eval summary (metrics, per-case breakdown)
│
├── scripts/
│   ├── build_rag_store.py       # convenience wrapper around rag/build_store.py
│   └── run_demo.py              # runs the canonical demo end to end
│
└── tests/
    ├── __init__.py
    ├── test_ingestion.py        # FlowRecord assembly, feature extraction
    ├── test_detection.py        # StubDetector behavior, FlaggedFlow shape
    ├── test_rag.py              # chunking boundaries, store query returns
    ├── test_tools.py            # tools return clean structured results, fail gracefully
    └── test_agent.py            # loop terminates, respects iteration cap, produces a report
```

Notes on a few deliberate choices. `config.py` centralizes the things that get tuned during the build — model names, retrieval `k`, the iteration cap — so they are not scattered as magic numbers. The `ingestion/sources.py` split is what makes live capture a later drop-in. `detection/base.py` holding the `Protocol` is what makes the LSTM swap contained. The `eval/` package is a peer of the main package, not buried inside it, because the evaluation story is a first-class deliverable, not an afterthought.

---

## 5. Build Phases

The plan is sequenced to de-risk, not to cut for time. Each phase ends at something that runs and can be demoed. Quality deepens layer by layer; there is never a big-bang integration at the end.

### Phase 1 — Skeleton: a thin end-to-end agent

Build `process_packets` with `PcapFileSource`, the `FlowRecord` object, and basic feature extraction. Build `StubDetector` with a transparent rule. Build a minimal ChromaDB store with a small hand-picked set of CVE entries. Build the LangGraph graph with one tool (`cve_lookup`), the ReAct loop, the iteration cap, and graceful tool failure. Wire `cli.py`.

**Done when:** running `cli.py` on a sample PCAP produces a structured threat report, and the agent visibly took a multi-step path to get there.

### Phase 2 — Deepen the RAG layer

Replace the hand-picked CVE set with real data: pull CVE entries from the NIST NVD API and MITRE ATT&CK techniques, implement natural-boundary chunking, build and persist the full store via `build_store.py`. Add the second tool, `attack_technique_lookup`, so the agent can investigate techniques separately from vulnerabilities.

**Done when:** the agent has real threat intelligence to retrieve and two distinct tools to choose between, and the reports cite real CVE/ATT&CK identifiers.

### Phase 3 — Swap in the LSTM

Implement `LstmDetector`, wrapping the CAPP model behind the existing `Detector` Protocol. Switch the entry point to use it via a config flag. This phase is contained precisely because Phases 1–2 already proved everything downstream of detection works.

**Done when:** the pipeline runs end to end with the LSTM as the detector, and the stub is still selectable for fast testing.

### Phase 4 — Evaluation harness

Build the labeled flagged-flow set with expected classifications. Build the harness that runs the agent over the set. Build the LLM-as-judge scorer with the bias mitigations from Section 2. Produce an eval summary reporting classification agreement and trajectory quality.

**Done when:** there is a single command that runs the eval and outputs measured agent behavior, and the results are honest enough to talk about in an interview — including whatever the agent gets wrong.

### Phase 5 — Polish and add-backs

In priority order, as time allows: a minimal dashboard over the existing report output; a `LiveCaptureSource` plugged into the existing ingestion interface; deployment with Docker. Each is independent. None blocks a complete, demoable MVP — by this phase the project is already done in every sense that matters for the portfolio.

---

## 6. Open Questions and Risks

**LSTM input alignment.** The CAPP model was trained on a particular feature representation. The risk is that NetSentinel's `FlowRecord` features do not line up with what the model expects. Resolve early: pin down the model's exact expected input *before* Phase 3, and make `features.py` produce that representation. If alignment turns out to be expensive, the stub detector is the fallback and the LSTM becomes a Phase 5 add-back instead — the architecture already allows this.

**RAG retrieval quality.** Off-the-shelf embeddings over CVE text may retrieve loosely-related entries. The evidence gate is Phase 4: if eval shows the agent reasoning from bad retrievals, Corrective RAG is the planned response (Section 2). The risk is bounded because the upgrade path is known.

**Eval set construction.** A labeled set of flagged flows with *correct* expected classifications is real work and is the part most likely to be done weakly. Getting genuine ground truth may require care in sourcing PCAPs with known attack content. This is called out as a risk because a weak eval set quietly undermines the strongest part of the project.

**LLM cost and latency during eval.** Running the full agent loop over a labeled set on every eval run costs API calls and time. Mitigation: keep the eval set small and curated (the reference doc's guidance is 50–200 for production; the MVP can start smaller), and cache where the framework allows.

**Agent loop reliability.** Even with short trajectories, the agent can still take a bad path — wrong tool, unhelpful query, premature conclusion. This is not fully solvable in the MVP. The mitigations are the iteration cap, the structured terminal action, and the trajectory-quality scoring in eval that makes bad paths *visible* even when the final answer happens to be right.

**Scope discipline.** The honest meta-risk: the original NetSentinel vision is large and the temptation will be to pull deferred items back in early. The build plan exists to resist that. Live capture, the dashboard, and deployment stay in Phase 5. The MVP is done when Phase 4 is done.
