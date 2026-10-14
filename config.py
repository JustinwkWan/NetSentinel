"""Central configuration for NetSentinel. No magic numbers elsewhere."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Paths
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
PCAP_DIR = DATA_DIR / "pcaps"
THREAT_INTEL_DIR = DATA_DIR / "threat_intel"
CHROMA_DIR = DATA_DIR / "chroma"
TRAINING_DIR = DATA_DIR / "training"  # live-capture windows saved for LSTM training

# LLM - supports DeepSeek via Anthropic-compatible API
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-v4-pro")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/anthropic")
LLM_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
LLM_TEMPERATURE = 0.0

# LLM rate limiting (shared by every model call in the process). DeepSeek's
# documented account limit is 500 concurrent requests for deepseek-v4-pro;
# these are deliberately far below it to bound cost and load.
LLM_REQUESTS_PER_SECOND = 1.0  # sustained rate at which requests may start
LLM_MAX_BURST = 4  # requests that may start back to back after idle time
LLM_MAX_RETRIES = 4  # SDK retries on 429/5xx/timeouts, exponential backoff
LLM_TIMEOUT_SECONDS = 120.0  # hard deadline per attempt; normal calls take 2-30s

# RAG
RETRIEVAL_K = 3
CHROMA_COLLECTION_CVE = "cve_entries"
CHROMA_COLLECTION_ATTACK = "attack_techniques"

# Agent
AGENT_MAX_ITERATIONS = 5
# Investigations running at once, across all runs (API, live capture, CLI)
INVESTIGATION_MAX_CONCURRENCY = 4

# Evaluation
EVAL_JUDGE_MODEL = os.getenv("EVAL_JUDGE_MODEL", LLM_MODEL)

# Detection
DETECTOR_TYPE = "stub"  # "stub" or "lstm"

# LSTM detector
LSTM_MODEL_PATH = DATA_DIR / "models" / "lstm_detector.pt"
LSTM_MAX_SEQ_LEN = 32  # packets per flow the model sees, from the start of the flow
LSTM_SCORE_BATCH_SIZE = 256  # flows scored per forward pass
LSTM_MIN_TRAINING_FLOWS = 500  # training refuses smaller datasets

# Flows on these ports are never learned as normal traffic
TRAINING_EXCLUDE_PORTS = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345}
LSTM_ANOMALY_THRESHOLD = 1.82  # fallback for checkpoints without one; training: mean + 3*std of reconstruction errors

# StubDetector thresholds
STUB_SUSPICIOUS_PORTS = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345}
STUB_HIGH_PACKET_RATE = 1000.0  # packets per second
STUB_HIGH_BYTE_RATE = 1_000_000  # bytes per second

# API
API_MAX_JOBS_RETAINED = 200  # finished jobs kept in memory; oldest evicted first

# Live capture
CAPTURE_LOG_PATH = DATA_DIR / "logs" / "dumpcap.log"
CAPTURE_INGEST_WAIT_SECONDS = 120.0  # max wait for jobs to read a file before it is deleted
