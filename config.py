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

# LLM — supports DeepSeek via Anthropic-compatible API
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-v4-pro")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/anthropic")
LLM_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
LLM_TEMPERATURE = 0.0

# RAG
RETRIEVAL_K = 3
CHROMA_COLLECTION_CVE = "cve_entries"
CHROMA_COLLECTION_ATTACK = "attack_techniques"

# Agent
AGENT_MAX_ITERATIONS = 5

# Detection
DETECTOR_TYPE = "stub"  # "stub" or "lstm"

# StubDetector thresholds
STUB_SUSPICIOUS_PORTS = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345}
STUB_HIGH_PACKET_RATE = 1000.0  # packets per second
STUB_HIGH_BYTE_RATE = 1_000_000  # bytes per second
