"""Download, chunk, embed, and persist CVE + ATT&CK data to ChromaDB."""

from __future__ import annotations

import json
import time
from pathlib import Path

import chromadb
import requests

import config
from netsentinel.rag.chunking import chunk_attack_technique, chunk_cve

# NVD API for CVE data
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# MITRE ATT&CK STIX data (Enterprise matrix)
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Network-security-relevant CVE search keywords
CVE_KEYWORDS = [
    "remote code execution network",
    "denial of service TCP",
    "buffer overflow SMB",
    "SQL injection remote",
    "privilege escalation network",
    "authentication bypass SSH",
    "command injection HTTP",
    "path traversal web server",
    "cross-site scripting XSS",
    "server side request forgery",
]

# How many CVEs to fetch per keyword (NVD returns up to 2000 per request)
CVE_RESULTS_PER_KEYWORD = 50


def fetch_cves(keywords: list[str] | None = None) -> list[dict]:
    """Fetch CVE entries from the NVD API using keyword searches."""
    keywords = keywords or CVE_KEYWORDS
    all_cves = {}  # dedupe by CVE ID

    for keyword in keywords:
        print(f"  [*] Fetching CVEs for: {keyword}")
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": CVE_RESULTS_PER_KEYWORD,
        }
        try:
            resp = requests.get(NVD_API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve", {}).get("id", "")
                if cve_id and cve_id not in all_cves:
                    all_cves[cve_id] = vuln
            print(f"    Got {len(vulnerabilities)} results ({len(all_cves)} unique total)")
        except Exception as e:
            print(f"    [!] Failed: {e}")

        # NVD rate limit: 5 requests per 30s without API key
        time.sleep(6)

    return list(all_cves.values())


def fetch_attack_techniques() -> list[dict]:
    """Fetch ATT&CK techniques from MITRE's STIX data."""
    print("  [*] Fetching ATT&CK Enterprise STIX data...")
    try:
        resp = requests.get(ATTACK_STIX_URL, timeout=60)
        resp.raise_for_status()
        stix_bundle = resp.json()
    except Exception as e:
        print(f"    [!] Failed to fetch ATT&CK data: {e}")
        return []

    techniques = []
    for obj in stix_bundle.get("objects", []):
        if (
            obj.get("type") == "attack-pattern"
            and not obj.get("revoked", False)
            and not obj.get("x_mitre_deprecated", False)
        ):
            techniques.append(obj)

    print(f"    Got {len(techniques)} active techniques")
    return techniques


def save_raw_data(cves: list[dict], techniques: list[dict]) -> None:
    """Save raw downloaded data for reproducibility."""
    config.THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)

    cve_path = config.THREAT_INTEL_DIR / "cves_raw.json"
    with open(cve_path, "w") as f:
        json.dump(cves, f)
    print(f"  [*] Saved {len(cves)} raw CVEs to {cve_path}")

    attack_path = config.THREAT_INTEL_DIR / "attack_techniques_raw.json"
    with open(attack_path, "w") as f:
        json.dump(techniques, f)
    print(f"  [*] Saved {len(techniques)} raw techniques to {attack_path}")


def build_collection(
    client: chromadb.ClientAPI,
    collection_name: str,
    chunks: list[dict],
) -> None:
    """Build a ChromaDB collection from chunked documents."""
    # Delete existing collection if present
    try:
        client.delete_collection(collection_name)
    except Exception:
        pass

    collection = client.create_collection(name=collection_name)

    # ChromaDB has a batch size limit; add in batches
    batch_size = 100
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i : i + batch_size]
        collection.add(
            ids=[c["id"] for c in batch],
            documents=[c["document"] for c in batch],
            metadatas=[c["metadata"] for c in batch],
        )

    print(f"  [*] Built collection '{collection_name}' with {len(chunks)} chunks")


def build_store(use_cached: bool = False) -> None:
    """Build the full RAG store: download data, chunk, embed, persist."""
    print("[*] Building RAG store...")

    cve_cache = config.THREAT_INTEL_DIR / "cves_raw.json"
    attack_cache = config.THREAT_INTEL_DIR / "attack_techniques_raw.json"

    # Fetch or load cached data
    if use_cached and cve_cache.exists() and attack_cache.exists():
        print("[*] Using cached data from data/threat_intel/")
        with open(cve_cache) as f:
            raw_cves = json.load(f)
        with open(attack_cache) as f:
            raw_techniques = json.load(f)
    else:
        print("[*] Downloading fresh data...")
        raw_cves = fetch_cves()
        raw_techniques = fetch_attack_techniques()
        save_raw_data(raw_cves, raw_techniques)

    # Chunk on natural boundaries
    print("[*] Chunking data...")
    cve_chunks = []
    for entry in raw_cves:
        chunk = chunk_cve(entry)
        if chunk:
            cve_chunks.append(chunk)
    print(f"  [*] {len(cve_chunks)} CVE chunks from {len(raw_cves)} entries")

    attack_chunks = []
    for tech in raw_techniques:
        chunk = chunk_attack_technique(tech)
        if chunk:
            attack_chunks.append(chunk)
    print(f"  [*] {len(attack_chunks)} ATT&CK chunks from {len(raw_techniques)} entries")

    # Build ChromaDB collections
    print("[*] Building ChromaDB collections...")
    config.CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(config.CHROMA_DIR))

    if cve_chunks:
        build_collection(client, config.CHROMA_COLLECTION_CVE, cve_chunks)
    else:
        print("  [!] No CVE chunks to build — skipping CVE collection")

    if attack_chunks:
        build_collection(client, config.CHROMA_COLLECTION_ATTACK, attack_chunks)
    else:
        print("  [!] No ATT&CK chunks to build — skipping ATT&CK collection")

    print("[*] RAG store build complete.")
