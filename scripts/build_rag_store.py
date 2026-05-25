"""Build the ChromaDB RAG store with hand-picked CVE entries for Phase 1."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import chromadb

import config


# Hand-picked CVE entries for Phase 1 — small set covering common network attacks
SEED_CVES = [
    {
        "cve_id": "CVE-2017-0144",
        "severity": "critical",
        "description": (
            "The SMBv1 server in Microsoft Windows allows remote attackers to "
            "execute arbitrary code via crafted packets, aka 'Windows SMB Remote "
            "Code Execution Vulnerability.' This vulnerability was exploited by "
            "the WannaCry ransomware and EternalBlue exploit. Affects Windows "
            "Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, "
            "Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, "
            "Windows 10 Gold, 1511, and 1607, and Windows Server 2016."
        ),
    },
    {
        "cve_id": "CVE-2021-44228",
        "severity": "critical",
        "description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases "
            "2.12.3, 2.12.4, and 2.3.1) JNDI features used in configuration, log "
            "messages, and parameters do not protect against attacker controlled "
            "LDAP and other JNDI related endpoints. An attacker who can control "
            "log messages or log message parameters can execute arbitrary code "
            "loaded from LDAP servers when message lookup substitution is enabled. "
            "Known as Log4Shell."
        ),
    },
    {
        "cve_id": "CVE-2019-0708",
        "severity": "critical",
        "description": (
            "A remote code execution vulnerability exists in Remote Desktop "
            "Services formerly known as Terminal Services when an unauthenticated "
            "attacker connects to the target system using RDP and sends specially "
            "crafted requests, aka 'Remote Desktop Services Remote Code Execution "
            "Vulnerability' or BlueKeep. Affects Windows 7 SP1, Windows Server "
            "2008 R2 SP1, Windows Server 2008, Windows XP, Windows Server 2003."
        ),
    },
    {
        "cve_id": "CVE-2020-1472",
        "severity": "critical",
        "description": (
            "An elevation of privilege vulnerability exists when an attacker "
            "establishes a vulnerable Netlogon secure channel connection to a "
            "domain controller, using the Netlogon Remote Protocol (MS-NRPC), "
            "aka 'Netlogon Elevation of Privilege Vulnerability' or Zerologon. "
            "An attacker who successfully exploited this vulnerability could run "
            "a specially crafted application on a device on the network."
        ),
    },
    {
        "cve_id": "CVE-2014-0160",
        "severity": "high",
        "description": (
            "The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do "
            "not properly handle Heartbeat Extension packets, which allows remote "
            "attackers to obtain sensitive information from process memory via "
            "crafted packets that trigger a buffer over-read, as demonstrated by "
            "reading private keys, aka the Heartbleed bug."
        ),
    },
    {
        "cve_id": "CVE-2023-44487",
        "severity": "high",
        "description": (
            "The HTTP/2 protocol allows a denial of service (server resource "
            "consumption) because request cancellation can reset many streams "
            "quickly, as exploited in the wild in August through October 2023. "
            "Known as Rapid Reset attack. Affects multiple HTTP/2 implementations "
            "including nginx, Apache, and various cloud providers."
        ),
    },
    {
        "cve_id": "CVE-2017-5638",
        "severity": "critical",
        "description": (
            "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 "
            "and 2.5.x before 2.5.10.1 has incorrect exception handling and error "
            "message generation during file-upload attempts, which allows remote "
            "attackers to execute arbitrary commands via crafted Content-Type, "
            "Content-Disposition, or Content-Length HTTP header values."
        ),
    },
    {
        "cve_id": "CVE-2021-34527",
        "severity": "critical",
        "description": (
            "Windows Print Spooler Remote Code Execution Vulnerability, aka "
            "PrintNightmare. A remote code execution vulnerability exists when "
            "the Windows Print Spooler service improperly performs privileged "
            "file operations. An attacker who successfully exploited this "
            "vulnerability could run arbitrary code with SYSTEM privileges."
        ),
    },
    {
        "cve_id": "CVE-2018-13379",
        "severity": "critical",
        "description": (
            "An Improper Limitation of a Pathname to a Restricted Directory "
            "('Path Traversal') in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to "
            "5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, "
            "1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows "
            "an unauthenticated attacker to download system files via specially "
            "crafted HTTP resource requests."
        ),
    },
    {
        "cve_id": "CVE-2022-27254",
        "severity": "medium",
        "description": (
            "Replay attack vulnerability in network traffic. An attacker can "
            "capture and replay network packets to perform unauthorized actions. "
            "This affects systems that do not implement proper anti-replay "
            "mechanisms such as sequence numbers, timestamps, or nonces in "
            "their network protocols."
        ),
    },
]


def build_store():
    """Build the ChromaDB store with seed CVE data."""
    config.CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(config.CHROMA_DIR))

    # Delete existing collection if present
    try:
        client.delete_collection(config.CHROMA_COLLECTION_CVE)
    except Exception:
        pass

    collection = client.create_collection(
        name=config.CHROMA_COLLECTION_CVE,
        metadata={"description": "CVE entries for network security threats"},
    )

    ids = []
    documents = []
    metadatas = []

    for cve in SEED_CVES:
        ids.append(cve["cve_id"])
        documents.append(cve["description"])
        metadatas.append({
            "cve_id": cve["cve_id"],
            "severity": cve["severity"],
        })

    collection.add(ids=ids, documents=documents, metadatas=metadatas)
    print(f"[*] Built CVE collection with {len(ids)} entries at {config.CHROMA_DIR}")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(config.PROJECT_ROOT))
    build_store()
