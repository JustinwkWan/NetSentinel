"""Convenience wrapper: build the RAG store with real CVE + ATT&CK data."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.rag.build_store import build_store


def main():
    parser = argparse.ArgumentParser(
        description="Build the NetSentinel RAG store with CVE + ATT&CK data"
    )
    parser.add_argument(
        "--cached",
        action="store_true",
        help="Use previously downloaded data from data/threat_intel/ instead of fetching fresh",
    )
    args = parser.parse_args()
    build_store(use_cached=args.cached)


if __name__ == "__main__":
    main()
