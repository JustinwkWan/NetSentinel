"""Run the canonical demo end to end."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.cli import main

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.argv.append(str(Path(__file__).resolve().parent.parent / "data" / "pcaps" / "sample_suspicious.pcap"))
    main()
