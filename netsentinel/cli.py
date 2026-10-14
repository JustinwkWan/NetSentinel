"""Entry point: takes a PCAP path, runs pipeline, prints reports."""

from __future__ import annotations

import argparse
import sys
import time

import config
from netsentinel.agent.scheduler import InvestigationResult, investigate_all
from netsentinel.detection.stub import StubDetector
from netsentinel.ingestion.sources import PcapFileSource, process_packets


DETECTORS = {
    "stub": lambda: StubDetector,
    "lstm": lambda: __import__(
        "netsentinel.detection.lstm", fromlist=["LstmDetector"]
    ).LstmDetector,
}


def main():
    parser = argparse.ArgumentParser(
        description="NetSentinel - AI network security agent"
    )
    parser.add_argument("pcap", help="Path to a PCAP file to analyze")
    parser.add_argument(
        "--detector",
        choices=list(DETECTORS.keys()),
        default=config.DETECTOR_TYPE,
        help="Detector to use (default: stub)",
    )
    args = parser.parse_args()

    print(f"[*] Loading PCAP: {args.pcap}")
    source = PcapFileSource(args.pcap)
    flows = process_packets(source)
    print(f"[*] Assembled {len(flows)} flows")

    if not flows:
        print("[!] No flows found in PCAP. Exiting.")
        sys.exit(0)

    detector_cls = DETECTORS[args.detector]()
    detector = detector_cls()
    flagged = detector.flag(flows)
    print(f"[*] Flagged {len(flagged)} suspicious flows")

    if not flagged:
        print("[*] No suspicious flows detected. Exiting.")
        sys.exit(0)

    print(f"\n[*] Investigating {len(flagged)} flows...")
    start = time.perf_counter()

    def on_result(index: int, result: InvestigationResult) -> None:
        ff = result.flagged
        t = result.timing
        lines = [
            f"\n[*] Flow {index + 1}/{len(flagged)}: {ff.flow.flow_key}",
            f"    Anomaly score: {ff.anomaly_score:.2f} - {ff.reason}",
            f"    Took {t.total_s:.1f}s: {t.llm_calls} LLM calls ({t.llm_s:.1f}s), "
            f"{t.tool_calls} tool calls ({t.tool_s:.1f}s)",
            result.report.format() if result.report is not None
            else f"[!] Investigation failed for {ff.flow.flow_key}: {result.error}",
        ]
        # One print per flow, so output from parallel workers never interleaves
        print("\n".join(lines))

    results = investigate_all(flagged, on_result=on_result)
    succeeded = sum(1 for r in results if r.report is not None)
    print(f"\n[*] Done. {succeeded}/{len(flagged)} flows investigated successfully "
          f"in {time.perf_counter() - start:.1f}s.")


if __name__ == "__main__":
    main()
