"""Entry point: takes a PCAP path, runs pipeline, prints reports."""

from __future__ import annotations

import argparse
import sys

import config
from netsentinel.agent.graph import investigate_flow
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
        description="NetSentinel — AI network security agent"
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

    reports = []
    for i, ff in enumerate(flagged, 1):
        print(f"\n[*] Investigating flow {i}/{len(flagged)}: {ff.flow.flow_key}")
        print(f"    Anomaly score: {ff.anomaly_score:.2f} — {ff.reason}")
        try:
            report = investigate_flow(ff)
            reports.append(report)
            print(report.format())
        except Exception as e:
            print(f"[!] Investigation failed for {ff.flow.flow_key}: {e}")

    print(f"\n[*] Done. {len(reports)}/{len(flagged)} flows investigated successfully.")


if __name__ == "__main__":
    main()
