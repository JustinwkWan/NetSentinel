"""Detector metrics: false alarm rate on unseen normal traffic, detection
rate on attacks.

Usage:
    python -m eval.detector_metrics [--holdout 0.15] [--instances 10] [--model PATH]

By default a separate model is trained on the earlier captured windows in
data/training/ and tested on the later ones, so every normal flow it is
scored on is traffic it never trained on. The production model is left
untouched. With --model, that checkpoint is measured instead, and only the
windows it was not trained on count as unseen normal traffic.

Attacks are synthetic (see eval/attack_traffic.py) and pass through the
real ingestion path before scoring.
"""

from __future__ import annotations

import argparse
import bisect
import json
import random
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import torch

import config
from eval.attack_traffic import ATTACK_SCENARIOS, BENIGN_CONTROL, Scenario
from netsentinel.detection.lstm import LstmDetector, load_checkpoint
from netsentinel.ingestion.flows import FlowRecord
from netsentinel.ingestion.sources import PcapFileSource, process_packets
from scripts.train_lstm import find_pcaps, is_excluded, train_model
from scapy.all import wrpcap

DEFAULT_HOLDOUT_FRACTION = 0.15
DEFAULT_INSTANCES = 10
DEFAULT_SEED = 0
TARGET_FALSE_ALARM_RATES = (0.01, 0.02, 0.05, 0.10)
RESULTS_PATH = config.DATA_DIR / "eval" / "detector_metrics.json"


@dataclass
class ScenarioResult:
    name: str
    description: str
    instances: int
    instances_detected: int
    flows: int
    flows_flagged: int
    auc: float | None
    # Kept for threshold sweeps; dropped from the saved JSON
    flow_scores: list[list[float]] = field(default_factory=list, repr=False)

    @property
    def flow_detection_rate(self) -> float:
        return self.flows_flagged / self.flows if self.flows else 0.0

    @property
    def instance_detection_rate(self) -> float:
        return self.instances_detected / self.instances if self.instances else 0.0


def split_by_time(pcaps: list[Path], holdout_fraction: float) -> tuple[list[Path], list[Path]]:
    """Earlier files for training, the latest ones held out.

    Testing on later traffic than the model trained on is the situation the
    detector is deployed in. Capture windows are named in time order.
    """
    if not 0 < holdout_fraction < 1:
        raise ValueError("holdout fraction must be between 0 and 1")
    ordered = sorted(pcaps, key=lambda p: p.name)
    n_test = max(1, round(len(ordered) * holdout_fraction))
    if n_test >= len(ordered):
        raise ValueError(f"need at least 2 pcaps to hold some out, got {len(ordered)}")
    return ordered[:-n_test], ordered[-n_test:]


def auc(positive: list[float], negative: list[float]) -> float | None:
    """ROC AUC: the chance a random attack flow outscores a random normal one."""
    if not positive or not negative:
        return None
    ranked = sorted(negative)
    wins = 0.0
    for score in positive:
        below = bisect.bisect_left(ranked, score)
        ties = bisect.bisect_right(ranked, score) - below
        wins += below + 0.5 * ties
    return wins / (len(positive) * len(negative))


def threshold_for_false_alarm_rate(normal_scores: list[float], rate: float) -> float:
    """Lowest threshold that flags at most `rate` of the normal flows."""
    ranked = sorted(normal_scores)
    allowed = int(rate * len(ranked))
    index = len(ranked) - allowed - 1
    return ranked[max(index, 0)]


def read_flows(pcaps: list[Path]) -> tuple[list[FlowRecord], list[str]]:
    """Scorable flows of the given files, and the files that could not be read."""
    flows, unreadable = [], []
    for pcap in pcaps:
        try:
            found = process_packets(PcapFileSource(str(pcap)))
        except Exception as e:
            print(f"[!] Skipping {pcap.name}: {e}")
            unreadable.append(pcap.name)
            continue
        flows.extend(f for f in found if f.packets and not is_excluded(f))
    return flows, unreadable


def scenario_flows(scenario: Scenario, instances: int, seed: int,
                   workdir: Path) -> list[list[FlowRecord]]:
    """Flows of each instance, after a round trip through a pcap file."""
    rng = random.Random(f"{seed}:{scenario.name}")
    result = []
    for i in range(instances):
        path = workdir / f"{scenario.name}_{i}.pcap"
        wrpcap(str(path), scenario.generate(rng, 1_000_000.0 + i * 10_000))
        result.append(process_packets(PcapFileSource(str(path))))
    return result


def measure_scenario(detector: LstmDetector, scenario: Scenario,
                     instances: list[list[FlowRecord]],
                     normal_scores: list[float]) -> ScenarioResult:
    flow_scores = [detector.score(flows) for flows in instances]
    threshold = detector.threshold
    every = [s for scores in flow_scores for s in scores]
    return ScenarioResult(
        name=scenario.name,
        description=scenario.description,
        instances=len(instances),
        instances_detected=sum(any(s > threshold for s in scores)
                               for scores in flow_scores),
        flows=len(every),
        flows_flagged=sum(s > threshold for s in every),
        auc=auc(every, normal_scores),
        flow_scores=flow_scores,
    )


def sweep(normal_scores: list[float], attacks: list[ScenarioResult]) -> list[dict]:
    """Detection at thresholds tuned to fixed false alarm rates.

    The thresholds are picked on the held-out normal flows themselves, so
    these rows show the tradeoff curve, not a tuned operating point.
    """
    rows = []
    for rate in TARGET_FALSE_ALARM_RATES:
        threshold = threshold_for_false_alarm_rate(normal_scores, rate)
        per_scenario = {}
        for result in attacks:
            caught = sum(any(s > threshold for s in scores)
                         for scores in result.flow_scores)
            per_scenario[result.name] = caught / result.instances
        rows.append({
            "target_false_alarm_rate": rate,
            "threshold": threshold,
            "false_alarm_rate": sum(s > threshold for s in normal_scores)
                                / len(normal_scores),
            "attacks_detected": sum(per_scenario.values()) / len(per_scenario),
            "per_scenario": per_scenario,
        })
    return rows


def run(holdout_fraction: float = DEFAULT_HOLDOUT_FRACTION,
        instances: int = DEFAULT_INSTANCES, seed: int = DEFAULT_SEED,
        model_path: str | Path | None = None,
        training_dir: str | Path | None = None) -> dict:
    pcaps = find_pcaps([training_dir or config.TRAINING_DIR])
    if not pcaps:
        raise SystemExit(f"[!] No pcaps in {training_dir or config.TRAINING_DIR}")

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        if model_path is None:
            train_files, test_files = split_by_time(pcaps, holdout_fraction)
            print(f"[*] Training a separate model on {len(train_files)} earlier "
                  f"window(s); holding out the latest {len(test_files)}")
            torch.manual_seed(seed)
            model_label = "separate model, trained on a time split"
            model_path = workdir / "metrics_model.pt"
            train_model(paths=train_files, output_path=model_path)
        else:
            model_label = str(model_path)
            trained_on = set(load_checkpoint(model_path).get("training_files", []))
            test_files = [p for p in pcaps if p.name not in trained_on]
            train_files = [p for p in pcaps if p.name in trained_on]
            if not test_files:
                raise SystemExit(
                    f"[!] {model_path} was trained on every window in the training "
                    "folder, so there is no unseen normal traffic to measure false "
                    "alarms on. Run without --model to train a separate model."
                )
        detector = LstmDetector(model_path)

        print(f"\n[*] Scoring unseen normal traffic from {len(test_files)} window(s)...")
        normal_flows, unreadable = read_flows(test_files)
        if not normal_flows:
            raise SystemExit("[!] The held-out windows contain no scorable flows")
        normal_scores = detector.score(normal_flows)

        print(f"[*] Generating and scoring {instances} instance(s) of each attack...")
        attacks = [
            measure_scenario(detector, s,
                             scenario_flows(s, instances, seed, workdir),
                             normal_scores)
            for s in ATTACK_SCENARIOS
        ]
        control = measure_scenario(
            detector, BENIGN_CONTROL,
            scenario_flows(BENIGN_CONTROL, instances, seed, workdir),
            normal_scores,
        )

    all_attack_scores = [s for r in attacks for scores in r.flow_scores for s in scores]
    false_alarms = sum(s > detector.threshold for s in normal_scores)
    return {
        "model": model_label,
        "threshold": detector.threshold,
        "seed": seed,
        "train_windows": len(train_files),
        "test_windows": len(test_files) - len(unreadable),
        "unreadable_windows": unreadable,
        "normal_flows": len(normal_flows),
        "false_alarms": false_alarms,
        "false_alarm_rate": false_alarms / len(normal_flows),
        "synthetic_benign_false_alarm_rate": control.flow_detection_rate,
        "attacks_detected": sum(r.instance_detection_rate for r in attacks) / len(attacks),
        "auc": auc(all_attack_scores, normal_scores),
        "scenarios": attacks,
        "control": control,
        "sweep": sweep(normal_scores, attacks),
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def format_summary(m: dict) -> str:
    lines = [
        "=" * 70,
        "NETSENTINEL DETECTOR METRICS",
        "=" * 70,
        f"Model:      {m['model']} (threshold {m['threshold']:.4f})",
        f"Normal set: {m['normal_flows']} flows from {m['test_windows']} unseen "
        f"window(s); model trained on {m['train_windows']}",
        "",
        f"False alarm rate (unseen normal):   {_pct(m['false_alarm_rate'])} "
        f"({m['false_alarms']}/{m['normal_flows']} flows)",
        f"False alarm rate (synthetic benign): {_pct(m['synthetic_benign_false_alarm_rate'])}",
        f"Attacks detected (avg of scenarios): {_pct(m['attacks_detected'])}",
        f"ROC AUC (attack flows vs normal):    "
        + ("n/a" if m["auc"] is None else f"{m['auc']:.3f}"),
        "",
        f"{'Scenario':<18}{'Attacks caught':>16}{'Flows flagged':>18}{'AUC':>8}",
    ]
    for r in m["scenarios"]:
        caught = f"{r.instances_detected}/{r.instances} ({_pct(r.instance_detection_rate)})"
        flagged = f"{r.flows_flagged}/{r.flows} ({_pct(r.flow_detection_rate)})"
        auc_text = "n/a" if r.auc is None else f"{r.auc:.3f}"
        lines.append(f"{r.name:<18}{caught:>16}{flagged:>18}{auc_text:>8}")

    lines += ["", "If the threshold were set for a given false alarm rate:",
              f"{'False alarms':>14}{'Attacks detected':>20}"]
    for row in m["sweep"]:
        lines.append(f"{_pct(row['false_alarm_rate']):>14}"
                     f"{_pct(row['attacks_detected']):>20}")

    lines += [
        "",
        "An attack counts as detected when any of its flows is flagged.",
        "Attacks are synthetic; a high synthetic-benign false alarm rate means",
        "the detector is reacting to the generator, so treat attack rates with care.",
        "=" * 70,
    ]
    return "\n".join(lines)


def to_json(m: dict) -> dict:
    def scenario(r: ScenarioResult) -> dict:
        d = asdict(r)
        d.pop("flow_scores")
        d["flow_detection_rate"] = r.flow_detection_rate
        d["instance_detection_rate"] = r.instance_detection_rate
        return d

    out = dict(m)
    out["scenarios"] = [scenario(r) for r in m["scenarios"]]
    out["control"] = scenario(m["control"])
    return out


def main():
    parser = argparse.ArgumentParser(description="Measure the LSTM detector")
    parser.add_argument("--holdout", type=float, default=DEFAULT_HOLDOUT_FRACTION,
                        help="fraction of the latest windows held out as unseen "
                             "normal traffic")
    parser.add_argument("--instances", type=int, default=DEFAULT_INSTANCES,
                        help="instances generated per attack scenario")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--model", default=None,
                        help="measure this checkpoint instead of training a "
                             "separate one")
    args = parser.parse_args()

    metrics = run(holdout_fraction=args.holdout, instances=args.instances,
                  seed=args.seed, model_path=args.model)
    print("\n" + format_summary(metrics))
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(to_json(metrics), indent=2))
    print(f"\n[*] Saved {RESULTS_PATH}")


if __name__ == "__main__":
    main()
