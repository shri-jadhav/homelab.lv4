"""Command line interface for the SOC Detection Engineering Lab."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import DetectionEngine
from .ingest import load_events_from_jsonl
from .io import write_outputs
from .rules import DetectionConfig


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SOC Detection Engineering Lab: Replay telemetry, detect threats, and generate reports.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/events.jsonl"),
        help="Path to JSON Lines telemetry file (default: data/events.jsonl)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("artifacts"),
        help="Directory for generated reports (default: artifacts)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional path to JSON file overriding rule thresholds and windows",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail fast on any malformed JSON line, missing field, or duplicate event ID",
    )
    parser.add_argument(
        "--wazuh-alerts",
        type=Path,
        default=None,
        help="Optional path to Wazuh alerts.json file to ingest and correlate genuine SIEM telemetry",
    )
    parser.add_argument(
        "--eval",
        action="store_true",
        help="Run detection evaluation benchmark against labeled test scenarios",
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=Path("data/eval_ground_truth.json"),
        help="Path to ground truth labels JSON file (used with --eval)",
    )
    args = parser.parse_args()

    # Load configuration if provided
    config = DetectionConfig()
    if args.config:
        try:
            cfg_dict = json.loads(args.config.read_text(encoding="utf-8"))
            config = DetectionConfig.from_dict(cfg_dict)
        except Exception as exc:
            parser.error(f"Error loading config from {args.config}: {exc}")

    # Handle evaluation mode
    if args.eval:
        from .evaluator import evaluate_dataset
        dataset_path = args.input if args.input != Path("data/events.jsonl") else Path("data/eval_scenarios.jsonl")
        try:
            eval_report = evaluate_dataset(
                dataset_path=dataset_path,
                ground_truth_path=args.ground_truth,
                config=config,
            )
            args.out.mkdir(parents=True, exist_ok=True)
            eval_out_path = args.out / "evaluation_report.json"
            eval_out_path.write_text(json.dumps(eval_report, indent=2), encoding="utf-8")
        except Exception as exc:
            parser.error(f"Evaluation error: {exc}")

        cm = eval_report["confusion_matrix"]
        m = eval_report["metrics"]
        print("=" * 60)
        print("  SOC DETECTION EVALUATION BENCHMARK REPORT")
        print("=" * 60)
        print(f"Scenarios Evaluated   : {eval_report['total_scenarios']}")
        print(f"True Positives  (TP)  : {cm['true_positives']}")
        print(f"True Negatives  (TN)  : {cm['true_negatives']}")
        print(f"False Positives (FP)  : {cm['false_positives']}")
        print(f"False Negatives (FN)  : {cm['false_negatives']}")
        print("-" * 60)
        print(f"Precision             : {m['precision']:.2%}")
        print(f"Recall (Sensitivity)  : {m['recall']:.2%}")
        print(f"F1-Score              : {m['f1_score']:.2%}")
        print(f"Specificity           : {m['specificity']:.2%}")
        print(f"Accuracy              : {m['accuracy']:.2%}")
        print("-" * 60)
        print(f"Detailed Report JSON  : {eval_out_path.resolve()}")
        print("=" * 60)
        return 0

    try:
        if args.wazuh_alerts:
            from .wazuh_adapter import load_wazuh_alerts
            events, ingest_report = load_wazuh_alerts(args.wazuh_alerts, strict=args.strict)
            data_source = "wazuh_siem"
        else:
            events, ingest_report = load_events_from_jsonl(args.input, strict=args.strict)
            data_source = "synthetic_jsonl"

        engine = DetectionEngine(config=config)
        alert_objects = engine.run(events)
        alerts = [a.to_dict() for a in alert_objects]

        write_outputs(
            alerts=alerts,
            event_count=len(events),
            out_dir=args.out,
            events=events,
            ingest_report=ingest_report,
            data_source=data_source,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print("=" * 60)
    print("  SOC DETECTION ENGINEERING LAB - RUN SUMMARY")
    print("=" * 60)
    print(f"Total Lines Processed : {ingest_report.total_lines}")
    print(f"Valid Events Ingested : {len(events)}")
    if ingest_report.quarantined_events > 0:
        print(f"Quarantined Records   : {ingest_report.quarantined_events} (Duplicates: {ingest_report.duplicate_events})")
    print(f"Alerts Generated      : {len(alerts)}")

    sev_counts = {s: sum(1 for a in alerts if a["severity"] == s) for s in ["critical", "high", "medium", "low"]}
    sev_str = ", ".join(f"{s.upper()}: {c}" for s, c in sev_counts.items() if c > 0)
    print(f"Severity Breakdown    : {sev_str or 'None'}")
    print("-" * 60)
    print(f"HTML Dashboard Report : {(args.out / 'report.html').resolve()}")
    print(f"Correlated Incidents  : {(args.out / 'incidents.json').resolve()}")
    print(f"JSON Alerts           : {(args.out / 'alerts.json').resolve()}")
    print(f"CSV Export            : {(args.out / 'alerts.csv').resolve()}")
    print(f"Execution Summary     : {(args.out / 'summary.json').resolve()}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
