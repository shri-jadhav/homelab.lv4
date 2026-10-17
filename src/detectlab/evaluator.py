"""Detection evaluation module for benchmark datasets and confusion matrix metrics."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine import DetectionEngine
from .ingest import load_events_from_jsonl
from .models import SecurityEvent
from .rules import DetectionConfig


@dataclass
class ScenarioEvaluation:
    """Evaluation result for an individual labeled telemetry scenario."""
    scenario_id: str
    description: str
    is_malicious: bool
    expected_rules: list[str]
    actual_rules: list[str]
    status: str  # 'TP', 'TN', 'FP', 'FN'
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "description": self.description,
            "is_malicious": self.is_malicious,
            "expected_rules": self.expected_rules,
            "actual_rules": self.actual_rules,
            "status": self.status,
            "notes": self.notes,
        }


def evaluate_dataset(
    dataset_path: Path | str,
    ground_truth_path: Path | str,
    config: DetectionConfig | None = None,
) -> dict[str, Any]:
    """Run detection evaluation against a labeled synthetic benchmark dataset."""
    cfg = config or DetectionConfig()
    dataset_file = Path(dataset_path)
    gt_file = Path(ground_truth_path)

    # 1. Load ground truth
    ground_truth_data = json.loads(gt_file.read_text(encoding="utf-8"))
    gt_by_id = {item["scenario_id"]: item for item in ground_truth_data}

    # 2. Load events
    events, ingest_report = load_events_from_jsonl(dataset_file, strict=False)

    # Group events by scenario_id
    events_by_scenario: dict[str, list[SecurityEvent]] = {sid: [] for sid in gt_by_id}
    for e in events:
        scenario_id = e.extra.get("scenario_id")
        if scenario_id and scenario_id in events_by_scenario:
            events_by_scenario[scenario_id].append(e)

    # 3. Evaluate each scenario in isolation
    engine = DetectionEngine(config=cfg)
    scenario_results: list[ScenarioEvaluation] = []

    tp_count = 0
    tn_count = 0
    fp_count = 0
    fn_count = 0

    per_rule_stats: dict[str, dict[str, int]] = {}

    for sid, gt in gt_by_id.items():
        scen_events = events_by_scenario.get(sid, [])
        alerts = engine.run(scen_events)
        actual_rules = sorted({a.rule_id for a in alerts})
        expected_rules = sorted(gt.get("expected_rules", []))
        is_mal = gt.get("is_malicious", False)

        # Track per-rule expectations
        for r in expected_rules:
            stats = per_rule_stats.setdefault(r, {"expected": 0, "detected": 0, "tp": 0, "fn": 0, "fp": 0})
            stats["expected"] += 1
            if r in actual_rules:
                stats["detected"] += 1
                stats["tp"] += 1
            else:
                stats["fn"] += 1

        for r in actual_rules:
            if r not in expected_rules:
                stats = per_rule_stats.setdefault(r, {"expected": 0, "detected": 0, "tp": 0, "fn": 0, "fp": 0})
                stats["detected"] += 1
                stats["fp"] += 1

        # Scenario-level classification
        if is_mal:
            # Expected positive scenario
            if set(expected_rules).issubset(set(actual_rules)) and not (set(actual_rules) - set(expected_rules)):
                status = "TP"
                tp_count += 1
                notes = "All expected detections fired without extraneous alerts."
            elif any(r in actual_rules for r in expected_rules):
                status = "PARTIAL_TP"
                tp_count += 1
                notes = f"Partial trigger: expected {expected_rules}, got {actual_rules}."
            else:
                status = "FN"
                fn_count += 1
                notes = f"Missed detection: expected {expected_rules}, got {actual_rules}."
        else:
            # Expected negative scenario (benign control)
            if not actual_rules:
                status = "TN"
                tn_count += 1
                notes = "Benign control correctly suppressed (zero alerts)."
            else:
                status = "FP"
                fp_count += 1
                notes = f"False positive: benign scenario triggered {actual_rules}."

        scenario_results.append(
            ScenarioEvaluation(
                scenario_id=sid,
                description=gt["description"],
                is_malicious=is_mal,
                expected_rules=expected_rules,
                actual_rules=actual_rules,
                status=status,
                notes=notes,
            )
        )

    # 4. Calculate global evaluation metrics
    total_scenarios = len(scenario_results)
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = (tp_count + tn_count) / total_scenarios if total_scenarios > 0 else 0.0
    specificity = tn_count / (tn_count + fp_count) if (tn_count + fp_count) > 0 else 0.0

    report = {
        "dataset": str(dataset_file),
        "ground_truth": str(gt_file),
        "total_scenarios": total_scenarios,
        "confusion_matrix": {
            "true_positives": tp_count,
            "true_negatives": tn_count,
            "false_positives": fp_count,
            "false_negatives": fn_count,
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "specificity": round(specificity, 4),
        },
        "per_rule_performance": per_rule_stats,
        "scenarios": [s.to_dict() for s in scenario_results],
        "limitations_and_disclaimer": (
            "These metrics evaluate detection logic against controlled, synthetic scenarios. "
            "In production SIEM environments, real-world noise, high event velocity, network address translation (NAT), "
            "and unpredictable human behavior will result in lower precision and require environment-specific baseline tuning. "
            "Do not cite benchmark test scores as guaranteed production detection rates."
        ),
    }
    return report
