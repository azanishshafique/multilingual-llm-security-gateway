"""
run_evaluation.py
-----------------
Runs the gateway pipeline against data/final_eval.csv and produces:
  - results/evaluation_results.csv
  - results/metrics_summary.json

Usage:
    python run_evaluation.py
    python run_evaluation.py --mode rule_only   # baseline comparison
    python run_evaluation.py --mode hybrid      # default
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.detectors.rule_detector import rule_detect
from app.detectors.semantic_detector import semantic_detect, warm_up
from app.pii.presidio_custom import analyze_pii
from app.policy.policy_engine import compute_policy, prepare_output
from app.utils.language import detect_language, is_mixed_language

DATA_PATH = "data/final_eval.csv"
RESULTS_DIR = "results"


def run_pipeline_local(text: str, mode: str = "hybrid") -> Dict[str, Any]:
    t0 = time.perf_counter()

    language = detect_language(text)
    mixed = is_mixed_language(text)
    rule_score, rule_reasons = rule_detect(text)

    if mode == "hybrid":
        semantic_score, semantic_reasons = semantic_detect(text)
    else:
        semantic_score, semantic_reasons = 0.0, []

    pii_result = analyze_pii(text)

    final_risk, decision, all_reasons = compute_policy(
        rule_score=rule_score,
        semantic_score=semantic_score,
        pii_result=pii_result,
        rule_reasons=rule_reasons,
        semantic_reasons=semantic_reasons,
        language=language,
        is_mixed=mixed,
    )

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "language": language,
        "rule_score": rule_score,
        "semantic_score": semantic_score,
        "pii_risk": pii_result["pii_risk"],
        "final_risk": final_risk,
        "decision": decision,
        "reason_codes": all_reasons,
        "latency_ms": latency_ms,
    }


def compute_metrics(tp, fp, tn, fn) -> Dict[str, float]:
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="hybrid", choices=["hybrid", "rule_only"])
    parser.add_argument("--data", default=DATA_PATH)
    args = parser.parse_args()

    print(f"\n[Evaluation] Mode: {args.mode} | Dataset: {args.data}")
    print("Warming up models...")
    warm_up()

    os.makedirs(RESULTS_DIR, exist_ok=True)

    rows = []
    with open(args.data, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    print(f"Loaded {len(rows)} samples. Running pipeline...\n")

    results = []
    latencies = []
    per_lang: Dict[str, Dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})

    # For binary classification: BLOCK = attack, ALLOW/MASK = not-attack
    tp = fp = tn = fn = 0

    for row in rows:
        expected = row["expected_policy"].strip().upper()
        text = row["prompt"].strip()
        lang_label = row.get("language", "en")

        result = run_pipeline_local(text, mode=args.mode)
        predicted = result["decision"].upper()

        # Binary: BLOCK vs non-BLOCK
        expected_bin = "BLOCK" if expected == "BLOCK" else "NOTBLOCK"
        predicted_bin = "BLOCK" if predicted == "BLOCK" else "NOTBLOCK"

        correct = (expected == predicted or
                   (expected in ("ALLOW", "MASK") and predicted in ("ALLOW", "MASK")))

        if expected_bin == "BLOCK" and predicted_bin == "BLOCK":
            tp += 1
            per_lang[lang_label]["tp"] += 1
        elif expected_bin != "BLOCK" and predicted_bin == "BLOCK":
            fp += 1
            per_lang[lang_label]["fp"] += 1
        elif expected_bin != "BLOCK" and predicted_bin != "BLOCK":
            tn += 1
            per_lang[lang_label]["tn"] += 1
        else:
            fn += 1
            per_lang[lang_label]["fn"] += 1

        latencies.append(result["latency_ms"])

        results.append({
            "id": row["id"],
            "prompt": text[:80],
            "language": lang_label,
            "attack_type": row.get("attack_type", ""),
            "expected": expected,
            "predicted": predicted,
            "correct": correct,
            "rule_score": result["rule_score"],
            "semantic_score": result["semantic_score"],
            "final_risk": result["final_risk"],
            "reason_codes": "|".join(result["reason_codes"]),
            "latency_ms": result["latency_ms"],
        })

    # Write results CSV
    out_csv = f"{RESULTS_DIR}/evaluation_results_{args.mode}.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # Compute overall metrics
    overall = compute_metrics(tp, fp, tn, fn)

    # Per-language metrics
    lang_metrics = {}
    for lang, counts in per_lang.items():
        lang_metrics[lang] = compute_metrics(
            counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        )

    # Latency stats
    lat_sorted = sorted(latencies)
    latency_stats = {
        "mean_ms": round(sum(latencies) / len(latencies), 2),
        "median_ms": round(lat_sorted[len(lat_sorted) // 2], 2),
        "p95_ms": round(lat_sorted[int(len(lat_sorted) * 0.95)], 2),
        "min_ms": round(min(latencies), 2),
        "max_ms": round(max(latencies), 2),
    }

    summary = {
        "mode": args.mode,
        "total_samples": len(rows),
        "overall_metrics": overall,
        "per_language_metrics": lang_metrics,
        "latency_stats": latency_stats,
    }

    summary_path = f"{RESULTS_DIR}/metrics_summary_{args.mode}.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # Print report
    print("=" * 60)
    print(f"EVALUATION RESULTS [{args.mode.upper()}]")
    print("=" * 60)
    print(f"Total Samples : {len(rows)}")
    print(f"Accuracy      : {overall['accuracy']:.4f}")
    print(f"Precision     : {overall['precision']:.4f}")
    print(f"Recall        : {overall['recall']:.4f}")
    print(f"F1 Score      : {overall['f1']:.4f}")
    print(f"TP={overall['true_positives']}  FP={overall['false_positives']}  "
          f"TN={overall['true_negatives']}  FN={overall['false_negatives']}")
    print()
    print("Per-language breakdown:")
    for lang, m in lang_metrics.items():
        print(f"  {lang:6s}  Recall={m['recall']:.2f}  F1={m['f1']:.2f}  "
              f"TP={m['true_positives']}  FP={m['false_positives']}  FN={m['false_negatives']}")
    print()
    print(f"Latency: mean={latency_stats['mean_ms']}ms  "
          f"median={latency_stats['median_ms']}ms  "
          f"p95={latency_stats['p95_ms']}ms")
    print()
    print(f"Results saved: {out_csv}")
    print(f"Summary saved: {summary_path}")


if __name__ == "__main__":
    main()
