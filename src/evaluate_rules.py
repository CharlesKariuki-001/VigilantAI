"""
Vigilant AI — Month 2 / Week 1, Day 6
src/evaluate_rules.py

Runs the current RuleEngine against the full canonical dataset
(data/scam_dataset.csv) and reports:
  - Overall precision, recall, F1, false-positive rate
  - Per-category recall (which scam types the rule engine is weak on)
  - Every false positive and false negative, saved to a CSV so you can
    look at the exact messages the rules got wrong

This gives you the first real, defensible performance numbers for your
case study / Chapter 3 methodology — not estimates, actual measured numbers
against your own dataset.

Run from the project root:
    python src/evaluate_rules.py
"""

import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rule_engine import RuleEngine

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "scam_dataset.csv")
REPORT_DIR = os.path.join(PROJECT_ROOT, "docs")
MISMATCHES_PATH = os.path.join(REPORT_DIR, "rule_engine_mismatches.csv")
REPORT_PATH = os.path.join(REPORT_DIR, "rule_engine_evaluation.md")


def main():
    if not os.path.exists(DATASET_PATH):
        print(f"[STOP] No dataset found at {DATASET_PATH}.")
        print("Run scripts/build_dataset.py first to create it.")
        sys.exit(1)

    df = pd.read_csv(DATASET_PATH)
    if len(df) == 0:
        print("[STOP] Dataset is empty.")
        sys.exit(1)

    os.makedirs(REPORT_DIR, exist_ok=True)
    engine = RuleEngine()

    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0
    mismatches = []
    category_recall = {}  # category -> [caught, total]

    for _, row in df.iterrows():
        message = str(row["message_text"])
        true_label = str(row["label"]).strip().lower()
        category = str(row.get("fraud_category", "other"))

        result = engine.analyze(message)
        predicted_label = "fraud" if result["status"] == "FRAUD" else "legit"

        if true_label == "fraud":
            category_recall.setdefault(category, [0, 0])
            category_recall[category][1] += 1
            if predicted_label == "fraud":
                category_recall[category][0] += 1

        if true_label == "fraud" and predicted_label == "fraud":
            true_positive += 1
        elif true_label == "legit" and predicted_label == "fraud":
            false_positive += 1
            mismatches.append({
                "error_type": "FALSE_POSITIVE (flagged a real message as fraud)",
                "message_text": message,
                "true_label": true_label,
                "fraud_category": category,
                "triggered_rules": "; ".join(r["name"] for r in result["triggered_rules"]),
            })
        elif true_label == "legit" and predicted_label == "legit":
            true_negative += 1
        elif true_label == "fraud" and predicted_label == "legit":
            false_negative += 1
            mismatches.append({
                "error_type": "FALSE_NEGATIVE (missed a real scam)",
                "message_text": message,
                "true_label": true_label,
                "fraud_category": category,
                "triggered_rules": "",
            })

    total = true_positive + false_positive + true_negative + false_negative
    precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else 0
    recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = false_positive / (false_positive + true_negative) if (false_positive + true_negative) else 0
    accuracy = (true_positive + true_negative) / total if total else 0

    # --- Print to console ---
    print("=" * 70)
    print(f"VIGILANT AI — Rule Engine Evaluation  ({len(engine.rules)} rules)")
    print(f"Dataset: {len(df)} messages ({(df['label']=='fraud').sum()} fraud / "
          f"{(df['label']=='legit').sum()} legit)")
    print("=" * 70)
    print(f"Precision        : {precision:.1%}   (target: > 90%)")
    print(f"Recall           : {recall:.1%}   (target: > 85%)")
    print(f"F1 score         : {f1:.1%}")
    print(f"False Positive Rate : {fpr:.1%}   (target: < 5%)")
    print(f"Accuracy         : {accuracy:.1%}")
    print(f"\nConfusion matrix: TP={true_positive}  FP={false_positive}  TN={true_negative}  FN={false_negative}")

    print("\nRecall by fraud category (lowest first — these need new/better rules):")
    cat_rows = []
    for cat, (caught, tot) in category_recall.items():
        cat_recall = caught / tot if tot else 0
        cat_rows.append((cat, caught, tot, cat_recall))
    cat_rows.sort(key=lambda r: r[3])
    for cat, caught, tot, cat_recall in cat_rows:
        flag = "  <-- WEAK" if cat_recall < 0.7 else ""
        print(f"  {cat:35s} {caught:4d}/{tot:<4d} ({cat_recall:.0%}){flag}")

    # --- Save mismatches CSV ---
    if mismatches:
        pd.DataFrame(mismatches).to_csv(MISMATCHES_PATH, index=False)
        print(f"\nSaved {len(mismatches)} mismatches to {MISMATCHES_PATH}")
        print("Review these first in Week 2 — every false negative is a rule you need to add,")
        print("every false positive is a rule that's too broad.")

    # --- Save markdown report ---
    with open(REPORT_PATH, "w") as f:
        f.write("# Vigilant AI — Rule Engine Evaluation Report\n\n")
        f.write(f"Generated by `src/evaluate_rules.py` against {len(df)} labeled messages "
                f"({len(engine.rules)} active rules).\n\n")
        f.write("## Headline metrics\n\n")
        f.write("| Metric | Value | Target (from project spec) |\n|---|---|---|\n")
        f.write(f"| Precision | {precision:.1%} | > 90% |\n")
        f.write(f"| Recall | {recall:.1%} | > 85% |\n")
        f.write(f"| F1 score | {f1:.1%} | - |\n")
        f.write(f"| False Positive Rate | {fpr:.1%} | < 5% |\n")
        f.write(f"| Accuracy | {accuracy:.1%} | - |\n\n")
        f.write(f"Confusion matrix: TP={true_positive}, FP={false_positive}, "
                f"TN={true_negative}, FN={false_negative}\n\n")
        f.write("## Recall by fraud category\n\n")
        f.write("| Category | Caught | Total | Recall |\n|---|---|---|---|\n")
        for cat, caught, tot, cat_recall in cat_rows:
            f.write(f"| {cat} | {caught} | {tot} | {cat_recall:.0%} |\n")
        f.write(f"\nSee `rule_engine_mismatches.csv` for every individual false "
                f"positive/negative.\n")

    print(f"\nFull report written to {REPORT_PATH}")
    print("=" * 70)


if __name__ == "__main__":
    main()