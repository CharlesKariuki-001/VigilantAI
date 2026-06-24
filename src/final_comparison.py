"""
Vigilant AI — Final Comparison (Month 3 Week 4)
Compares Rule Engine vs ML vs Hybrid on the same test set.
"""

import os
import sys
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rule_engine import RuleEngine
from feature_engineering import FeatureBuilder
from predict import HybridDetector

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "scam_dataset.csv")
REPORT_PATH = os.path.join(PROJECT_ROOT, "docs", "final_comparison.md")


def main():
    df = pd.read_csv(DATASET_PATH).dropna(subset=["message_text", "label"])
    df = df.drop_duplicates(subset=["message_text"])

    X_text = df["message_text"].astype(str).to_numpy(dtype=object)
    y = (df["label"] == "fraud").astype(int).to_numpy()

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Evaluating on {len(X_test_text)} test messages\n")

    results = {}

    # Rule Engine Alone
    print("Evaluating Rule Engine...")
    engine = RuleEngine()
    y_pred_rules = [1 if engine.analyze(msg)["status"] == "FRAUD" else 0 for msg in X_test_text]
    results["Rule Engine"] = {
        "Precision": precision_score(y_test, y_pred_rules, zero_division=0),
        "Recall": recall_score(y_test, y_pred_rules, zero_division=0),
        "F1": f1_score(y_test, y_pred_rules, zero_division=0),
    }

    # ML Alone
    print("Evaluating ML Model...")
    fb = FeatureBuilder()
    X_train = fb.fit_transform(X_train_text)
    X_test = fb.transform(X_test_text)

    model = joblib.load(os.path.join(PROJECT_ROOT, "models", "vigilant_model.pkl"))
    y_pred_ml = model.predict(X_test)
    results["ML Model"] = {
        "Precision": precision_score(y_test, y_pred_ml, zero_division=0),
        "Recall": recall_score(y_test, y_pred_ml, zero_division=0),
        "F1": f1_score(y_test, y_pred_ml, zero_division=0),
    }

    # Hybrid
    print("Evaluating Hybrid...")
    detector = HybridDetector()
    y_pred_hybrid = []
    for msg in X_test_text:
        res = detector.predict(msg)
        y_pred_hybrid.append(1 if res["status"] == "FRAUD" else 0)

    results["Hybrid (Rules + ML)"] = {
        "Precision": precision_score(y_test, y_pred_hybrid, zero_division=0),
        "Recall": recall_score(y_test, y_pred_hybrid, zero_division=0),
        "F1": f1_score(y_test, y_pred_hybrid, zero_division=0),
    }

    df_results = pd.DataFrame(results).T
    print("\n" + "="*70)
    print("FINAL COMPARISON")
    print("="*70)
    print(df_results.round(3).to_string())

    # Save report
    with open(REPORT_PATH, "w") as f:
        f.write("# Final System Comparison\n\n")
        f.write(f"Test set size: {len(X_test_text)} messages\n\n")
        f.write(df_results.to_markdown(floatfmt=".1%"))

    print(f"\nReport saved to {REPORT_PATH}")


if __name__ == "__main__":
    main()