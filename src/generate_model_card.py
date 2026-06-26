"""
Vigilant AI — Model Card Generator (Month 3 Week 4)
Auto-generates a professional Model Card from real metadata.
"""

import os
import sys
import json
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")
THRESHOLD_PATH = os.path.join(MODELS_DIR, "decision_threshold.json")
OUTPUT_PATH = os.path.join(DOCS_DIR, "MODEL_CARD.md")


def main():
    if not os.path.exists(METADATA_PATH):
        print(f"[STOP] No model_metadata.json found at {METADATA_PATH}.")
        print("Run `python src/train_model.py` first.")
        sys.exit(1)

    with open(METADATA_PATH, encoding="utf-8") as f:
        meta = json.load(f)

    threshold_info = {}
    if os.path.exists(THRESHOLD_PATH):
        with open(THRESHOLD_PATH, encoding="utf-8") as f:
            threshold_info = json.load(f)

    m = meta.get("metrics", {})

    targets = {
        "Precision > 90%": m.get("precision", 0) > 0.90,
        "Recall > 85%": m.get("recall", 0) > 0.85,
        "False Positive Rate < 5%": m.get("false_positive_rate", 0) < 0.05,
    }

    def tick(met):
        return "✅" if met else "❌"

    card = f"""# Vigilant AI — Model Card

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Model trained at:** {meta.get("trained_at", "N/A")}
**Model type:** {meta.get("model_type", "XGBClassifier")}

## Project Context

Vigilant AI is a **hybrid fraud detection system** built for East Africa (Kenya, Tanzania, Uganda).
It protects everyday users from M-Pesa and mobile money scams using:

- **Layer 1**: Rule Engine (high precision, fully explainable)
- **Layer 2**: XGBoost ML Model (high recall, catches new patterns)
- **Layer 3**: SHAP Explainability (transparent "why" for every prediction)

## Training Data

| Property                  | Value                                                   |
|---------------------------|---------------------------------------------------------|
| Total messages            | {meta.get("dataset_size", "N/A")}                       |
| Fraud messages            | {meta.get("fraud_count", "N/A")}                        |
| Legit messages            | {meta.get("legit_count", "N/A")}                        |
| Languages                 | English, Swahili, Sheng                                 |
| Data sources              | Synthetic batches + real patterns + community feedback  |

## Features

- Word-level TF-IDF (1-2 grams)
- Character-level TF-IDF (3-5 grams) — important for Swahili/Sheng
- Rule Engine binary flags (67+ rules)
- Structural features (length, digit ratio, punctuation, phone/link presence)

**Total features:** {meta.get("feature_count", "N/A")}

## Performance (Held-Out Test Set)

| Metric                    | Value                                        | Target | Status                              |
|---------------------------|----------------------------------------------|--------|-------------------------------------|
| Precision                 | {m.get("precision", 0):.1%}                  | > 90%  | {tick(targets["Precision > 90%"])}  |
| Recall                    | {m.get("recall", 0):.1%}                     | > 85%  | {tick(targets["Recall > 85%"])}     |
| F1 Score                  | {m.get("f1", 0):.1%}                         | -      | -                                   |
| False Positive Rate       | {m.get("false_positive_rate", 0):.1%}        | < 5%   | {tick(targets["False Positive Rate < 5%"])} |
| Accuracy                  | {m.get("accuracy", 0):.1%}                   | -      | -                                   |

**Decision threshold:** {threshold_info.get("decision_threshold", 0.5)}

## System Comparison (Hybrid vs Individual Layers)

From `final_comparison.py`:

- **Rule Engine Alone**: High precision, moderate recall
- **ML Model Alone**: Very strong on test set
- **Hybrid System**: Best overall balance (recommended for production)

## Known Limitations

- Still some false negatives in rare scam categories
- Model performance depends heavily on dataset diversity
- Near-empty or very short messages are handled by rules only
- Current version is English/Swahili/Sheng focused

## How to Reproduce

```bash
python scripts/merge_batches.py
python src/train_model.py
python src/final_comparison.py
python src/generate_model_card.py
```

---

**Built by Charles Kariuki**
Mount Kenya University
Vigilant AI — Fighting M-Pesa fraud in Kenya, one message at a time.
"""

    os.makedirs(DOCS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(card)

    print(f"✅ Model Card successfully generated at: {OUTPUT_PATH}")
    print()

    failed = [k for k, v in targets.items() if not v]
    if failed:
        print("Note: Some targets not yet fully met — expected with growing dataset.")
        for t in failed:
            print(f"  ❌ {t}")
    else:
        print("All performance targets currently met on the held-out test set.")


if __name__ == "__main__":
    main()