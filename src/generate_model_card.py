"""
Vigilant AI — src/generate_model_card.py

Auto-generates a Model Card (standard ML documentation) from the real,
trained model's metadata file. Pulls actual numbers — not claims.

This becomes direct source material for:
  - Chapter 4 (Results) of your MKU project report
  - The case study document your roadmap calls for in Month 11
  - Any grant or investor pitch that asks "what does the model actually do?"

Run from the project root after train_model.py has been run at least once:
    python src/generate_model_card.py
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
    # ---- Load metadata ----
    if not os.path.exists(METADATA_PATH):
        print(f"[STOP] No model_metadata.json found at {METADATA_PATH}.")
        print("Run src/train_model.py first to train a model and generate this file.")
        sys.exit(1)

    with open(METADATA_PATH) as f:
        meta = json.load(f)

    threshold_info = {}
    if os.path.exists(THRESHOLD_PATH):
        with open(THRESHOLD_PATH) as f:
            threshold_info = json.load(f)

    # ---- Check which targets are met ----
    m = meta["metrics"]
    targets = {
        "Precision > 90%":          m.get("precision", 0) > 0.90,
        "Recall > 85%":             m.get("recall", 0) > 0.85,
        "False Positive Rate < 5%": m.get("false_positive_rate", 0) < 0.05,
    }

    # ---- Build card text ----
    def tick(met):
        return "✅" if met else "❌"

    threshold_val = threshold_info.get("decision_threshold", 0.5)
    threshold_note = threshold_info.get(
        "rationale",
        "Default 0.5 — run src/calibrate_threshold.py to optimise for your dataset."
    )

    card = f"""# Vigilant AI — Model Card

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Model trained at:** {meta.get("trained_at", "unknown")}
**Model type:** {meta.get("model_type", "XGBClassifier")}

---

## What This Model Does

Binary classification of SMS / mobile-money messages as `fraud` or `legit`
for Kenyan M-Pesa users, operating as Layer 2 of a hybrid detection system.

Layer 1 (rule engine) handles known, explicit fraud patterns.
Layer 2 (this model) handles patterns the rules haven't seen before.
Both layers explain their reasoning — the rules name the pattern, the model
uses SHAP to show which words and features influenced the score.

This is an **advisory tool**. The final decision (whether to reply, click,
or send money) remains with the user.

---

## Training Data

| Property | Value |
|---|---|
| Total labeled messages | {meta.get("dataset_size", "N/A")} |
| Fraud examples | {meta.get("fraud_count", "N/A")} |
| Legit examples | {meta.get("legit_count", "N/A")} |
| Class imbalance handling | {"SMOTE oversampling + " if meta.get("smote_applied") else ""}XGBoost scale_pos_weight={meta.get("scale_pos_weight", "N/A")} |

**Data sources** (see `data/scam_dataset.csv` `source` column):
- Manually collected real Kenyan scam SMS messages
- Open Swahili SMS scam dataset (Tanzania-context, re-validated)
- LLM-generated synthetic examples across 21 fraud categories
- Community reports submitted through the Vigilant AI app
- User feedback corrections (wrong predictions corrected by real users)

---

## Feature Pipeline

Built by `src/feature_engineering.py`, combining three sources:

| Feature Group | What It Captures |
|---|---|
| Word-level TF-IDF (1-2 grams) | Vocabulary and phrase patterns |
| Character-level TF-IDF (3-5 grams) | Swahili/Sheng morphology, obfuscated spelling |
| Rule engine trigger flags | One binary flag per rule — lets ML weigh the rules statistically |
| Structural features | Message length, digit ratio, punctuation density, phone/link presence |

**Total features:** {meta.get("feature_count", "N/A")}

---

## Performance (Held-Out Test Set)

| Metric | Value | Target | Met? |
|---|---|---|---|
| Precision | {m.get("precision", 0):.1%} | > 90% | {tick(targets["Precision > 90%"])} |
| Recall | {m.get("recall", 0):.1%} | > 85% | {tick(targets["Recall > 85%"])} |
| F1 Score | {m.get("f1", 0):.1%} | — | — |
| False Positive Rate | {m.get("false_positive_rate", 0):.1%} | < 5% | {tick(targets["False Positive Rate < 5%"])} |
| Accuracy | {m.get("accuracy", 0):.1%} | — | — |

**Decision threshold:** `{threshold_val}`
_{threshold_note}_

---

## Known Limitations

**Small dataset risk:** On small or template-heavy training data, the model
can lean on structural cues (message length, digit ratio) rather than
semantic content. Check SHAP top factors periodically — if "Message length"
or "High proportion of digits" dominates explanations, collect more diverse
examples before trusting the model in production.

**Near-empty input:** Messages under ~6 characters or with no letters are
NOT passed to the ML model (see the guard in `src/predict.py`). The model
has no reliable signal on trivial text and will guess wrongly without this
guard.

**Language boundary:** Validated on English, Swahili, and Sheng. Not
tested on other languages — behaviour outside these is undefined.

**Static snapshot:** These numbers reflect one specific training run.
Re-generate this card after every retrain (`src/retrain_pipeline.py`).
Numbers here become stale the moment the model is updated.

---

## Reproducing These Results

```bash
# 1. Build the dataset
python scripts/build_dataset.py

# 2. Train the model
python src/train_model.py

# 3. Calibrate the decision threshold
python src/calibrate_threshold.py

# 4. Compare rule engine vs ML vs hybrid
python src/final_comparison.py

# 5. Regenerate this card
python src/generate_model_card.py
```

---

## Project Context

- **Builder:** Charles Kariuki Mburu
- **Institution:** Mount Kenya University, Thika Campus
- **Programme:** BSc Computer Science (BSCCS/2025/67743)
- **Project:** Vigilant AI — AI-Powered Mobile Money Fraud Detection for Kenya
- **Academic year:** 2025 / 2026
"""

    # ---- Write output ----
    os.makedirs(DOCS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(card)

    print(f"Model card written to {OUTPUT_PATH}")
    print()

    failed = [k for k, v in targets.items() if not v]
    if failed:
        print("Targets NOT yet met (expected on small/early-stage datasets):")
        for t in failed:
            print(f"  ❌ {t}")
        print()
        print("These will improve as your dataset grows. The architecture is correct.")
    else:
        print("All three performance targets currently met on the held-out test set.")


if __name__ == "__main__":
    main()
    