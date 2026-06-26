# Vigilant AI — Model Card

**Generated:** 2026-06-26 23:10:05
**Model trained at:** 2026-06-26T23:09:51
**Model type:** XGBClassifier

## Project Context

Vigilant AI is a **hybrid fraud detection system** built for East Africa (Kenya, Tanzania, Uganda).
It protects everyday users from M-Pesa and mobile money scams using:

- **Layer 1**: Rule Engine (high precision, fully explainable)
- **Layer 2**: XGBoost ML Model (high recall, catches new patterns)
- **Layer 3**: SHAP Explainability (transparent "why" for every prediction)

## Training Data

| Property                  | Value                                                   |
|---------------------------|---------------------------------------------------------|
| Total messages            | 2094                       |
| Fraud messages            | 1204                        |
| Legit messages            | 890                        |
| Languages                 | English, Swahili, Sheng                                 |
| Data sources              | Synthetic batches + real patterns + community feedback  |

## Features

- Word-level TF-IDF (1-2 grams)
- Character-level TF-IDF (3-5 grams) — important for Swahili/Sheng
- Rule Engine binary flags (67+ rules)
- Structural features (length, digit ratio, punctuation, phone/link presence)

**Total features:** 6574

## Performance (Held-Out Test Set)

| Metric                    | Value                                        | Target | Status                              |
|---------------------------|----------------------------------------------|--------|-------------------------------------|
| Precision                 | 99.6%                  | > 90%  | ✅  |
| Recall                    | 99.6%                     | > 85%  | ✅     |
| F1 Score                  | 99.6%                         | -      | -                                   |
| False Positive Rate       | 0.6%        | < 5%   | ✅ |
| Accuracy                  | 99.5%                   | -      | -                                   |

**Decision threshold:** 0.5

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
