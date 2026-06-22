"""
Vigilant AI — Month 3
src/predict.py

Combines Rule Engine + ML Model + SHAP Explainability for real-time prediction.
"""

import os
import sys
import joblib
import shap
import numpy as np

# ------------------------------------------------------------------
# Module-path fix for unpickling.
#
# The trained model (.pkl files) was created by running training code
# directly inside src/ (e.g. `python feature_engineering.py`), so the
# pickled FeatureBuilder's class is recorded under the BARE module name
# `feature_engineering`, not `src.feature_engineering`. Adding this
# directory to sys.path makes both bare and package-qualified names work,
# so unpickling succeeds regardless of how the model was originally saved.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from src.feature_engineering import FeatureBuilder
from src.rule_engine import RuleEngine

# ------------------------------------------------------------------
# Load model artifacts once at import time (not per-request)
# ------------------------------------------------------------------
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

model = joblib.load(os.path.join(MODELS_DIR, "vigilant_model.pkl"))
feature_builder = joblib.load(os.path.join(MODELS_DIR, "feature_builder.pkl"))

rule_engine = RuleEngine()

# TreeExplainer is created once — rebuilding it per-request is unnecessary overhead.
_explainer = shap.TreeExplainer(model)


def _confidence_from_probability(proba: float) -> str:
    """Map a 0-1 fraud probability to a human-readable confidence label."""
    if proba >= 0.85 or proba <= 0.15:
        return "HIGH"
    if proba >= 0.65 or proba <= 0.35:
        return "MEDIUM"
    return "LOW"


def _extract_single_row_shap(shap_values, row_index: int = 0):
    """
    Normalize TreeExplainer output across shap/xgboost versions.

    Returns a 1D array of per-feature SHAP values for the positive
    ("fraud") class, for the single row at `row_index`.
    """
    # Case 1: list of per-class arrays → [array(n_samples, n_features), ...]
    if isinstance(shap_values, list):
        positive_class_values = shap_values[-1]
        return np.asarray(positive_class_values)[row_index]

    shap_array = np.asarray(shap_values)

    # Case 2: 3D array (n_samples, n_features, n_classes) — newer shap versions
    if shap_array.ndim == 3:
        return shap_array[row_index, :, -1]

    # Case 3: standard 2D array (n_samples, n_features) — binary model, single output
    return shap_array[row_index]


def _clean_feature_name(name: str) -> str | None:
    """
    Convert raw internal feature names into human-readable labels.

    Strips type prefixes (word::, char::, rule::, tfidf::) and maps known
    structural feature names to plain English descriptions.

    Returns None for names that are still noisy/cryptic after cleaning,
    so callers can skip them entirely.
    """
    # char:: n-grams: useful to the model, cryptic to humans — always skip
    if name.startswith("char::"):
        return None

    # Strip remaining known prefixes
    name = (
        name
        .replace("word::", "")
        .replace("rule::", "")
        .replace("tfidf::", "")
    )

    # Map structural/numeric feature names to readable labels
    _READABLE = {
        "digit_ratio":   "Many numbers",
        "punct_density": "Heavy punctuation",
        "msg_length":    "Long message",
        "exclaim_count": "Exclamation marks",
        "url_count":     "Contains URL",
        "caps_ratio":    "Lots of capitals",
        "word_count":    "Word count",
    }
    if name in _READABLE:
        return _READABLE[name]

    # has_* → "Contains X" in title case
    if name.startswith("has_"):
        return "Contains " + name[4:].replace("_", " ").title()

    # Drop anything that is noisy/cryptic:
    #   • too short (single chars, empty)
    #   • purely numeric ("26", "100")
    #   • starts with a digit — catches bare fragments ("00") AND tfidf
    #     bigrams built from char n-grams ("00 am", "00 based", "00 dial")
    #     since the first token in those bigrams is always the digit fragment
    #   • contains only digits and spaces (e.g. "00 26")
    stripped = name.strip()
    first_token = stripped.split()[0] if stripped.split() else stripped
    if len(stripped) < 3:
        return None
    if first_token[0].isdigit():
        return None
    if all(c.isdigit() or c.isspace() for c in stripped):
        return None

    return name


def _is_displayable_feature(name: str) -> bool:
    """
    Character-level n-gram features (char::xx) help catch Sheng/typo
    obfuscation in the model but appear as cryptic 2-5 letter fragments
    to humans. Exclude them from the SHAP display pool.
    """
    return not name.startswith("char::")


def _is_readable_cleaned_name(clean_name: str | None) -> bool:
    """
    Accepts the output of _clean_feature_name and returns False for
    anything that should be hidden from the user (None, blank, too short).
    """
    if clean_name is None:
        return False
    stripped = clean_name.strip()
    return len(stripped) >= 3


def predict_with_explanation(message: str, sender: str = None):
    """
    Returns the combined fraud prediction and a SHAP explanation for a
    single SMS message.
    """
    cleaned = (message or "").strip()

    # Rule Engine first — fast, explainable filter; always runs so its
    # triggered rules are always shown regardless of ML result.
    rule_result = rule_engine.analyze(cleaned, sender)

    # ML Prediction
    X = feature_builder.transform([cleaned])
    proba = float(model.predict_proba(X)[0][1])  # Probability of fraud
    prediction = "FRAUD" if proba >= 0.5 else "SAFE"

    # SHAP Explanation
    raw_shap_values = _explainer.shap_values(X)
    row_shap_values = _extract_single_row_shap(raw_shap_values, row_index=0)

    feature_names = feature_builder.get_feature_names()
    shap_importance = list(zip(feature_names, row_shap_values))

    # Prefer word/structural/rule features (skip cryptic char-ngram fragments);
    # fall back to unfiltered list if too few displayable features remain.
    displayable = [pair for pair in shap_importance if _is_displayable_feature(pair[0])]
    pool = displayable if len(displayable) >= 8 else shap_importance
    pool.sort(key=lambda pair: abs(pair[1]), reverse=True)

    # Build top-8 list, applying human-readable name cleaning and a final
    # guard filter to drop any remaining cryptic short/numeric names.
    top_features = []
    for name, value in pool:
        if len(top_features) >= 8:
            break
        clean_name = _clean_feature_name(name)
        if not _is_readable_cleaned_name(clean_name):
            continue
        top_features.append({
            "feature": clean_name,
            "impact": round(float(value), 4),
        })

    return {
        "status": prediction,
        "fraud_probability": round(proba * 100, 1),
        "confidence": _confidence_from_probability(proba),
        "rule_engine_score": rule_result["score"],
        "combined_recommendation": rule_result["recommendation"],
        "top_shap_features": top_features,
        "triggered_rules": rule_result.get("triggered_rules", []),
    }


# ------------------------------------------------------------------
# Quick smoke-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("Testing SHAP explainability...\n")
    test_messages = [
        "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
        "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.",
        "Nimetuma pesa kwa makosa, tafadhali rudisha kwa hii namba.",
    ]
    for msg in test_messages:
        res = predict_with_explanation(msg)
        print(f"Message: {msg[:60]}...")
        print(f"  Status: {res['status']} ({res['fraud_probability']}%) — Confidence: {res['confidence']}")
        print("  Top SHAP reasons:")
        for f in res["top_shap_features"][:5]:
            direction = "↑ fraud" if f["impact"] > 0 else "↓ safe"
            print(f"    • {f['feature']} ({direction}, impact: {f['impact']:.3f})")
        if res["triggered_rules"]:
            print(f"  Triggered rules: {', '.join(res['triggered_rules'])}")
        print("-" * 70)