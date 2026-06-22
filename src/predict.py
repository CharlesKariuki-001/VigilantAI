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
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from src.feature_engineering import FeatureBuilder
from src.rule_engine import RuleEngine

# ------------------------------------------------------------------
# Load model artifacts once at import time (not per-request)
# ------------------------------------------------------------------
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

model         = joblib.load(os.path.join(MODELS_DIR, "vigilant_model.pkl"))
feature_builder = joblib.load(os.path.join(MODELS_DIR, "feature_builder.pkl"))

rule_engine = RuleEngine()
_explainer  = shap.TreeExplainer(model)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _confidence_from_probability(proba: float) -> str:
    if proba >= 0.85 or proba <= 0.15:
        return "HIGH"
    if proba >= 0.65 or proba <= 0.35:
        return "MEDIUM"
    return "LOW"


def _extract_single_row_shap(shap_values, row_index: int = 0):
    """Normalize TreeExplainer output across shap/xgboost versions."""
    if isinstance(shap_values, list):
        return np.asarray(shap_values[-1])[row_index]
    shap_array = np.asarray(shap_values)
    if shap_array.ndim == 3:
        return shap_array[row_index, :, -1]
    return shap_array[row_index]


_READABLE = {
    "digit_ratio":   "Many numbers",
    "punct_density": "Heavy punctuation",
    "msg_length":    "Long message",
    "exclaim_count": "Exclamation marks",
    "url_count":     "Contains URL",
    "caps_ratio":    "Lots of capitals",
    "word_count":    "Word count",
}


def _clean_feature_name(name: str):
    """
    Return a human-readable label, or None if the feature is too noisy
    to show a user (char n-grams, digit fragments, short noise).
    """
    # 1. Always drop char:: prefix features
    if name.startswith("char::"):
        return None

    # 2. Strip ALL known prefixes (belt-and-suspenders)
    for prefix in ("word::", "char::", "rule::", "tfidf::"):
        name = name.replace(prefix, "")

    name = name.strip()
    if not name:
        return None

    # 3. Drop digit-led tokens — catches bare "00", "26" AND bigrams
    #    like "00 am", "26 based" that survive prefix stripping because
    #    they were built by the tfidf vectorizer on top of char fragments.
    first_token = name.split()[0]
    if first_token[0].isdigit():
        return None

    # 4. Drop very short or all-digit strings
    if len(name) <= 2:
        return None
    if name.replace(" ", "").isdigit():
        return None

    # 5. Map known structural features → readable English
    if name in _READABLE:
        return _READABLE[name]

    # 6. has_* → "Contains X"
    if name.startswith("has_"):
        return "Contains " + name[4:].replace("_", " ").title()

    return name


def _keep(clean_name) -> bool:
    """Final guard: reject None, blank, or suspiciously short names."""
    if clean_name is None:
        return False
    return len(clean_name.strip()) >= 3


# ------------------------------------------------------------------
# Main prediction entry point
# ------------------------------------------------------------------

def predict_with_explanation(message: str, sender: str = None):
    cleaned = (message or "").strip()

    # Rule Engine
    rule_result = rule_engine.analyze(cleaned, sender)

    # ML Prediction
    X     = feature_builder.transform([cleaned])
    proba = float(model.predict_proba(X)[0][1])
    prediction = "FRAUD" if proba >= 0.5 else "SAFE"

    # SHAP
    raw_shap      = _explainer.shap_values(X)
    row_shap      = _extract_single_row_shap(raw_shap, row_index=0)
    feature_names = feature_builder.get_feature_names()

    impacts = sorted(
        zip(feature_names, row_shap),
        key=lambda p: abs(p[1]),
        reverse=True,
    )

    top_features = []
    for name, value in impacts:
        if len(top_features) >= 8:
            break
        clean = _clean_feature_name(name)
        if not _keep(clean):
            continue
        top_features.append({
            "feature": clean,
            "impact":  round(float(value), 4),
        })

    return {
        "status":                 prediction,
        "fraud_probability":      round(proba * 100, 1),
        "confidence":             _confidence_from_probability(proba),
        "rule_engine_score":      rule_result["score"],
        "combined_recommendation": rule_result["recommendation"],
        "top_shap_features":      top_features,
        "triggered_rules":        rule_result.get("triggered_rules", []),
    }


# ------------------------------------------------------------------
# Smoke-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("Testing SHAP explainability...\n")
    tests = [
        "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
        "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.",
        "Nimetuma pesa kwa makosa, tafadhali rudisha kwa hii namba.",
    ]
    for msg in tests:
        res = predict_with_explanation(msg)
        print(f"Message: {msg[:60]}...")
        print(f"  Status: {res['status']} ({res['fraud_probability']}%) — Confidence: {res['confidence']}")
        print("  Top SHAP reasons:")
        for f in res["top_shap_features"][:5]:
            arrow = "↑ fraud" if f["impact"] > 0 else "↓ safe"
            print(f"    • {f['feature']} ({arrow}, {f['impact']:.3f})")
        if res["triggered_rules"]:
            print(f"  Rules: {', '.join(res['triggered_rules'])}")
        print("-" * 70)