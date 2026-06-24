"""
Vigilant AI — Month 3
src/predict.py

Combines Rule Engine + ML Model + SHAP Explainability for real-time prediction.
Exports both HybridDetector (class) and predict_with_explanation (function).
"""

import os
import sys
import joblib
import shap
import numpy as np
import re

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

try:
    from src.feature_engineering import FeatureBuilder
    from src.rule_engine import RuleEngine
except ModuleNotFoundError:
    from feature_engineering import FeatureBuilder
    from rule_engine import RuleEngine

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

model           = joblib.load(os.path.join(MODELS_DIR, "vigilant_model.pkl"))
feature_builder = joblib.load(os.path.join(MODELS_DIR, "feature_builder.pkl"))
rule_engine     = RuleEngine()
_explainer      = shap.TreeExplainer(model)


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

_BLOCKLIST_PREFIXES = ("acc ", "acc_", "00", "26")
_BLOCKLIST_EXACT    = {"acc", "na", "ya", "wa", "za", "la", "ka"}


def _is_training_artifact(name: str) -> bool:
    if any(name.startswith(p) for p in _BLOCKLIST_PREFIXES):
        return True
    for token in name.split():
        if re.search(r'[a-zA-Z]', token) and re.search(r'\d', token):
            return True
    return False


def _clean_feature_name(name: str):
    """Return a human-readable label, or None if the feature is noise."""
    if name.startswith("char::"):
        return None
    for prefix in ("word::", "char::", "rule::", "tfidf::"):
        name = name.replace(prefix, "")
    name = name.strip()
    if not name:
        return None
    first_token = name.split()[0]
    if first_token[0].isdigit():
        return None
    if len(name) <= 2:
        return None
    if name in _BLOCKLIST_EXACT:
        return None
    if _is_training_artifact(name):
        return None
    if name in _READABLE:
        return _READABLE[name]
    if name.startswith("has_"):
        return "Contains " + name[4:].replace("_", " ").title()
    return name


def _keep(clean_name) -> bool:
    if clean_name is None:
        return False
    return len(clean_name.strip()) >= 3


def _build_top_features(X) -> list:
    """Run SHAP and return cleaned top features list."""
    raw_shap = _explainer.shap_values(X)
    row_shap = _extract_single_row_shap(raw_shap, row_index=0)
    feature_names = feature_builder.get_feature_names()
    impacts = sorted(zip(feature_names, row_shap), key=lambda p: abs(p[1]), reverse=True)

    top_features = []
    for name, value in impacts:
        if len(top_features) >= 8:
            break
        if abs(value) < 0.01:
            continue
        clean = _clean_feature_name(name)
        if not _keep(clean):
            continue
        top_features.append({
            "feature":   clean,
            "impact":    round(float(value), 4),
            "direction": "toward fraud" if value > 0 else "toward safe",
        })
    return top_features


# ------------------------------------------------------------------
# Function interface (used internally and by legacy callers)
# ------------------------------------------------------------------

def predict_with_explanation(message: str, sender: str = None) -> dict:
    cleaned = (message or "").strip()

    rule_result = rule_engine.analyze(cleaned, sender)

    X     = feature_builder.transform([cleaned])
    proba = float(model.predict_proba(X)[0][1])
    prediction = "FRAUD" if proba >= 0.5 else "SAFE"

    top_features = _build_top_features(X)

    return {
        "status":                  prediction,
        "fraud_probability":       round(proba * 100, 1),
        "confidence":              _confidence_from_probability(proba),
        "rule_engine_score":       rule_result["score"],
        "combined_recommendation": rule_result["recommendation"],
        "top_shap_features":       top_features,
        "triggered_rules":         rule_result.get("triggered_rules", []),
    }


# ------------------------------------------------------------------
# Class interface — what app.py imports as HybridDetector
# ------------------------------------------------------------------

class HybridDetector:
    """
    Wraps predict_with_explanation in a class so app.py can do:
        from src.predict import HybridDetector
        detector = HybridDetector()
        result = detector.predict(message, sender)
    """

    def predict(self, message: str, sender: str = None) -> dict:
        cleaned = (message or "").strip()

        rule_result = rule_engine.analyze(cleaned, sender)

        X     = feature_builder.transform([cleaned])
        proba = float(model.predict_proba(X)[0][1])
        ml_status = "FRAUD" if proba >= 0.5 else "SAFE"

        top_features = _build_top_features(X)

        # Final status: if rule engine fires a critical hit, trust it;
        # otherwise use the ML prediction.
        critical_rule_hit = any(
            r["weight"] >= 9 for r in rule_result.get("triggered_rules", [])
        )
        final_status = "FRAUD" if (ml_status == "FRAUD" or critical_rule_hit) else "SAFE"

        return {
            "status":     final_status,
            "confidence": _confidence_from_probability(proba),
            "decided_by": "hybrid",
            "rule_engine": {
                "status":          rule_result["status"],
                "score":           rule_result["score"],
                "triggered_rules": rule_result.get("triggered_rules", []),
            },
            "ml_model": {
                "fraud_probability": round(proba * 100, 1),
                "threshold_used":    0.5,
                "explanation_text":  "See SHAP factors below",
                "top_factors":       top_features,
            },
            "recommendation": rule_result["recommendation"],
        }


# ------------------------------------------------------------------
# Quick smoke test
# ------------------------------------------------------------------

if __name__ == "__main__":
    print("Testing HybridDetector + predict_with_explanation...\n")
    tests = [
        "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
        "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.",
        "Nimetuma pesa kwa makosa, tafadhali rudisha kwa hii namba.",
        "Akaunti yako itafungwa leo kama hutathibitisha PIN.",
    ]

    detector = HybridDetector()

    for msg in tests:
        # Test class interface
        res = detector.predict(msg)
        print(f"[HybridDetector] {msg[:60]}")
        print(f"  Status: {res['status']} ({res['confidence']}) — decided_by: {res['decided_by']}")
        print(f"  ML fraud probability: {res['ml_model']['fraud_probability']}%")
        print("  Top SHAP factors:")
        for f in res["ml_model"]["top_factors"][:3]:
            arrow = "↑ fraud" if f["impact"] > 0 else "↓ safe"
            print(f"    • {f['feature']} ({arrow}, {f['impact']:.3f})")
        print("-" * 70)