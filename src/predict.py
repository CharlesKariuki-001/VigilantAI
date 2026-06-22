"""
Vigilant AI — Month 3
src/predict.py

Combines Rule Engine + ML Model + SHAP Explainability for real-time prediction.

Fixes applied vs the original draft:
1. Import paths corrected to `src.feature_engineering` / `src.rule_engine` --
   app.py imports this module as `from src.predict import ...`, which makes
   `src` a package, so sibling modules must be imported the same way or
   Python raises ModuleNotFoundError at app startup.
2. Added a `confidence` field (HIGH/MEDIUM/LOW) derived from the fraud
   probability, since app.py displays this directly.
3. Defensive handling of `shap_values()` output shape. Depending on the
   installed shap/xgboost version, TreeExplainer.shap_values() can return
   either a single 2D array (n_samples x n_features) for binary models, or
   a list of two such arrays ([shap_for_class_0, shap_for_class_1]). The
   code below detects which shape it got and always extracts the
   per-feature SHAP values for the single message being scored, for the
   positive ("fraud") class.
"""

import os
import joblib
import shap
import numpy as np

from src.feature_engineering import FeatureBuilder
from src.rule_engine import RuleEngine

# ------------------------------------------------------------------
# Load model artifacts once at import time (not per-request)
# ------------------------------------------------------------------
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

model = joblib.load(os.path.join(MODELS_DIR, "vigilant_model.pkl"))
feature_builder = joblib.load(os.path.join(MODELS_DIR, "feature_builder.pkl"))

rule_engine = RuleEngine()

# TreeExplainer is also created once -- rebuilding it per-request is
# unnecessary overhead, it only depends on the (fixed) trained model.
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
    # Case 1: list of per-class arrays, e.g. [array(n_samples, n_features), array(n_samples, n_features)]
    if isinstance(shap_values, list):
        # Use the last class in the list as the "positive"/fraud class.
        positive_class_values = shap_values[-1]
        return np.asarray(positive_class_values)[row_index]

    shap_array = np.asarray(shap_values)

    # Case 2: 3D array (n_samples, n_features, n_classes) -- newer shap versions
    if shap_array.ndim == 3:
        return shap_array[row_index, :, -1]

    # Case 3: standard 2D array (n_samples, n_features) -- binary model, single output
    return shap_array[row_index]


def predict_with_explanation(message: str, sender: str = None):
    """
    Returns both the combined prediction and a SHAP explanation for a
    single SMS message.
    """
    # Rule Engine first (fast, explainable filter -- always runs regardless
    # of what the ML model says, so its triggered rules are always shown).
    rule_result = rule_engine.analyze(message, sender)

    # ML Prediction
    X = feature_builder.transform([message])
    proba = float(model.predict_proba(X)[0][1])  # Probability of fraud
    prediction = "FRAUD" if proba >= 0.5 else "SAFE"

    # SHAP Explanation
    raw_shap_values = _explainer.shap_values(X)
    row_shap_values = _extract_single_row_shap(raw_shap_values, row_index=0)

    feature_names = feature_builder.get_feature_names()
    shap_importance = list(zip(feature_names, row_shap_values))
    shap_importance.sort(key=lambda pair: abs(pair[1]), reverse=True)

    top_features = shap_importance[:8]  # Top 8 reasons

    return {
        "status": prediction,
        "fraud_probability": round(proba * 100, 1),
        "confidence": _confidence_from_probability(proba),
        "rule_engine_score": rule_result["score"],
        "combined_recommendation": rule_result["recommendation"],
        "top_shap_features": [
            {"feature": name, "impact": round(float(value), 4)}
            for name, value in top_features
        ],
        "triggered_rules": rule_result.get("triggered_rules", []),
    }