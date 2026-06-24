"""
Vigilant AI — Month 3
src/predict.py

Hybrid Predictor: Rule Engine + XGBoost + Clean SHAP Explanations
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

from feature_engineering import FeatureBuilder
from rule_engine import RuleEngine

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

model = joblib.load(os.path.join(MODELS_DIR, "vigilant_model.pkl"))
feature_builder = joblib.load(os.path.join(MODELS_DIR, "feature_builder.pkl"))

rule_engine = RuleEngine()
_explainer = shap.TreeExplainer(model)


def _is_noise_feature(name: str) -> bool:
    """
    Returns True if this feature name should be hidden from SHAP explanations.
    The model can still USE these features internally — we just don't show them
    to the user because they are not human-readable or meaningful as explanations.
    """
    name = name.strip()

    # Very short — not meaningful
    if len(name) < 3:
        return True

    # Phone number pattern — TF-IDF bigrams containing Kenyan phone numbers
    # (e.g. "0701223399 leo", "0712345678 to") these are memorised training
    # artifacts, not generalizable fraud signals
    if re.search(r"\b0[17]\d{8}\b", name):
        return True

    # Pure digits or starts with a long digit sequence
    if re.match(r"^\d+", name) and len(re.match(r"^\d+", name).group()) >= 4:
        return True

    # Character n-gram noise — single characters, punctuation fragments
    if re.match(r"^[^a-zA-Z\u0600-\u06FF]+$", name):
        return True

    # Transaction code fragments (e.g. "TB17C", "RK23X") — memorised codes
    if re.match(r"^[A-Z]{1,3}\d{2,}[A-Z0-9]*$", name):
        return True

    return False


def _clean_feature_name(raw_name: str) -> str | None:
    """
    Converts a raw internal feature name into a human-readable explanation.
    Returns None if the feature should be hidden entirely.
    """
    name = raw_name

    # Strip internal prefixes
    for prefix in ("word::", "char::", "rule::", "tfidf::"):
        if name.startswith(prefix):
            name = name[len(prefix):]

    name = name.strip()

    # Apply noise filter AFTER stripping prefix
    if _is_noise_feature(name):
        return None

    # Also filter the raw (pre-strip) name in case prefix removal exposed noise
    if _is_noise_feature(raw_name):
        return None

    # Human-readable mappings for structural features
    structural_mappings = {
        "digit_ratio":    "High proportion of numbers in message",
        "punct_density":  "Heavy punctuation use",
        "msg_length":     "Message length",
        "exclaim_count":  "Uses exclamation marks",
        "has_phone":      "Contains a phone number",
        "has_link":       "Contains a link or URL",
        "has_amount":     "Mentions a money amount",
    }
    if name in structural_mappings:
        return structural_mappings[name]

    if name.startswith("has_"):
        return "Contains " + name[4:].replace("_", " ")

    return name


class HybridDetector:

    MIN_CONTENT_LENGTH = 6  # messages shorter than this skip ML entirely

    def predict(self, message: str, sender: str = None) -> dict:
        cleaned = (message or "").strip()

        # ---- Rule Engine (always runs) ----
        rule_result = rule_engine.analyze(cleaned, sender)
        triggered_rules = rule_result.get("triggered_rules", [])
        rule_status = rule_result["status"]

        # ---- Guard: skip ML on trivial / near-empty input ----
        has_letters = any(c.isalpha() for c in cleaned)
        if len(cleaned) < self.MIN_CONTENT_LENGTH or not has_letters:
            return {
                "status": rule_status,
                "confidence": "LOW",
                "decided_by": "rule_engine_only_insufficient_text",
                "rule_engine": {
                    "status": rule_status,
                    "score": rule_result.get("score", 0),
                    "triggered_rules": triggered_rules,
                },
                "ml_model": {
                    # Store as 0-1 float throughout — app.py formats as %
                    "fraud_probability": None,
                    "threshold_used": 0.5,
                    "explanation_text": "Message too short for ML evaluation — rule engine only.",
                    "top_factors": [],
                },
                "recommendation": rule_result["recommendation"],
            }

        # ---- ML prediction ----
        X = feature_builder.transform([cleaned])

        # fraud_probability is a plain float: 0.0 = definitely safe, 1.0 = definitely fraud
        # Do NOT multiply by 100 here — let app.py format it for display
        fraud_probability = float(model.predict_proba(X)[0][1])
        ml_status = "FRAUD" if fraud_probability >= 0.5 else "SAFE"

        # ---- SHAP explanation ----
        raw_shap = _explainer.shap_values(X)
        if isinstance(raw_shap, list):
            shap_row = np.asarray(raw_shap[1][0]).flatten()   # fraud class
        else:
            shap_row = np.asarray(raw_shap[0]).flatten()

        feature_names = feature_builder.get_feature_names()
        impacts = sorted(zip(feature_names, shap_row), key=lambda x: abs(x[1]), reverse=True)

        # Build clean top-factor list — skip noise until we have enough readable ones
        top_factors = []
        for raw_name, value in impacts:
            if len(top_factors) >= 5:
                break
            clean_name = _clean_feature_name(raw_name)
            if clean_name is None:
                continue
            top_factors.append({
                "feature": clean_name,
                "impact": round(float(value), 4),
                "direction": "toward fraud" if value > 0 else "toward safe",
            })

        # ---- SHAP explanation text (plain language) ----
        fraud_factors = [f for f in top_factors if f["direction"] == "toward fraud"]
        if fraud_factors:
            labels = ["Top reason", "Secondary", "Also"]
            parts = [f"This message scored {fraud_probability:.0%} fraud probability."]
            for i, factor in enumerate(fraud_factors[:3]):
                label = labels[i] if i < len(labels) else "Also"
                parts.append(f"{label}: {factor['feature']}.")
            explanation_text = " ".join(parts)
        else:
            explanation_text = (
                f"This message scored {fraud_probability:.0%} fraud probability. "
                "No single dominant fraud signal found."
            )

        # ---- Final hybrid decision ----
        # Rules take priority when a critical-weight rule fires (weight >= 9)
        # otherwise trust the ML model's verdict
        critical_rule_fired = any(
            r.get("weight", 0) >= 9 for r in triggered_rules
        )

        if critical_rule_fired or (rule_status == "FRAUD" and ml_status == "FRAUD"):
            final_status = "FRAUD"
            decided_by = "hybrid"
        elif rule_status == "FRAUD":
            final_status = "FRAUD"
            decided_by = "rule_engine"
        elif ml_status == "FRAUD":
            final_status = "FRAUD"
            decided_by = "ml_model"
        else:
            final_status = "SAFE"
            decided_by = "hybrid"

        # Confidence based on ML probability distance from 0.5
        if fraud_probability >= 0.8 or fraud_probability <= 0.2:
            confidence = "HIGH"
        elif fraud_probability >= 0.65 or fraud_probability <= 0.35:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return {
            "status": final_status,
            "confidence": confidence,
            "decided_by": decided_by,
            "rule_engine": {
                "status": rule_status,
                "score": rule_result.get("score", 0),
                "triggered_rules": triggered_rules,
            },
            "ml_model": {
                # Always stored as 0.0–1.0 float here.
                # In app.py display it as: f"{result['ml_model']['fraud_probability']:.0%}"
                # That will show "87%" not "8700%"
                "fraud_probability": round(fraud_probability, 4),
                "threshold_used": 0.5,
                "explanation_text": explanation_text,
                "top_factors": top_factors,
            },
            "recommendation": rule_result["recommendation"],
        }


# ---- Quick sanity check when running directly ----
if __name__ == "__main__":
    detector = HybridDetector()

    tests = [
        ("Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.", "FRAUD"),
        ("TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.", "SAFE"),
        ("Nipigie nikuambie tutaonana wapi leo jioni.", "SAFE"),
        ("KRA: Una refund ya Ksh 12,400. Jisajili na ID yako kupokea.", "FRAUD"),
        ("", "SAFE"),
    ]

    print("=" * 60)
    print("predict.py sanity check")
    print("=" * 60)
    all_pass = True
    for msg, expected in tests:
        result = detector.predict(msg)
        prob = result["ml_model"]["fraud_probability"]
        prob_str = f"{prob:.0%}" if prob is not None else "N/A (guarded)"
        status = result["status"]
        passed = status == expected
        all_pass = all_pass and passed
        tick = "✅" if passed else "❌"
        print(f"{tick} [{status:5s} expected={expected}] prob={prob_str:6} | {msg[:60]}")
        if result["ml_model"]["top_factors"]:
            for f in result["ml_model"]["top_factors"][:2]:
                print(f"     • {f['feature']} ({f['direction']})")

    print()
    print("ALL PASSED" if all_pass else "SOME FAILED — check above")
    print("=" * 60)