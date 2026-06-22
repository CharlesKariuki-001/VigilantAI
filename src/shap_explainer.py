"""
Vigilant AI — Month 3 / Week 2
src/shap_explainer.py

Converts raw SHAP values from the XGBoost model into human-readable explanations.
"""

import os
import joblib
import shap
import numpy as np

from feature_engineering import FeatureBuilder


class ScamExplainer:
    def __init__(self):
        MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
        
        self.model = joblib.load(os.path.join(MODELS_DIR, "vigilant_model.pkl"))
        self.feature_builder = joblib.load(os.path.join(MODELS_DIR, "feature_builder.pkl"))
        self.feature_names = self.feature_builder.get_feature_names()
        
        self.explainer = shap.TreeExplainer(self.model)

    def _clean_feature_name(self, name: str) -> str:
        """Make feature names readable for normal users."""
        if name.startswith("rule::"):
            return name.replace("rule::", "")
        if name.startswith("word::"):
            return name.replace("word::", "")
        if name.startswith("char::"):
            return f"Pattern: {name.replace('char::', '')}"
        if name == "msg_length":
            return "Long message"
        if name == "digit_ratio":
            return "Many numbers"
        if name == "has_phone":
            return "Contains phone number"
        if name == "has_link":
            return "Contains a link"
        if name == "has_amount":
            return "Mentions money amount"
        return name

    def explain(self, message: str):
        """Return SHAP explanation for one message"""
        X = self.feature_builder.transform([message])
        proba = self.model.predict_proba(X)[0][1]   # Probability of fraud
        
        shap_values = self.explainer.shap_values(X)
        if isinstance(shap_values, list):
            shap_values = shap_values[1][0]   # For binary classification (fraud class)
        else:
            shap_values = shap_values[0]
        
        # Pair features with their SHAP impact
        impacts = list(zip(self.feature_names, shap_values))
        impacts.sort(key=lambda x: abs(x[1]), reverse=True)
        
        # Take top meaningful features (ignore noisy char n-grams for user display)
        top_factors = []
        for name, value in impacts[:10]:
            if name.startswith("char::"):
                continue  # Too technical for users
            if abs(value) < 0.01:
                continue
            top_factors.append({
                "feature": self._clean_feature_name(name),
                "impact": round(float(value), 4),
                "direction": "toward fraud" if value > 0 else "toward safe"
            })
            if len(top_factors) >= 5:
                break

        explanation_text = self._build_text(proba, top_factors)

        return {
            "fraud_probability": round(float(proba) * 100, 1),
            "top_factors": top_factors,
            "explanation_text": explanation_text
        }

    def _build_text(self, proba, top_factors):
        pct = f"{proba:.0%}"
        if not top_factors:
            return f"This message is {pct} likely to be fraud."
        
        parts = [f"This message is {pct} likely to be fraud."]
        for i, factor in enumerate(top_factors[:3]):
            label = ["Top reason", "Also", "Also"][i]
            parts.append(f"{label}: {factor['feature']}.")
        return " ".join(parts)


# Quick test
if __name__ == "__main__":
    explainer = ScamExplainer()
    tests = [
        "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
        "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.",
    ]
    for msg in tests:
        res = explainer.explain(msg)
        print(f"Message: {msg[:60]}...")
        print(f"Probability: {res['fraud_probability']}%")
        print(f"Explanation: {res['explanation_text']}")
        print("Top factors:")
        for f in res["top_factors"]:
            print(f"   {f['feature']} ({f['direction']})")
        print("-" * 60)