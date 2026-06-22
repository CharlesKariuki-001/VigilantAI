"""
Vigilant AI — Month 3 Week 2
src/shap_explainer.py

Converts raw SHAP values from the XGBoost model into human-readable explanations.
"""

import os
import sys
import re
import joblib
import shap
import numpy as np

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

try:
    from src.feature_engineering import FeatureBuilder
except ModuleNotFoundError:
    from feature_engineering import FeatureBuilder


_READABLE = {
    "digit_ratio":   "Many numbers",
    "punct_density": "Heavy punctuation",
    "msg_length":    "Long message",
    "exclaim_count": "Exclamation marks",
    "url_count":     "Contains URL",
    "caps_ratio":    "Lots of capitals",
    "word_count":    "Word count",
    "has_phone":     "Contains phone number",
    "has_link":      "Contains a link",
    "has_amount":    "Mentions money amount",
}

# Stop-words and training artifacts to never show users
_BLOCKLIST_EXACT = {"acc", "na", "ya", "wa", "za", "la", "ka"}


def _is_training_artifact(name: str) -> bool:
    """
    Detect tokens that leaked from training data rather than real signal:
      - acc-prefixed account names  ("acc datajob", "acc fuliza2026")
      - alphanumeric compounds      ("fuliza2026", "ntsa2026")
    """
    if any(name.startswith(p) for p in ("acc ", "acc_")):
        return True
    for token in name.split():
        if re.search(r'[a-zA-Z]', token) and re.search(r'\d', token):
            return True
    return False


def _clean_feature_name(name: str):
    """
    Return a human-readable label for a raw feature name, or None if
    the feature is too noisy / cryptic to show a user.
    """
    # Always drop char n-grams
    if name.startswith("char::"):
        return None

    # Strip all known prefixes
    for prefix in ("word::", "char::", "rule::", "tfidf::"):
        name = name.replace(prefix, "")
    name = name.strip()

    if not name:
        return None

    # Drop digit-led tokens ("00", "26", "00 am", "26 based")
    first_token = name.split()[0]
    if first_token[0].isdigit():
        return None

    # Drop short noise and exact stop-words
    if len(name) <= 2 or name in _BLOCKLIST_EXACT:
        return None

    # Drop training artifacts
    if _is_training_artifact(name):
        return None

    # Map structural features → readable English
    if name in _READABLE:
        return _READABLE[name]

    # has_* → "Contains X"
    if name.startswith("has_"):
        return "Contains " + name[4:].replace("_", " ").title()

    return name


class ScamExplainer:
    def __init__(self):
        MODELS_DIR = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models"
        )
        self.model           = joblib.load(os.path.join(MODELS_DIR, "vigilant_model.pkl"))
        self.feature_builder = joblib.load(os.path.join(MODELS_DIR, "feature_builder.pkl"))
        self.feature_names   = self.feature_builder.get_feature_names()
        self.explainer       = shap.TreeExplainer(self.model)

    def _extract_row_shap(self, shap_values):
        """Normalize TreeExplainer output across shap/xgboost versions."""
        if isinstance(shap_values, list):
            return np.asarray(shap_values[-1])[0]
        arr = np.asarray(shap_values)
        if arr.ndim == 3:
            return arr[0, :, -1]
        return arr[0]

    def explain(self, message: str) -> dict:
        """Return a SHAP explanation dict for one SMS message."""
        X     = self.feature_builder.transform([message])
        proba = float(self.model.predict_proba(X)[0][1])

        raw_shap   = self.explainer.shap_values(X)
        row_shap   = self._extract_row_shap(raw_shap)

        impacts = sorted(
            zip(self.feature_names, row_shap),
            key=lambda p: abs(p[1]),
            reverse=True,
        )

        top_factors = []
        for name, value in impacts:
            if len(top_factors) >= 6:
                break
            # Skip near-zero features — they add noise without explanation value
            if abs(value) < 0.01:
                continue
            clean = _clean_feature_name(name)
            if not clean:
                continue
            top_factors.append({
                "feature":   clean,
                "impact":    round(float(value), 4),
                "direction": "toward fraud" if value > 0 else "toward safe",
            })

        return {
            "fraud_probability": round(proba * 100, 1),
            "top_factors":       top_factors,
            "explanation_text":  self._build_text(proba, top_factors),
        }

    def _build_text(self, proba: float, top_factors: list) -> str:
        pct = f"{proba:.0%}"
        if not top_factors:
            return f"This message is {pct} likely to be fraud."
        labels = ["Top reason", "Secondary reason", "Also"]
        parts  = [f"This message is {pct} likely to be fraud."]
        for i, f in enumerate(top_factors[:3]):
            parts.append(f"{labels[i]}: {f['feature']}.")
        return " ".join(parts)


if __name__ == "__main__":
    explainer = ScamExplainer()
    tests = [
        "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
        "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.",
        "Akaunti yako itafungwa leo kama hutathibitisha PIN.",
    ]
    for msg in tests:
        res = explainer.explain(msg)
        print(f"Message: {msg[:60]}...")
        print(f"Probability: {res['fraud_probability']}%")
        print(f"Explanation: {res['explanation_text']}")
        print("Top factors:")
        for f in res["top_factors"]:
            arrow = "↑" if f["impact"] > 0 else "↓"
            print(f"  {arrow} {f['feature']} (impact: {f['impact']:.3f})")
        print("-" * 60)