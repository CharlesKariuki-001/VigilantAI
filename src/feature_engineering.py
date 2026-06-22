"""
Vigilant AI — Month 3 / Week 1
src/feature_engineering.py

Converts raw SMS text into a numerical feature matrix for the ML model.
Combines:
  1. Word-level TF-IDF (semantic meaning)
  2. Character-level TF-IDF (catches Swahili/Sheng morphology and obfuscation)
  3. Rule Engine binary features (your expert knowledge)
  4. Structural features (length, digits, links, etc.)

This class ensures training and inference use identical logic.
"""

import re
import numpy as np
import sys
import os
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer

# Add src to path so we can import RuleEngine
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rule_engine import RuleEngine


class FeatureBuilder:
    def __init__(self, max_word_features=4000, max_char_features=2500):
        # Word-level TF-IDF (captures meaning)
        self.word_vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=max_word_features,
            min_df=1,
            stop_words=None  # We want Swahili words
        )
        
        # Character-level TF-IDF (catches slang, typos, morphology)
        self.char_vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(3, 5),
            max_features=max_char_features,
            min_df=1
        )
        
        self.rule_engine = RuleEngine()
        self.fitted = False
        self.rule_feature_names = None

    def _structural_features(self, messages):
        """Hand-crafted numeric features"""
        features = []
        for msg in messages:
            msg = str(msg)
            length = len(msg)
            digit_ratio = sum(c.isdigit() for c in msg) / length if length > 0 else 0
            punct_density = sum(1 for c in msg if c in "!?.") / length if length > 0 else 0
            has_phone = 1 if re.search(r"0[17]\d{8}|\+254", msg) else 0
            has_link = 1 if re.search(r"http|www\.|bit\.ly|tinyurl", msg, re.IGNORECASE) else 0
            has_amount = 1 if re.search(r"ksh|tzs|\d{3,}", msg, re.IGNORECASE) else 0
            exclaim_count = msg.count("!")
            
            features.append([length, digit_ratio, punct_density, has_phone, has_link, has_amount, exclaim_count])
        
        return np.array(features, dtype=float)

    def _rule_engine_features(self, messages):
        """Binary features: did each rule fire?"""
        rule_names = [r["name"] for r in self.rule_engine.rules]
        features = []
        
        for msg in messages:
            result = self.rule_engine.analyze(str(msg))
            triggered = {r["name"] for r in result.get("triggered_rules", [])}
            row = [1 if name in triggered else 0 for name in rule_names]
            features.append(row)
        
        return np.array(features, dtype=float), rule_names

    def fit_transform(self, messages):
        """Fit on training data and transform"""
        messages = list(messages)
        
        word_X = self.word_vectorizer.fit_transform(messages)
        char_X = self.char_vectorizer.fit_transform(messages)
        struct_X = csr_matrix(self._structural_features(messages))
        rule_X, self.rule_feature_names = self._rule_engine_features(messages)
        rule_X = csr_matrix(rule_X)

        self.fitted = True
        return hstack([word_X, char_X, struct_X, rule_X]).tocsr()

    def transform(self, messages):
        """Transform new data (used in inference)"""
        if not self.fitted:
            raise RuntimeError("FeatureBuilder must be fitted first using fit_transform()")
        
        messages = list(messages)
        word_X = self.word_vectorizer.transform(messages)
        char_X = self.char_vectorizer.transform(messages)
        struct_X = csr_matrix(self._structural_features(messages))
        rule_X, _ = self._rule_engine_features(messages)
        rule_X = csr_matrix(rule_X)

        return hstack([word_X, char_X, struct_X, rule_X]).tocsr()

    def get_feature_names(self):
        """Return all feature names for debugging/SHAP"""
        word_names = [f"word::{name}" for name in self.word_vectorizer.get_feature_names_out()]
        char_names = [f"char::{name}" for name in self.char_vectorizer.get_feature_names_out()]
        struct_names = ["length", "digit_ratio", "punct_density", "has_phone", "has_link", "has_amount", "exclaim_count"]
        rule_names = [f"rule::{name}" for name in self.rule_feature_names]
        return word_names + char_names + struct_names + rule_names


# Quick test
if __name__ == "__main__":
    samples = [
        "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
        "TB17CVOCY9 Confirmed. You have received Ksh2,500 from Francis Gachie."
    ]
    fb = FeatureBuilder()
    X = fb.fit_transform(samples)
    print(f"✅ Feature Engineering works! Shape: {X.shape}")
    print(f"Total features: {len(fb.get_feature_names())}")