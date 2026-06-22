"""
Vigilant AI — Month 3 / Week 1
src/train_model.py

Trains the real Machine Learning classifier (XGBoost) using features from FeatureBuilder.
Handles class imbalance and saves the model + feature builder for later use in the app.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix, classification_report
from imblearn.over_sampling import SMOTE
import xgboost as xgb

# Import our feature builder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_engineering import FeatureBuilder

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "scam_dataset.csv")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")

os.makedirs(MODELS_DIR, exist_ok=True)


def main():
    # Load dataset
    if not os.path.exists(DATASET_PATH):
        print(f"❌ Dataset not found at {DATASET_PATH}")
        print("Run scripts/build_dataset.py first!")
        return

    df = pd.read_csv(DATASET_PATH).dropna(subset=["message_text", "label"])
    df = df[df["label"].isin(["fraud", "legit"])]
    
    print(f"✅ Loaded {len(df)} messages ({df['label'].value_counts().to_dict()})")

       # Prepare data
    X_text = np.array(df["message_text"].astype(str).tolist())
    y = np.array((df["label"] == "fraud").astype(int).tolist())


    # Split
    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, random_state=42, stratify=y
    )

    # Build features
    print("Building features...")
    fb = FeatureBuilder()
    X_train = fb.fit_transform(X_train_text)
    X_test = fb.transform(X_test_text)

    print(f"Feature matrix shape: {X_train.shape}")

    # Handle imbalance
    smote = SMOTE(random_state=42)
    X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)

    # Train XGBoost
    print("Training XGBoost model...")
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=len(y_train_bal) / sum(y_train_bal),
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train_bal, y_train_bal)

    # Evaluate
    y_pred = model.predict(X_test)
    
    print("\n" + "="*60)
    print("MODEL PERFORMANCE")
    print("="*60)
    print(classification_report(y_test, y_pred, target_names=["Legit", "Fraud"], zero_division=0))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save model and feature builder
    joblib.dump(model, os.path.join(MODELS_DIR, "vigilant_model.pkl"))
    joblib.dump(fb, os.path.join(MODELS_DIR, "feature_builder.pkl"))

    print(f"\n✅ Model saved to models/vigilant_model.pkl")
    print(f"✅ Feature builder saved to models/feature_builder.pkl")


if __name__ == "__main__":
    main()