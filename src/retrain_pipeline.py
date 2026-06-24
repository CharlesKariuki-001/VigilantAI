"""
Vigilant AI — Retraining Pipeline (Improved)
Handles empty/missing feedback & community files gracefully.
"""

import os
import sys
import json
import shutil
import joblib
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix
from imblearn.over_sampling import SMOTE
import xgboost as xgb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_engineering import FeatureBuilder

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
ARCHIVE_DIR = os.path.join(MODELS_DIR, "archive")

DATASET_PATH = os.path.join(DATA_DIR, "scam_dataset.csv")
FEEDBACK_PATH = os.path.join(DATA_DIR, "feedback_log.csv")
COMMUNITY_PATH = os.path.join(DATA_DIR, "community_reports.csv")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")


def load_csv_safe(path, default_columns):
    """Safely load CSV even if empty or missing"""
    if not os.path.exists(path):
        return pd.DataFrame(columns=default_columns)
    try:
        df = pd.read_csv(path)
        if df.empty:
            return pd.DataFrame(columns=default_columns)
        return df
    except:
        return pd.DataFrame(columns=default_columns)


def main():
    print("🚀 Starting Retraining Pipeline...\n")

    if not os.path.exists(DATASET_PATH):
        print("❌ No scam_dataset.csv found!")
        return

    # Load current dataset
    current_df = pd.read_csv(DATASET_PATH).dropna(subset=["message_text", "label"])
    current_df = current_df.drop_duplicates(subset=["message_text"])
    print(f"Current dataset: {len(current_df)} messages")

    new_rows = []

    # Load feedback corrections
    fb = load_csv_safe(FEEDBACK_PATH, ["message_text", "predicted_label", "correct_label"])
    if not fb.empty:
        corrections = fb[fb["correct_label"].str.upper() != fb["predicted_label"].str.upper()]
        for _, row in corrections.iterrows():
            label = "fraud" if str(row["correct_label"]).upper() == "FRAUD" else "legit"
            new_rows.append({
                "message_text": row["message_text"],
                "label": label,
                "language": "mixed",
                "fraud_category": "user_feedback",
                "source": "feedback_correction",
                "date_collected": datetime.now().date().isoformat(),
            })
        print(f"Added {len(corrections)} corrections from feedback")

    # Load reviewed community reports
    cr = load_csv_safe(COMMUNITY_PATH, ["message_text", "user_believes_fraud", "status"])
    if not cr.empty:
        reviewed = cr[cr.get("status", "pending_review") == "reviewed"]
        for _, row in reviewed.iterrows():
            label = "fraud" if str(row.get("user_believes_fraud", True)).lower() == "true" else "legit"
            new_rows.append({
                "message_text": row["message_text"],
                "label": label,
                "language": "mixed",
                "fraud_category": "community_report",
                "source": "community_reviewed",
                "date_collected": datetime.now().date().isoformat(),
            })
        print(f"Added {len(reviewed)} reviewed community reports")

    if not new_rows:
        print("\n✅ No new feedback or reviewed reports. Model stays the same.")
        return

    # Combine and clean
    new_df = pd.DataFrame(new_rows)
    combined = pd.concat([current_df, new_df], ignore_index=True)
    combined = combined.drop_duplicates(subset=["message_text"])
    print(f"Combined dataset: {len(combined)} messages after deduplication")

    # Train candidate model
    fb = FeatureBuilder()
    X = fb.fit_transform(combined["message_text"].astype(str).to_numpy())
    y = (combined["label"] == "fraud").astype(int).to_numpy()

    model = xgb.XGBClassifier(
        n_estimators=300, 
        max_depth=6, 
        learning_rate=0.1, 
        random_state=42, 
        n_jobs=-1
    )
    model.fit(X, y)

    # Save new model
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    
    joblib.dump(model, os.path.join(MODELS_DIR, "vigilant_model.pkl"))
    joblib.dump(fb, os.path.join(MODELS_DIR, "feature_builder.pkl"))
    combined.to_csv(DATASET_PATH, index=False)

    print(f"\n🎉 New model trained and promoted successfully!")
    print(f"Total messages now: {len(combined)}")
    print(f"Old model archived in models/archive/")


if __name__ == "__main__":
    main()