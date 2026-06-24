"""
Vigilant AI — Hyperparameter Tuning (Month 3 Week 4)
"""

import os
import sys
import json
from datetime import datetime
import pandas as pd
from scipy.stats import randint, uniform
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import make_scorer, recall_score
import xgboost as xgb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_engineering import FeatureBuilder

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "scam_dataset.csv")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
OUTPUT_PATH = os.path.join(MODELS_DIR, "best_hyperparameters.json")


def main():
    print("Loading dataset for hyperparameter tuning...")
    df = pd.read_csv(DATASET_PATH).dropna(subset=["message_text", "label"])
    df = df.drop_duplicates(subset=["message_text"])

    X_text = df["message_text"].astype(str).to_numpy(dtype=object)
    y = (df["label"] == "fraud").astype(int).to_numpy()

    print(f"Dataset: {len(df)} messages ({y.sum()} fraud)")

    fb = FeatureBuilder()
    X = fb.fit_transform(X_text)

    scale_pos_weight = float((y == 0).sum() / max((y == 1).sum(), 1))

    base_model = xgb.XGBClassifier(
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    param_dist = {
        "n_estimators": randint(100, 500),
        "max_depth": randint(3, 10),
        "learning_rate": uniform(0.01, 0.3),
        "min_child_weight": randint(1, 7),
        "subsample": uniform(0.6, 0.4),
        "colsample_bytree": uniform(0.6, 0.4),
    }

    search = RandomizedSearchCV(
        base_model,
        param_distributions=param_dist,
        n_iter=25,
        scoring=make_scorer(recall_score, zero_division=0),
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
        random_state=42,
        n_jobs=-1,
        verbose=1
    )

    print("Starting hyperparameter search (25 combinations)...")
    search.fit(X, y)

    best_params = search.best_params_
    best_recall = search.best_score_

    print("\n" + "="*60)
    print("BEST HYPERPARAMETERS FOUND")
    print("="*60)
    for k, v in best_params.items():
        print(f"  {k:20}: {v}")
    print(f"\nBest CV Recall: {best_recall:.1%}")

    with open(OUTPUT_PATH, "w") as f:
        json.dump({
            "best_params": best_params,
            "cv_recall": float(best_recall),
            "dataset_size": len(df),
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)

    print(f"\nResults saved to {OUTPUT_PATH}")
    print("Copy the best_params into train_model.py when ready.")


if __name__ == "__main__":
    main()