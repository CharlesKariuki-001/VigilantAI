"""
Vigilant AI — Dataset Merger
Merges all fraud + legit batch CSVs into one clean scam_dataset.csv
"""

import os
import pandas as pd
from datetime import datetime

# Paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw_Scams")

FRAUD_DIR = os.path.join(RAW_DIR, "fraud_batches")
LEGIT_DIR = os.path.join(RAW_DIR, "legit_batches")
OUTPUT_PATH = os.path.join(DATA_DIR, "scam_dataset.csv")


def load_and_normalize(file_path: str, source_type: str) -> pd.DataFrame:
    """Load CSV and ensure correct columns"""
    df = pd.read_csv(file_path)
    
    # Standardize column names
    df = df.rename(columns={
        "message_text": "message_text",
        "label": "label",
        "language": "language",
        "fraud_category": "fraud_category",
        "source": "source"
    })
    
    # Ensure required columns exist
    required = ["message_text", "label"]
    for col in required:
        if col not in df.columns:
            df[col] = ""
    
    # Fill missing columns
    if "language" not in df.columns:
        df["language"] = "mixed"
    if "fraud_category" not in df.columns:
        df["fraud_category"] = "other" if source_type == "fraud" else "n/a"
    if "source" not in df.columns:
        df["source"] = source_type
    
    df["date_collected"] = datetime.now().date().isoformat()
    
    return df[["message_text", "label", "language", "fraud_category", "source", "date_collected"]]


def main():
    print("🚀 Starting dataset merge...\n")
    
    all_dfs = []
    
    # Load Fraud batches
    if os.path.exists(FRAUD_DIR):
        fraud_files = [f for f in os.listdir(FRAUD_DIR) if f.endswith(".csv")]
        print(f"Found {len(fraud_files)} fraud batch files")
        for file in fraud_files:
            path = os.path.join(FRAUD_DIR, file)
            try:
                df = load_and_normalize(path, "fraud")
                all_dfs.append(df)
                print(f"  ✓ {file} → {len(df)} rows")
            except Exception as e:
                print(f"  ✗ Failed to load {file}: {e}")
    
    # Load Legit batches
    if os.path.exists(LEGIT_DIR):
        legit_files = [f for f in os.listdir(LEGIT_DIR) if f.endswith(".csv")]
        print(f"\nFound {len(legit_files)} legit batch files")
        for file in legit_files:
            path = os.path.join(LEGIT_DIR, file)
            try:
                df = load_and_normalize(path, "legit")
                all_dfs.append(df)
                print(f"  ✓ {file} → {len(df)} rows")
            except Exception as e:
                print(f"  ✗ Failed to load {file}: {e}")
    
    if not all_dfs:
        print("❌ No files found!")
        return
    
    # Combine everything
    combined = pd.concat(all_dfs, ignore_index=True)
    
    # Clean up
    combined = combined.drop_duplicates(subset=["message_text"], keep="first")
    combined = combined.dropna(subset=["message_text"])
    
    # Save
    combined.to_csv(OUTPUT_PATH, index=False)
    
    fraud_count = len(combined[combined["label"].str.lower() == "fraud"])
    legit_count = len(combined) - fraud_count
    
    print("\n" + "="*60)
    print("✅ MERGE COMPLETE!")
    print("="*60)
    print(f"Total messages          : {len(combined)}")
    print(f"Fraud messages          : {fraud_count}")
    print(f"Legit messages          : {legit_count}")
    print(f"Final file saved at     : {OUTPUT_PATH}")
    print("="*60)


if __name__ == "__main__":
    main()