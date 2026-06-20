"""
Vigilant AI — Month 2 / Week 1
scripts/build_dataset.py

Merges every data source into one canonical dataset at data/scam_dataset.csv,
following the schema in data/schema_README.md.

Run from the project root:
    python scripts/build_dataset.py

Sources it looks for (all optional — it merges whatever exists):
    data/raw_Scams/scam_examples.csv          <- your Month 1 collection
    data/external/*.csv                       <- external datasets you've downloaded
    data/synthetic/*.csv                      <- batches from Claude/ChatGPT (Day 5)
    data/community_reports.csv                <- "Report a scam" submissions, once wired up

It auto-detects common column name variants so it doesn't matter exactly how
your Month 1 CSV was structured. If it can't confidently detect a column, it
prints a warning and skips that file rather than guessing and corrupting your
dataset.
"""

import pandas as pd
import glob
import os
import sys
from datetime import date

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
OUTPUT_PATH = os.path.join(DATA_DIR, "scam_dataset.csv")

CANONICAL_COLUMNS = ["message_text", "label", "language", "fraud_category", "source", "date_collected"]

# Common column-name variants we'll auto-map. Add more here if your files use
# something different — this is intentionally simple/editable, not magic.
MESSAGE_COL_CANDIDATES = ["message_text", "message", "sms", "text", "content", "body"]
LABEL_COL_CANDIDATES = ["label", "class", "category", "is_fraud", "result", "status"]
LANGUAGE_COL_CANDIDATES = ["language", "lang"]
FRAUD_CATEGORY_CANDIDATES = ["fraud_category", "category", "type", "fraud_type"]

# Values that should normalize to "fraud" / "legit"
FRAUD_VALUE_ALIASES = {"fraud", "scam", "spam", "1", "true", "yes"}
LEGIT_VALUE_ALIASES = {"legit", "ham", "safe", "trust", "0", "false", "no"}


def _find_column(df_columns, candidates):
    lower_map = {c.lower().strip(): c for c in df_columns}
    for cand in candidates:
        if cand in lower_map:
            return lower_map[cand]
    return None


def _normalize_label(raw_value):
    val = str(raw_value).strip().lower()
    if val in FRAUD_VALUE_ALIASES:
        return "fraud"
    if val in LEGIT_VALUE_ALIASES:
        return "legit"
    return None  # unknown — caller decides whether to drop or flag


def normalize_file(path: str, default_source: str, default_language: str = "mixed") -> pd.DataFrame:
    """Load one CSV and normalize it to the canonical schema. Returns empty df on failure."""
    try:
        df = pd.read_csv(path)
    except Exception as e:
        print(f"  [SKIP] Could not read {path}: {e}")
        return pd.DataFrame(columns=CANONICAL_COLUMNS)

    msg_col = _find_column(df.columns, MESSAGE_COL_CANDIDATES)
    label_col = _find_column(df.columns, LABEL_COL_CANDIDATES)

    if msg_col is None:
        print(f"  [SKIP] {path}: couldn't find a message/text column. "
              f"Columns found: {list(df.columns)}. Add the real column name to "
              f"MESSAGE_COL_CANDIDATES in this script.")
        return pd.DataFrame(columns=CANONICAL_COLUMNS)

    if label_col is None:
        print(f"  [WARN] {path}: no label column found — every row will need manual "
              f"labeling in Label Studio before this file is usable for training.")

    lang_col = _find_column(df.columns, LANGUAGE_COL_CANDIDATES)
    cat_col = _find_column(df.columns, FRAUD_CATEGORY_CANDIDATES)

    out = pd.DataFrame()
    out["message_text"] = df[msg_col].astype(str).str.strip()

    if label_col is not None:
        out["label"] = df[label_col].apply(_normalize_label)
        unknown_count = out["label"].isna().sum()
        if unknown_count > 0:
            print(f"  [WARN] {path}: {unknown_count} rows had an unrecognized label value "
                  f"and were dropped. Check FRAUD_VALUE_ALIASES / LEGIT_VALUE_ALIASES.")
        out = out.dropna(subset=["label"])
    else:
        out["label"] = None
        out = out.dropna(subset=["label"])  # drops everything — forces explicit labeling first

    out["language"] = df[lang_col] if lang_col else default_language
    out["fraud_category"] = df[cat_col] if cat_col else "other"
    out.loc[out["label"] == "legit", "fraud_category"] = "n/a"
    out["source"] = default_source
    out["date_collected"] = date.today().isoformat()

    # Drop empty/duplicate messages within this file
    out = out[out["message_text"].str.len() > 3]
    out = out.drop_duplicates(subset=["message_text"])

    print(f"  [OK] {path}: {len(out)} usable rows ({(out['label']=='fraud').sum()} fraud / "
          f"{(out['label']=='legit').sum()} legit)")
    return out[CANONICAL_COLUMNS]


def main():
    print("=" * 70)
    print("VIGILANT AI — Dataset Builder (Month 2 / Week 1)")
    print("=" * 70)

    frames = []

    # 1. Month 1 collection
    month1_path = os.path.join(DATA_DIR, "raw_Scams", "scam_examples.csv")
    if os.path.exists(month1_path):
        print(f"\nProcessing Month 1 collection: {month1_path}")
        frames.append(normalize_file(month1_path, default_source="month1_collection"))
    else:
        print(f"\n[INFO] No file at {month1_path} — skipping Month 1 collection.")

    # 2. External datasets (anything you've dropped in data/external/)
    external_files = glob.glob(os.path.join(DATA_DIR, "external", "*.csv"))
    if external_files:
        print(f"\nProcessing {len(external_files)} external dataset file(s):")
        for f in external_files:
            tag = "external_swahili_sms_dataset" if "swahili" in f.lower() else "external_other"
            frames.append(normalize_file(f, default_source=tag, default_language="sw"))
    else:
        print(f"\n[INFO] No files in data/external/ yet. See scripts/fetch_external_dataset.py "
              f"for how to pull the Kaggle Swahili SMS dataset.")

    # 3. Synthetic batches (Day 5 output, Claude/ChatGPT generated)
    synthetic_files = glob.glob(os.path.join(DATA_DIR, "synthetic", "*.csv"))
    if synthetic_files:
        print(f"\nProcessing {len(synthetic_files)} synthetic batch file(s):")
        for f in synthetic_files:
            source_tag = "synthetic_claude" if "claude" in f.lower() else "synthetic_chatgpt"
            frames.append(normalize_file(f, default_source=source_tag))
    else:
        print(f"\n[INFO] No files in data/synthetic/ yet. Run the Day 5 prompt and save "
              f"output there as synthetic_claude_batch1.csv etc.")

    # 4. Community reports
    community_path = os.path.join(DATA_DIR, "community_reports.csv")
    if os.path.exists(community_path):
        print(f"\nProcessing community reports: {community_path}")
        frames.append(normalize_file(community_path, default_source="community_report"))

    frames = [f for f in frames if not f.empty]
    if not frames:
        print("\n[STOP] No usable data found anywhere. Add at least your Month 1 CSV "
              "to data/raw_Scams/scam_examples.csv and re-run.")
        sys.exit(1)

    combined = pd.concat(frames, ignore_index=True)
    before = len(combined)
    combined = combined.drop_duplicates(subset=["message_text"])
    after = len(combined)

    combined.to_csv(OUTPUT_PATH, index=False)

    print("\n" + "=" * 70)
    print(f"DONE. Wrote {after} rows to {OUTPUT_PATH}  ({before - after} cross-source duplicates removed)")
    print(f"  fraud : {(combined['label']=='fraud').sum()}")
    print(f"  legit : {(combined['label']=='legit').sum()}")
    print("\nBreakdown by fraud_category:")
    print(combined[combined["label"] == "fraud"]["fraud_category"].value_counts().to_string())
    print("\nBreakdown by language:")
    print(combined["language"].value_counts().to_string())
    print("=" * 70)


if __name__ == "__main__":
    main()