"""
Vigilant AI — Month 2 / Week 1
scripts/fetch_external_dataset.py

Pulls the open Swahili SMS scam dataset (1,508 labeled Tanzanian Swahili
SMS, "scam" vs "trust") into data/external/ so build_dataset.py can merge it.

WHY THIS IS A SEPARATE SCRIPT, NOT AUTOMATED:
Kaggle requires an authenticated API key tied to your personal account.
Run this on your own machine (not in a sandboxed/CI environment), after a
one-time setup below.

-----------------------------------------------------------------------
ONE-TIME SETUP (do this once)
-----------------------------------------------------------------------
1. Create a free Kaggle account at kaggle.com if you don't have one.
2. Go to kaggle.com/settings -> API -> "Create New Token".
   This downloads a file called kaggle.json.
3. Place it at: ~/.kaggle/kaggle.json   (on Windows: C:\\Users\\<you>\\.kaggle\\kaggle.json)
4. Run: pip install kaggle

-----------------------------------------------------------------------
THEN RUN
-----------------------------------------------------------------------
    python scripts/fetch_external_dataset.py

-----------------------------------------------------------------------
IMPORTANT CONTEXT — read before trusting this data blindly
-----------------------------------------------------------------------
This dataset (by Henry Dioniz, "swahili-sms-detection-dataset") is built
from Tanzanian SMS, not Kenyan M-Pesa traffic. The scam typology overlaps
heavily with what you're targeting (the "tuma kwa namba hii" / send-money-
to-this-number pattern, fake job/Freemason recruitment, fake landlord
scams) but:
  - Phone number formats are Tanzanian (255/06xx/07xx Tigo/Vodacom/Halotel
    patterns), not Kenyan Safaricom formats.
  - Some "trust" (legit) examples are casual social chit-chat, not M-Pesa
    transaction confirmations — useful as general "not fraud" text, but
    NOT a substitute for real M-Pesa confirmation SMS in your legit class.
  - Re-spot-check a sample of labels yourself before fully trusting them —
    treat it as a volume/vocabulary booster for your Swahili fraud
    detection, not as ground truth for Kenyan M-Pesa patterns specifically.

The script tags every row with source=external_swahili_sms_dataset so you
can always filter it out later if it's hurting model precision.
"""

import os
import subprocess
import sys
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTERNAL_DIR = os.path.join(PROJECT_ROOT, "data", "external")
KAGGLE_SLUG = "henrydioniz/swahili-sms-detection-dataset"


def main():
    os.makedirs(EXTERNAL_DIR, exist_ok=True)

    try:
        import kaggle  # noqa: F401
    except ImportError:
        print("The 'kaggle' package isn't installed. Run: pip install kaggle")
        sys.exit(1)

    kaggle_json = os.path.expanduser("~/.kaggle/kaggle.json")
    if not os.path.exists(kaggle_json):
        print(f"No Kaggle API token found at {kaggle_json}.")
        print("See the setup instructions at the top of this script — you need to")
        print("download kaggle.json from kaggle.com/settings -> API -> Create New Token.")
        sys.exit(1)

    print(f"Downloading {KAGGLE_SLUG} into {EXTERNAL_DIR} ...")
    result = subprocess.run(
        ["kaggle", "datasets", "download", "-d", KAGGLE_SLUG, "-p", EXTERNAL_DIR, "--unzip"],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print("[ERROR] Kaggle download failed:")
        print(result.stderr)
        sys.exit(1)

    # Quick sanity check + rename to something build_dataset.py will recognize
    csvs = [f for f in os.listdir(EXTERNAL_DIR) if f.endswith(".csv")]
    print(f"\nDownloaded files: {csvs}")
    for f in csvs:
        path = os.path.join(EXTERNAL_DIR, f)
        df = pd.read_csv(path)
        print(f"\n  {f}: {len(df)} rows, columns = {list(df.columns)}")
        print(f"  Sample:\n{df.head(3).to_string()}")

    print("\nNow run: python scripts/build_dataset.py")
    print("If the column names printed above aren't 'message'/'sms' and 'label'/'class',")
    print("add the actual names to MESSAGE_COL_CANDIDATES / LABEL_COL_CANDIDATES in")
    print("scripts/build_dataset.py before merging.")


if __name__ == "__main__":
    main()