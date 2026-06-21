"""
Vigilant AI - Storage Helper
==============================
Handles saving community-reported scam messages and user feedback on the
rule engine's verdicts to plain CSV files. No database needed at this
scale -- CSV is easy to inspect, diff in git, and later load straight
into pandas for the Phase 2 ML training pipeline.

Files live under <project_root>/data/, resolved relative to this file's
location so it works the same whether the app is launched from the
project root or from inside src/.
"""

import csv
import os
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

COMMUNITY_REPORTS_PATH = os.path.join(DATA_DIR, "community_reports.csv")
FEEDBACK_LOG_PATH = os.path.join(DATA_DIR, "feedback_log.csv")


def _ensure_file(path: str, header: list):
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)


def save_community_report(message: str, sender: str = "", believes_fraud: bool = True) -> None:
    """Store a scam (or suspected-scam) message reported by a user, pending review."""
    _ensure_file(
        COMMUNITY_REPORTS_PATH,
        ["message_text", "sender", "user_believes_fraud", "status", "timestamp"],
    )
    with open(COMMUNITY_REPORTS_PATH, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(
            [
                (message or "").strip(),
                (sender or "").strip(),
                "fraud" if believes_fraud else "legit",
                "pending_review",
                datetime.now().isoformat(timespec="seconds"),
            ]
        )


def save_feedback(
    message: str,
    sender: str,
    predicted: str,
    correct: str,
    triggered_rules: list,
    notes: str = "",
) -> None:
    """Log whether the rule engine's verdict matched what the user says is true."""
    _ensure_file(
        FEEDBACK_LOG_PATH,
        ["message_text", "sender", "predicted_label", "correct_label", "triggered_rules", "notes", "timestamp"],
    )
    with open(FEEDBACK_LOG_PATH, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(
            [
                (message or "").strip(),
                (sender or "").strip(),
                predicted,
                correct,
                "; ".join(r["name"] for r in triggered_rules) if triggered_rules else "",
                (notes or "").strip(),
                datetime.now().isoformat(timespec="seconds"),
            ]
        )


def count_pending_reports() -> int:
    """Number of community reports still awaiting review."""
    if not os.path.exists(COMMUNITY_REPORTS_PATH):
        return 0
    with open(COMMUNITY_REPORTS_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return sum(1 for row in rows if row.get("status") == "pending_review")


def count_feedback_entries() -> int:
    """Total number of feedback entries logged so far (used in the sidebar stats)."""
    if not os.path.exists(FEEDBACK_LOG_PATH):
        return 0
    with open(FEEDBACK_LOG_PATH, newline="", encoding="utf-8") as f:
        return max(sum(1 for _ in f) - 1, 0)  # subtract header row