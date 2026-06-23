"""
Vigilant AI — Storage Layer
Handles saving community reports and user feedback to CSV files.
Simple, robust, and production-ready.
"""

import csv
import os
from datetime import datetime
from typing import List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

COMMUNITY_REPORTS_PATH = os.path.join(DATA_DIR, "community_reports.csv")
FEEDBACK_LOG_PATH = os.path.join(DATA_DIR, "feedback_log.csv")


def _ensure_file(path: str, header: List[str]):
    """Create file with header if it doesn't exist"""
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)


def save_community_report(
    message_text: str, 
    sender: str = "", 
    user_believes_fraud: bool = True
):
    """Save a user-submitted scam report"""
    _ensure_file(COMMUNITY_REPORTS_PATH, [
        "message_text", "sender", "user_believes_fraud", 
        "status", "timestamp"
    ])
    
    with open(COMMUNITY_REPORTS_PATH, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            message_text.strip(),
            sender.strip() if sender else "",
            "fraud" if user_believes_fraud else "legit",
            "pending_review",
            datetime.now().isoformat(timespec="seconds")
        ])


def save_feedback(
    message_text: str,
    sender: str,
    predicted_label: str,
    correct_label: str,
    triggered_rules: List[dict],
    notes: str = ""
):
    """Save user feedback on a prediction"""
    _ensure_file(FEEDBACK_LOG_PATH, [
        "message_text", "sender", "predicted_label", 
        "correct_label", "triggered_rules", "notes", "timestamp"
    ])
    
    rules_str = "; ".join([r.get("name", str(r)) for r in triggered_rules]) if triggered_rules else ""
    
    with open(FEEDBACK_LOG_PATH, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            message_text.strip(),
            sender.strip() if sender else "",
            predicted_label,
            correct_label,
            rules_str,
            notes.strip(),
            datetime.now().isoformat(timespec="seconds")
        ])


def count_pending_reports() -> int:
    """Count how many community reports are still waiting for review"""
    if not os.path.exists(COMMUNITY_REPORTS_PATH):
        return 0
    try:
        with open(COMMUNITY_REPORTS_PATH, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        return sum(1 for row in rows if row.get("status") == "pending_review")
    except:
        return 0


def count_feedback_entries() -> int:
    """Count total feedback entries logged"""
    if not os.path.exists(FEEDBACK_LOG_PATH):
        return 0
    try:
        with open(FEEDBACK_LOG_PATH, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        return len(rows)
    except:
        return 0