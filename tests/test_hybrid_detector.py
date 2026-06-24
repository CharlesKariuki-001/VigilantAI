"""
Vigilant AI — tests/test_hybrid_detector.py

Edge-case and regression tests for the hybrid detector.
Run before every retrain or deployment:
    python tests/test_hybrid_detector.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from predict import HybridDetector


def run_tests():
    detector = HybridDetector()
    failures = []

    def check(name, condition, detail=""):
        status = "PASS" if condition else "FAIL"
        print(f"  [{status}] {name} {detail}")
        if not condition:
            failures.append(name)

    # ================================================================
    # 1. CRASH SAFETY — must never raise an exception on weird input
    # ================================================================
    print("\n=== Crash safety: must not raise an exception on any input ===")
    crash_inputs = [
        "",
        "   ",
        "a",
        "OK",
        "12345",
        "😀😀😀" * 20,
        "A" * 3000,
        "\n\n\t\t",
        "<script>alert(1)</script>",
        "'; DROP TABLE messages; --",
        None,
    ]
    for inp in crash_inputs:
        safe_inp = inp if inp is not None else ""
        try:
            detector.predict(safe_inp)
            check(f"no crash on {repr(safe_inp)[:40]}", True)
        except Exception as e:
            check(f"no crash on {repr(safe_inp)[:40]}", False,
                  f"-> {type(e).__name__}: {e}")

    # ================================================================
    # 2. TRIVIAL INPUT — short/empty messages must not be marked FRAUD
    # ================================================================
    print("\n=== Trivial input must not be confidently flagged as FRAUD ===")
    trivial_inputs = ["", "   ", "a", "OK", "Hi", "😀😀😀"]
    for inp in trivial_inputs:
        result = detector.predict(inp)
        is_guarded = (
            result["status"] == "SAFE"
            or result.get("decided_by") == "rule_engine_only_insufficient_text"
        )
        check(
            f"trivial input {repr(inp):15} not FRAUD",
            is_guarded,
            f"-> got {result['status']} via {result.get('decided_by', 'unknown')}",
        )

    # ================================================================
    # 3. KNOWN FRAUD — regression check, these must always be caught
    # ================================================================
    print("\n=== Known fraud patterns must always be caught ===")
    known_fraud = [
        "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
        "Akaunti yako itafungwa leo kama hutathibitisha PIN.",
        "Piga *334*7# sasa kupokea zawadi yako.",
        "Loan yako imeapproved. Tuma Ksh 200 processing fee.",
        "KRA: Una refund ya Ksh 12,400. Jisajili na ID yako kupokea.",
    ]
    for msg in known_fraud:
        result = detector.predict(msg)
        check(
            f"catches fraud: {msg[:50]}",
            result["status"] == "FRAUD",
            f"-> got {result['status']}",
        )

    # ================================================================
    # 4. KNOWN LEGIT — regression check, these must never be flagged
    # ================================================================
    print("\n=== Known legitimate messages must never be flagged as FRAUD ===")
    known_legit = [
        "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.",
        "New M-PESA balance is Ksh4,500. Transaction cost, Ksh0.00.",
        "Nipigie nikuambie tutaonana wapi leo jioni.",
        "Asante kwa malipo, order yako iko njiani.",
    ]
    for msg in known_legit:
        result = detector.predict(msg)
        check(
            f"legit safe: {msg[:50]}",
            result["status"] == "SAFE",
            f"-> got {result['status']}",
        )

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "=" * 60)
    if failures:
        print(f"  {len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"    - {f}")
        sys.exit(1)
    else:
        print("  ALL CHECKS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()