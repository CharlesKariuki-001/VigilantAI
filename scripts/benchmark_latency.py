"""
Vigilant AI — Latency Benchmark (Month 3 Week 3)
"""

import os
import sys
import time
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from rule_engine import RuleEngine
from predict import HybridDetector

TEST_MESSAGES = [
    "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
    "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.",
    "Akaunti yako itafungwa leo kama hutathibitisha PIN.",
    "Hii ni jirani yako. Mama yako amepata ajali, tuma Ksh8,000 haraka.",
    "Tafadhali saidia watoto yatima. Tuma mchango kwa 0733888999.",
    "Nimetuma pesa kwa makosa, tafadhali nirudishie Ksh2,000.",
] * 8   # 48 runs for good average


def main():
    print("Loading models...\n")
    rule_engine = RuleEngine()
    detector = HybridDetector()
    print("Models loaded.\n")

    print("Benchmarking Rule Engine only...")
    rule_times = []
    for msg in TEST_MESSAGES:
        start = time.perf_counter()
        rule_engine.analyze(msg)
        rule_times.append((time.perf_counter() - start) * 1000)

    print("Benchmarking Full Hybrid (Rule + ML + SHAP)...")
    hybrid_times = []
    for msg in TEST_MESSAGES:
        start = time.perf_counter()
        detector.predict(msg)
        hybrid_times.append((time.perf_counter() - start) * 1000)

    def summarize(name, times):
        mean = statistics.mean(times)
        p95 = sorted(times)[int(len(times) * 0.95)]
        print(f"\n{name}")
        print(f"  Mean : {mean:.2f} ms")
        print(f"  P95  : {p95:.2f} ms")
        print(f"  Max  : {max(times):.2f} ms")

    summarize("Rule Engine Only", rule_times)
    summarize("Full Hybrid Pipeline", hybrid_times)

    print("\n" + "="*60)
    print("✅ Benchmark complete. Both should be well under 200ms.")
    print("="*60)


if __name__ == "__main__":
    main()
    