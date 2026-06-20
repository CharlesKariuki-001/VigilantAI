"""
Vigilant AI - Layer 1: Rule-Based M-Pesa / Mobile Money Scam Detector
======================================================================

Design philosophy (why this version is different from v1):

1. WEIGHTED SCORING, NOT "COUNT x 20".
   A single "PIN request" hit is far more dangerous than a single "haraka"
   (urgency) hit. Each rule now carries a severity weight (1-10). The final
   score is a normalized sum of weights, not a flat count. This is what
   lets us catch single-signal scams (e.g. one strong phrase) without
   needing 3-4 weak rules to fire together.

2. LEGITIMATE-MESSAGE PROTECTION (whitelist-first logic).
   Real M-PESA/Tigo Pesa/Airtel Money confirmations contain words like
   "now", "confirm", "agent", "till" that overlap with scam vocabulary.
   v1 flagged a real M-Shwari deposit SMS as fraud because of the word
   "now". This version checks for the STRICT structural signature of an
   official transaction receipt FIRST (txn code + "confirmed"/"imethibitishwa"
   + balance line) and, if matched, requires a much higher bar (an explicit
   money-request or PIN-request signal) before overriding it back to FRAUD.

3. CATEGORY COVERAGE FOR PREVIOUSLY WEAK AREAS.
   Built directly from the false-negative list in
   docs/rule_engine_mismatches.csv:
     - job_recruitment_scam        (Dubai/Qatar/Saudi "pay first" jobs)
     - prisoner_inheritance_scam   (Kamiti/Ukonga "inheritance" scams)
     - fake_authority_extortion    (fake Police/NTSA/KRA/KPLC fines)
     - fake_loan                   (Fuliza/M-Shwari/M-Pawa upfront-fee scams)
     - fake_wrong_number_send      ("sent by mistake, send it back")
     - phishing_link               (fake mpesa-secure-update.com style URLs)
     - fake_scholarship            (NGO/scholarship "registration fee")
   Each of these now has a dedicated, well-scoped regex rather than relying
   on broad generic rules.

4. BILINGUAL + REGIONAL (Kenya & Tanzania).
   Swahili and Sheng patterns are written to match both Kenyan phrasing
   (Ksh, M-Shwari, Fuliza, Safaricom) and Tanzanian phrasing (TZS, Tigo
   Pesa, Halotel Pesa, Vodacom, M-Pawa, M-Koba).

5. EXPLAINABLE OUTPUT.
   Every triggered rule returns its category, weight, and a short
   human-readable reason a non-technical user can understand -- this
   feeds directly into the Streamlit "why was this flagged" panel.
"""

import re
from typing import Dict, List, Optional


class RuleEngine:
    """Vigilant AI - Layer 1: Rule-Based M-Pesa Scam Detector (v2 - Deep Build)."""

    def __init__(self):
        self.rules: List[dict] = []
        self._load_rules()

    # ------------------------------------------------------------------
    # RULES
    # ------------------------------------------------------------------
    def _load_rules(self):
        """Load weighted scam-detection rules across all known categories."""
        self.rules = [

            # ===================== CRITICAL (weight 9-10) =====================
            {
                "name": "PIN / OTP Request",
                "category": "phishing_pin_request",
                "weight": 10,
                "pattern": re.compile(
                    r"\b(tuma|peleka|share|send|confirm|enter|weka)\b.{0,25}\b(pin|m-?pin|otp|password|siri)\b"
                    r"|\b(pin|otp|siri)\b.{0,25}\b(tuma|peleka|share|send|thibitisha)\b",
                    re.IGNORECASE,
                ),
                "explanation": "Legitimate M-PESA, Tigo Pesa, or Safaricom staff NEVER ask you to send your PIN or OTP via SMS, call, or link.",
            },
            {
                "name": "Phishing Link / Fake Verification URL",
                "category": "phishing_link",
                "weight": 9,
                "pattern": re.compile(
                    r"(https?://|www\.|bit\.ly|tinyurl|rebrand\.ly|tiny\.cc|shorturl|"
                    r"\b[a-z0-9-]+\.(com|net|co|info|xyz|online|site)\b)"
                    r".{0,40}(verify|secure|update|confirm|login|thibitisha)?"
                    r"|(verify|update|confirm|thibitisha).{0,15}(account|akaunti|mpesa).{0,15}"
                    r"(https?://|www\.|\.(com|net|co|info|xyz|online|site))",
                    re.IGNORECASE,
                ),
                "explanation": "Link sends you to a fake page designed to steal your M-PESA login or PIN. Official Safaricom/Vodacom never verify accounts via random links.",
            },
            {
                "name": "Fake Authority / Government Extortion",
                "category": "fake_authority_extortion",
                "weight": 9,
                "pattern": re.compile(
                    r"(polisi|police|askari|traffic|trafiki|ntsa|kra|kplc|nhif|nssf|huduma\s?namba|"
                    r"government|serikali|court|mahakama|magistrate)"
                    r".{0,60}(faini|fine|lipa|pay|tuma\s?ksh|tuma\s?tzs|refund|msamaha|kushtakiwa|"
                    r"kesi|nikuachilie|avoid.{0,10}(charge|case))",
                    re.IGNORECASE,
                ),
                "explanation": "Government agencies and police do not collect fines or bail through personal M-PESA numbers via SMS/call.",
            },
            {
                "name": "Prisoner / Inheritance Scam",
                "category": "prisoner_inheritance_scam",
                "weight": 9,
                "pattern": re.compile(
                    r"(mfungwa|prisoner|inmate|kamiti|ukonga|prison|jela)"
                    r".{0,80}(urithi|inheritance|mali|pesa\s?nyingi|fortune|wakili|advocate|lawyer)"
                    r"|(wakili|advocate|lawyer|daktari).{0,40}(kamiti|ukonga|prison|mfungwa)"
                    r".{0,60}(ada|fee|tuma|lipa)",
                    re.IGNORECASE,
                ),
                "explanation": "Classic 'prisoner left you an inheritance' social-engineering scam, common around Kamiti and Ukonga prisons.",
            },

            # ===================== HIGH (weight 7-8) =====================
            {
                "name": "Upfront Fee for Loan / Fuliza / M-Shwari",
                "category": "fake_loan",
                "weight": 8,
                "pattern": re.compile(
                    r"(fuliza|m-?shwari|m-?pawa|kcb\s?m-?pesa|mkopo|loan|credit)"
                    r".{0,60}(processing\s?fee|activation\s?fee|insurance\s?fee|deposit\s?insurance|"
                    r"ada\s?ya|bima|registration\s?fee|service\s?charge|kulipa\s?kwanza|"
                    r"tuma\s?(ksh|kshs|tzs)?\s?\d)",
                    re.IGNORECASE,
                ),
                "explanation": "Legitimate loan products (Fuliza, M-Shwari, M-Pawa, KCB M-Pesa) deduct fees automatically from the loan -- they never require you to pay an upfront fee to release funds.",
            },
            {
                "name": "Job / Recruitment Upfront Fee Scam",
                "category": "job_recruitment_scam",
                "weight": 8,
                "pattern": re.compile(
                    r"(job|kazi|vacancy|hiring|shortlisted|recruitment|hr|data\s?entry|"
                    r"dubai|qatar|saudi|abroad)"
                    r".{0,80}(processing\s?fee|registration\s?fee|training\s?fee|visa\s?fee|"
                    r"ada\s?ya|tuma\s?(ksh|kshs|tzs)|paybill|usafiri)",
                    re.IGNORECASE,
                ),
                "explanation": "A real employer never asks a candidate to pay a fee (visa, registration, training, travel) before being hired.",
            },
            {
                "name": "Fake Scholarship / Grant Fee",
                "category": "fake_scholarship",
                "weight": 8,
                "pattern": re.compile(
                    r"(scholarship|ufadhili|grant|ngo|bursary|masomo)"
                    r".{0,60}(registration\s?fee|ada\s?ya|processing\s?fee|tuma\s?(ksh|kshs|tzs))",
                    re.IGNORECASE,
                ),
                "explanation": "Genuine scholarships and NGO grants do not require an upfront 'registration fee' sent via M-PESA.",
            },
            {
                "name": "Fake Reversal / Sent-By-Mistake Request",
                "category": "fake_wrong_number_send",
                "weight": 7,
                "pattern": re.compile(
                    r"(nimetuma|nilituma|sent|niliituma|tuma).{0,40}(kwa\s?makosa|by\s?mistake|"
                    r"kimakosa|wrong\s?number|namba\s?isiyo\s?sahihi)"
                    r".{0,60}(rudisha|rejesha|return|send\s?back|nirudishie|namba\s?hii|"
                    r"tuma\s?kwa\s?namba)"
                    r"|reversal\s?request.{0,80}(piga|call|tuma)",
                    re.IGNORECASE,
                ),
                "explanation": "A genuine wrong transaction is reversed automatically by Safaricom/Vodacom support -- it is never resolved by you sending money to a 'reversal' number a stranger gives you.",
            },
            {
                "name": "Fake Prize / Promo Winner",
                "category": "fake_prize_winner",
                "weight": 7,
                "pattern": re.compile(
                    r"(umeshinda|hongera|won|winner|prize|jackpot|zawadi|bonasi|bonus|"
                    r"congratulations|selected|umechaguliwa)"
                    r".{0,80}(ksh|kshs|tzs|shillings|elfu|million|\d{2,3},?\d{3})"
                    r".{0,80}?(tuma|send|fee|ada|claim|kupokea|processing)?",
                    re.IGNORECASE,
                ),
                "explanation": "You cannot win a cash prize, car, or gift by first sending a 'processing' or 'verification' fee -- legitimate promotions never work this way.",
            },
            {
                "name": "Account Suspension / Lock Threat",
                "category": "account_suspension_threat",
                "weight": 7,
                "pattern": re.compile(
                    r"(account|akaunti|line|simu|sim|mpesa|m-?pesa)"
                    r".{0,40}(suspend|suspended|blocked|itafungwa|fungwa|locked|closed|"
                    r"terminate|deactivate|simamishwa|zimwa)",
                    re.IGNORECASE,
                ),
                "explanation": "Creates panic about losing access to your line/account so you act before thinking -- a classic pressure tactic.",
            },

            # ===================== MEDIUM (weight 4-6) =====================
            {
                "name": "Investment / Double-Your-Money Scam",
                "category": "investment_scam",
                "weight": 6,
                "pattern": re.compile(
                    r"(invest|investment|double\s?your\s?money|guaranteed\s?(profit|return)|"
                    r"business\s?opportunity|ongeza\s?pesa|zidisha\s?pesa)",
                    re.IGNORECASE,
                ),
                "explanation": "Promises of guaranteed or unrealistic returns are a hallmark of investment fraud.",
            },
            {
                "name": "Fake Delivery / Parcel Payment",
                "category": "fake_delivery_payment",
                "weight": 6,
                "pattern": re.compile(
                    r"(parcel|delivery|jumia|kilimall|courier|bidhaa).{0,50}"
                    r"(pay|lipa|tuma|confirm|fees|ada)",
                    re.IGNORECASE,
                ),
                "explanation": "Legitimate delivery services bill through their own app/checkout, not via a random number sent in an SMS.",
            },
            {
                "name": "Romance / Stranger Financial Help",
                "category": "romance_scam",
                "weight": 5,
                "pattern": re.compile(
                    r"(my love|darling|sweetheart|mpenzi).{0,40}(send|tuma|help me|nisaidie|money|pesa)",
                    re.IGNORECASE,
                ),
                "explanation": "Romance scams build trust quickly, then ask for money or financial 'help'.",
            },
            {
                "name": "Debt Collection Threat (Unverified)",
                "category": "fake_debt_collection",
                "weight": 5,
                "pattern": re.compile(
                    r"(deni|debt|loan).{0,40}(lipa\s?sasa|pay\s?now|crb|blacklist)",
                    re.IGNORECASE,
                ),
                "explanation": "Real CRB/loan recovery notices come through your bank/lender's official channel, not an unsolicited personal-number SMS demanding instant payment.",
            },
            {
                "name": "Safaricom / Vodacom Impersonation",
                "category": "impersonation",
                "weight": 5,
                "pattern": re.compile(
                    r"(safaricom|vodacom|customer\s?care|m-?pesa\s?support)"
                    r".{0,40}(verify|update|confirm|call\s?this|tuma)",
                    re.IGNORECASE,
                ),
                "explanation": "Official telco support does not initiate unsolicited SMS asking you to verify or update account details.",
            },
            {
                "name": "SIM Swap Warning",
                "category": "sim_swap",
                "weight": 5,
                "pattern": re.compile(r"(sim\s?swap|line\s?transferred|new\s?sim|sim\s?registered)", re.IGNORECASE),
                "explanation": "Used to panic victims into revealing personal/PIN details to 'protect' their line.",
            },

            # ===================== LOW / SUPPORTING (weight 1-3) =====================
            # These alone should rarely flip a message to FRAUD - they exist to
            # add weight when combined with a medium/high rule.
            {
                "name": "Urgency Pressure Language",
                "category": "urgency",
                "weight": 2,
                "pattern": re.compile(
                    r"\b(urgent|immediately|act\s?now|within\s?\d+\s?(minutes|hours|hrs)|"
                    r"haraka|sasa\s?hivi|leo\s?leo|kabla\s?ya|deadline)\b",
                    re.IGNORECASE,
                ),
                "explanation": "False urgency is used to stop victims from thinking clearly or verifying the message.",
            },
            {
                "name": "Personal Number Claims to Be M-PESA/Bank",
                "category": "sender_mismatch",
                "weight": 3,
                "pattern": re.compile(r"(this is|hii ni)\s?(m-?pesa|safaricom|vodacom|bank)", re.IGNORECASE),
                "explanation": "Genuine M-PESA/bank alerts come from the official short sender ID, never a message claiming 'this is M-PESA' from a personal number.",
            },
        ]

        # Money-request / PIN-request signal used to override legit-protection.
        self._override_pattern = re.compile(
            r"\b(tuma|send|peleka|lipa|pay)\b.{0,30}\b(ksh|kshs|tzs|pin|fee|ada)\b"
            r"|\bpin\b.{0,20}\b(tuma|send|share)\b",
            re.IGNORECASE,
        )

        # Strict structural signature of a genuine M-PESA/Tigo Pesa/Halotel
        # transaction receipt. Requires a transaction-code-like token AND
        # a confirmation word AND a balance statement -- not just any one
        # of those words in isolation (this is the bug that caused the
        # M-Shwari false positive in v1).
        self._legit_signature = re.compile(
            r"\b[A-Z0-9]{9,10}\b.{0,20}(confirmed|imethibitishwa)"
            r".{0,400}(new\s?m-?pesa\s?balance\s?is|salio\s?jipya)",
            re.IGNORECASE | re.DOTALL,
        )
        # Looser secondary signature for receipts without a leading code
        # (e.g. M-Shwari/Fuliza system notices), still requiring balance +
        # an official product name, with NO request-for-money language.
        self._legit_signature_soft = re.compile(
            r"(m-?shwari|fuliza|m-?pawa|m-?koba|lipa\s?mdogo\s?mdogo|pochi\s?la\s?biashara)"
            r".{0,200}(balance|salio|deposit|imewekwa|successful|imefanikiwa)",
            re.IGNORECASE | re.DOTALL,
        )

    # ------------------------------------------------------------------
    # LEGITIMACY CHECK
    # ------------------------------------------------------------------
    def is_likely_legitimate(self, text: str) -> bool:
        """
        Returns True only if the message has the STRICT structural shape of
        a genuine transaction receipt / system notice AND contains no
        explicit request for money or PIN.
        """
        has_structure = bool(self._legit_signature.search(text)) or bool(
            self._legit_signature_soft.search(text)
        )
        if not has_structure:
            return False
        if self._override_pattern.search(text):
            # Looks like a receipt but ALSO asks you to send something --
            # treat as suspicious, not legitimate.
            return False
        return True

    # ------------------------------------------------------------------
    # MAIN ANALYSIS
    # ------------------------------------------------------------------
    def analyze(self, message: str, sender: Optional[str] = None) -> Dict:
        message = (message or "").strip()
        triggered_rules = []
        total_weight = 0
        max_possible = sum(r["weight"] for r in self.rules) or 1

        # Suspicious sender: real M-PESA/Tigo Pesa messages come from a
        # short alphanumeric sender ID, not a personal 07xx/06xx number.
        if sender and re.search(r"^\+?(254|255)?0?7\d{8}$|^\+?(254|255)?0?6\d{8}$", str(sender).replace(" ", "")):
            triggered_rules.append(
                {
                    "name": "Personal Number Sender",
                    "category": "sender_mismatch",
                    "weight": 4,
                    "explanation": "Real M-PESA/Tigo Pesa/Vodacom messages come from 'M-PESA', 'Safaricom', or a short code -- never a personal phone number.",
                }
            )
            total_weight += 4

        for rule in self.rules:
            if rule["pattern"].search(message):
                triggered_rules.append(
                    {
                        "name": rule["name"],
                        "category": rule["category"],
                        "weight": rule["weight"],
                        "explanation": rule["explanation"],
                    }
                )
                total_weight += rule["weight"]

        legit = self.is_likely_legitimate(message)

        # Legit-protection override: a real receipt only gets flagged if a
        # CRITICAL-severity rule (weight >= 9) fired -- e.g. it also asks
        # for a PIN or contains a phishing link, which a real receipt never
        # does. Otherwise we trust the structural signature.
        critical_hit = any(r["weight"] >= 9 for r in triggered_rules)
        if legit and not critical_hit:
            return {
                "status": "SAFE",
                "confidence": "HIGH",
                "score": 0,
                "triggered_rules": [],
                "recommendation": "✅ This matches the structure of a genuine M-PESA/mobile-money notification. Still double-check the sender ID if in doubt.",
            }

        score = min(round((total_weight / max_possible) * 100 * 4), 100)  # scaled for readability

        if not triggered_rules:
            return {
                "status": "SAFE",
                "confidence": "MEDIUM",
                "score": 0,
                "triggered_rules": [],
                "recommendation": "✅ No known scam patterns detected. Still be cautious with unexpected messages.",
            }

        if total_weight >= 9 or len([r for r in triggered_rules if r["weight"] >= 7]) >= 1:
            confidence = "HIGH"
        elif total_weight >= 5:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return {
            "status": "FRAUD",
            "confidence": confidence,
            "score": score,
            "triggered_rules": triggered_rules,
            "recommendation": "⚠️ Do NOT reply, share your PIN, click any link, or send money. Verify independently via *334# or the official M-PESA app/customer care line printed on your SIM packaging.",
        }


# ==================== TESTING ====================
if __name__ == "__main__":
    engine = RuleEngine()

    test_cases = [
        {"msg": "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.", "sender": "0712345678"},
        {"msg": "Akaunti yako itafungwa leo kama hutathibitisha PIN.", "sender": "Safaricom"},
        {"msg": "Hongera! Umeshinda Ksh 200,000. Tuma haraka.", "sender": "Unknown"},
        {"msg": "TB17CVOCY9 Confirmed. You have received Ksh2,500.00 from JOHN DOE 0712345678 on 18/6/26 at 3:42 PM. New M-PESA balance is Ksh4,500.00.", "sender": "MPESA"},
        {"msg": "Loan yako imeapproved. Tuma Ksh 200 processing fee.", "sender": "0721123456"},
        {"msg": "M-Shwari: Your deposit of Ksh3,000.00 was successful on 18/6/26. Your M-Shwari savings balance is now Ksh18,500.00. Dial *334# for more options.", "sender": "MPESA"},
        {"msg": "WEWE umechaguliwa kufanya kazi Dubai mshahara wa $2000. Tuma Ksh3,500 ada ya visa kwa Paybill 567890 Acc: JOBS2026.", "sender": "0700112233"},
        {"msg": "Hujambo, mfungwa Kamiti Maximum anataka kuwasiliana nawe kuhusu urithi mkubwa. Piga 0798123456.", "sender": "0798123456"},
        {"msg": "Habari, Polisi Trafiki, gari lako limepigwa picha ukivuka taa nyekundu, tuma Ksh3,000 fine kwa 0712009911.", "sender": "0712009911"},
        {"msg": "Bonyeza hapa kuthibitisha M-Pesa yako: m-pesa-secure-update.com, vinginevyo akaunti itazimwa kesho.", "sender": "0789112233"},
        {"msg": "NIMETUMA pesa kwa makosa kwa namba yako, tafadhali nirudishie Ksh2,000 kwa 0723445566.", "sender": "0723445566"},
        {"msg": "Habari mzuri, umepata ufadhili wa masomo wa Ksh100,000 kutoka NGO ya kimataifa. Tuma Ksh1,500 ada ya usajili kwa 0734556688.", "sender": "0734556688"},
    ]

    print("=" * 78)
    print("VIGILANT AI - RULE ENGINE v2 (Weighted, Deep Build - 22 rule groups)")
    print("=" * 78)

    for case in test_cases:
        result = engine.analyze(case["msg"], case.get("sender"))
        print(f"\n📨 Sender : {case.get('sender', 'Unknown')}")
        print(f"Message   : {case['msg'][:95]}{'...' if len(case['msg']) > 95 else ''}")
        print(f"Status    : {result['status']} ({result['confidence']}) - Score: {result['score']}%")
        print(f"Advice    : {result['recommendation']}")
        if result["triggered_rules"]:
            print("Triggers:")
            for rule in result["triggered_rules"]:
                print(f"   • [{rule['category']}] {rule['name']} (w={rule['weight']}): {rule['explanation']}")
        print("-" * 78)