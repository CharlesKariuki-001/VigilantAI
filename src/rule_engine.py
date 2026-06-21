"""
Vigilant AI - Layer 1: Rule-Based M-Pesa / Mobile Money Scam Detector
======================================================================
Version 3.0 (Month 2, Week 2 - "Sophisticated Fakes" hardening)

WHAT CHANGED FROM v2 -> v3
---------------------------
v2 caught simple scams well (prize scams, PIN requests, job scams, etc.)
but missed a more dangerous class of attack: FORGED RECEIPTS -- messages
deliberately built to look almost exactly like a real M-PESA confirmation
SMS, with one of three subtle tells:

  (a) a duplicated/glued confirmation word or run-on sentence
      e.g. "...at 11:02 AM.Confirmed.You can now withdraw..."
  (b) a real-looking receipt with a refund/legal-threat sentence bolted on
      e.g. "...New M-PESA balance is Ksh12,450.00. Refund immediately to
      avoid legal action."
  (c) a malformed transaction code or currency format
      e.g. "UFO_9821_XYZ" (underscores -- real codes are 10 plain
      alphanumeric characters) or "Ksh. 8,000.00" (real M-PESA NEVER
      puts a period after "Ksh").

These are dealt with by a new "FORGED RECEIPT" rule family (weight 9-10)
that runs independently of whether the message *also* matches the
legit-signature whitelist -- a forged-receipt signal is treated as a
CRITICAL hit, which is exactly the kind of signal that is allowed to
override legit-protection (see `analyze()`).

NOTE ON A REMOVED v2 RULE: "Date Format Anomaly" (flagging DD/M/YY dates)
was removed rather than fixed. Real Safaricom M-PESA messages in Kenya
routinely use the short two-digit-year format (e.g. "18/6/26"), so this
rule was a guaranteed false-positive generator on genuine receipts. The
actual forgery signal is not the date FORMAT, it's things like duplicated
confirmation words, "Ksh." with a stray period, or malformed codes --
which are what the new FORGED RECEIPT rules check for directly.

DESIGN PRINCIPLES (carried over from v2, still true here)
-----------------------------------------------------------
1. WEIGHTED SCORING. Each rule carries a severity weight (1-10), not a
   flat "count x 20". A single PIN-request hit outweighs three weak
   urgency hits.

2. LEGITIMATE-MESSAGE PROTECTION. A message is only trusted as "SAFE"
   if it has the strict structural shape of a real receipt (code +
   confirmation word + balance line, or product-name + balance for
   system notices) AND contains no explicit money/PIN request AND
   contains no forged-receipt tell. Any CRITICAL rule (weight >= 9)
   overrides this protection.

3. BILINGUAL + REGIONAL. Patterns are written for English, Swahili, and
   Sheng, and for both Kenyan (Ksh, M-Shwari, Fuliza, Safaricom) and
   Tanzanian (TZS, Tigo Pesa, Halotel Pesa, Vodacom, M-Pawa, M-Koba)
   phrasing.

4. EXPLAINABLE OUTPUT. Every triggered rule returns category, weight,
   and a plain-language reason for the Streamlit "why was this flagged"
   panel.

5. SPECIFICITY OVER BREADTH. Every regex below is scoped with proximity
   windows and/or word boundaries specifically to avoid matching ordinary
   legitimate text (e.g. avoiding "ada ya" matching inside "baada ya").
"""

import re
from typing import Dict, List, Optional


class RuleEngine:
    """Vigilant AI - Layer 1: Rule-Based M-Pesa Scam Detector (v3.0)."""

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
                "name": "Forged Receipt - Refund/Legal Threat Appended",
                "category": "forged_receipt",
                "weight": 10,
                "pattern": re.compile(
                    r"(new\s?m-?pesa\s?balance\s?is|salio\s?jipya).{0,80}"
                    r"(refund\s?immediately|to\s?avoid\s?legal|legal\s?action|kuepuka\s?kesi|"
                    r"reverse\s?(this|the)?\s?(transaction|payment)|forward\s?this\s?message)"
                    r"|(refund\s?immediately|to\s?avoid\s?legal\s?action|legal\s?action\s?will\s?be\s?taken|"
                    r"kuepuka\s?kesi|forward\s?this\s?message\s?to)",
                    re.IGNORECASE,
                ),
                "explanation": "A real M-PESA transaction receipt NEVER threatens legal action or demands an immediate refund -- this sentence is bolted onto a fake receipt to scare you into sending money to the scammer.",
            },
            {
                "name": "Forged Receipt - Duplicated/Glued Confirmation",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"confirmed\b.{0,250}confirmed\b"  # "Confirmed" appearing twice in one message
                    r"|(am|pm)\.[a-z]"                  # time stamp glued directly into next sentence, e.g. "11:02 AM.Confirmed"
                    r"|\.[A-Z][a-z]+.{0,15}(can\s?now|sasa\s?unaweza)",  # ".You can now..." run-on with no space
                    re.IGNORECASE,
                ),
                "explanation": "Genuine M-PESA messages are generated by a single automated template and never contain a duplicated 'Confirmed' or sentences glued together without a space -- this is a sign of a hand-edited fake.",
            },
            {
                "name": "Forged Receipt - Malformed Transaction Code or Currency Format",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"\b[A-Z0-9]*_[A-Z0-9_]+\b.{0,30}confirmed"  # code containing an underscore, e.g. UFO_9821_XYZ
                    r"|\bksh\.\s?\d"                              # "Ksh." with a period -- real M-PESA never does this
                    r"|\btzs\.\s?\d",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA transaction codes are exactly 10 plain letters/numbers with no underscores or symbols, and the currency is always written 'Ksh1,234.00' -- never 'Ksh.' with a period. This message's formatting doesn't match the genuine Safaricom template.",
            },
            {
                "name": "Forged Receipt - Fake Bank-to-Wallet Deposit Phrasing",
                "category": "forged_receipt",
                "weight": 8,
                "pattern": re.compile(
                    r"deposited\s?to\s?your\s?wallet\s?from|imewekwa\s?kwenye\s?wallet\s?yako\s?kutoka",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA does not describe incoming bank funds as being 'deposited to your wallet' -- this phrasing does not match any genuine Safaricom/bank integration message and is commonly used in hybrid bank-impersonation fakes.",
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
                    r".{0,150}(processing\s?fee|activation\s?fee|insurance\s?fee|deposit\s?insurance|"
                    r"\bada\s?ya\b|\bbima\b|registration\s?fee|service\s?charge|kulipa\s?kwanza|"
                    r"clear(ed)?\s?a.{0,15}(charge|fee)|"
                    r"tuma\s?(ksh|kshs|tzs)?\s?\d)"
                    r"|(unahitaji\s?kulipa|lazima(\s?\w+){0,2}\s?(u)?lipe|must\s?(pay|clear)|you\s?must\s?clear)"
                    r".{0,200}(fuliza|m-?shwari|m-?pawa|loan|mkopo|fee|charge|insurance|bima)"
                    r"|(fuliza|m-?shwari|m-?pawa|loan|mkopo)"
                    r".{0,200}(unahitaji\s?kulipa|lazima(\s?\w+){0,2}\s?(u)?lipe|must\s?(pay|clear)|you\s?must\s?clear)",
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
                    r"\bada\s?ya\b|tuma\s?(ksh|kshs|tzs)|paybill|usafiri)",
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
                    r".{0,60}(registration\s?fee|\bada\s?ya\b|processing\s?fee|tuma\s?(ksh|kshs|tzs))",
                    re.IGNORECASE,
                ),
                "explanation": "Genuine scholarships and NGO grants do not require an upfront 'registration fee' sent via M-PESA.",
            },
            {
                "name": "Fake Reversal / Sent-By-Mistake Request",
                "category": "fake_wrong_number_send",
                "weight": 7,
                "pattern": re.compile(
                    r"(nimetuma|nilituma|sent|niliituma|tuma|ulipokea|umepokea|received)"
                    r".{0,60}(kwa\s?makosa|by\s?mistake|kimakosa|wrong\s?number|"
                    r"namba\s?isiyo\s?sahihi|badala\s?ya)"
                    r".{0,80}(rudisha|rejesha|return|send\s?back|nirudishie|namba\s?hii|"
                    r"tuma\s?kwa\s?namba|tuma)"
                    r"|reversal\s?request.{0,80}(piga|call|tuma)"
                    r"|(kimakosa|by\s?mistake|badala\s?ya).{0,80}(rudisha|rejesha|nirudishie|send\s?back)",
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
                    r"congratulations|selected|umechaguliwa|uliyoshinda|bahati\s?nasibu)"
                    r".{0,120}(ksh|kshs|tzs|shillings|elfu|million|\d{2,3},?\d{3})"
                    r".{0,80}?(tuma|send|fee|ada|claim|kupokea|processing|kulipia)?"
                    r"|(tuma|send).{0,40}(ksh|kshs|tzs)?.{0,30}(kulipia|\bada\s?ya\b).{0,40}"
                    r"(zawadi|bahati\s?nasibu|umeshinda|uliyoshinda|promo)",
                    re.IGNORECASE,
                ),
                "explanation": "You cannot win a cash prize, car, or gift by first sending a 'processing' or 'verification' fee -- legitimate promotions never work this way.",
            },
            {
                "name": "Send Money to Bare Number (No Official Receipt)",
                "category": "send_to_number_request",
                "weight": 7,
                "pattern": re.compile(
                    r"(tuma|send)\s?(kwa)?\s?(kwenye)?\s?(hii)?\s?namba"
                    r".{0,60}(ksh|kshs|tzs|\d{3,6})"
                    r".{0,80}(kulipia|\bada\s?ya\b|fee|deposit|usajili|processing|registration|"
                    r"insurance|activation|kuhamisha|transfer)",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA, delivery, or prize processes never require you to push money to a stranger's personal number to 'unlock' or 'process' something -- this is the single most common Kenyan/Tanzanian mobile-money scam pattern.",
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
                    r"(parcel|delivery|jumia|kilimall|courier|bidhaa|kufikishwa)"
                    r".{0,60}(pay|lipa|tuma|confirm|fees|ada|kulipia)"
                    r"|(pay|lipa|tuma|kulipia|fees|ada)"
                    r".{0,60}(parcel|delivery|jumia|kilimall|courier|bidhaa|kufikishwa)",
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
            r"\b(tuma|send|peleka|lipa|lipe|kulipa|kulipia)\b.{0,30}\b(ksh|kshs|tzs|pin|fee|ada|insurance|bima)\b"
            r"|\bpin\b.{0,20}\b(tuma|send|share)\b"
            r"|\b(lazima|unahitaji|must)\b.{0,20}\b(lipa|lipe|pay|clear)\b",
            re.IGNORECASE,
        )

        # Strict structural signature of a genuine M-PESA/Tigo Pesa/Halotel
        # transaction receipt. Requires a transaction-code-like token AND
        # a confirmation word AND a balance statement -- not just any one
        # of those words in isolation.
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
            r".{0,200}(balance|salio|deposit\s?of|imewekwa|successful|imefanikiwa)",
            re.IGNORECASE | re.DOTALL,
        )

    # ------------------------------------------------------------------
    # LEGITIMACY CHECK
    # ------------------------------------------------------------------
    def is_likely_legitimate(self, text: str) -> bool:
        """
        Returns True only if the message has the STRICT structural shape of
        a genuine transaction receipt / system notice AND contains no
        explicit request for money or PIN. Forged-receipt tells (handled
        separately as CRITICAL rules) are what ultimately override this in
        `analyze()` even when this structural check passes.
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

        # Legit-protection override: a real-looking receipt only gets
        # flagged if a CRITICAL-severity rule (weight >= 9) fired -- e.g.
        # a PIN request, a phishing link, or one of the forged-receipt
        # tells (duplicated confirmation, refund/legal threat, malformed
        # code/currency format). Anything below that bar is trusted as a
        # genuine receipt.
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
        # --- Genuine receipts (must stay SAFE) ---
        {"msg": "TB17CVOCY9 Confirmed. You have received Ksh2,500.00 from JOHN DOE 0712345678 on 18/6/26 at 3:42 PM. New M-PESA balance is Ksh4,500.00.", "sender": "MPESA", "expected": "SAFE"},
        {"msg": "M-Shwari: Your deposit of Ksh3,000.00 was successful on 18/6/26. Your M-Shwari savings balance is now Ksh18,500.00. Dial *334# for more options.", "sender": "MPESA", "expected": "SAFE"},
        {"msg": "QGH7K2MNB Confirmed. You have received Ksh1,000.00 from MARY WANJIRU 0722112233 on 18/6/26 at 9:15 AM. New M-PESA balance is Ksh3,210.00.", "sender": "MPESA", "expected": "SAFE"},

        # --- Sophisticated forged receipts (must be FRAUD) ---
        {"msg": "UFK9X7J4O2 Confirmed. You have received Ksh6,500.00 from GRACE WANJIKU 254722111222 on 21/6/26 at 11:02 AM.Confirmed.You can now withdraw at any agent.New M-PESA balance is Ksh6,730.00.", "sender": "0722111222", "expected": "FRAUD"},
        {"msg": "UFM8Z2Y1X4 Confirmed. You have received Ksh12,400.00 from DR. PETER KAMAU 254700999888 on 21/6/2026 at 8:20 AM. New M-PESA balance is Ksh12,450.00. Refund immediately to avoid legal action.", "sender": "0700999888", "expected": "FRAUD"},
        {"msg": "UFO_9821_XYZ Confirmed. Ksh. 8,000.00 has been deposited to your wallet from Equity Bank on 21/06/26 at 10:44 AM. New M-PESA balance is Ksh. 8,150.00. To check balance dial *334#.", "sender": "0711223344", "expected": "FRAUD"},

        # --- Classic scams (must be FRAUD) ---
        {"msg": "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.", "sender": "0712345678", "expected": "FRAUD"},
        {"msg": "Akaunti yako itafungwa leo kama hutathibitisha PIN.", "sender": "Safaricom", "expected": "FRAUD"},
        {"msg": "Loan yako imeapproved. Tuma Ksh 200 processing fee.", "sender": "0721123456", "expected": "FRAUD"},
        {"msg": "WEWE umechaguliwa kufanya kazi Dubai mshahara wa $2000. Tuma Ksh3,500 ada ya visa kwa Paybill 567890 Acc: JOBS2026.", "sender": "0700112233", "expected": "FRAUD"},
        {"msg": "Hujambo, mfungwa Kamiti Maximum anataka kuwasiliana nawe kuhusu urithi mkubwa. Piga 0798123456.", "sender": "0798123456", "expected": "FRAUD"},
        {"msg": "Habari, Polisi Trafiki, gari lako limepigwa picha ukivuka taa nyekundu, tuma Ksh3,000 fine kwa 0712009911.", "sender": "0712009911", "expected": "FRAUD"},
        {"msg": "Bonyeza hapa kuthibitisha M-Pesa yako: m-pesa-secure-update.com, vinginevyo akaunti itazimwa kesho.", "sender": "0789112233", "expected": "FRAUD"},
        {"msg": "NIMETUMA pesa kwa makosa kwa namba yako, tafadhali nirudishie Ksh2,000 kwa 0723445566.", "sender": "0723445566", "expected": "FRAUD"},
        {"msg": "Habari mzuri, umepata ufadhili wa masomo wa Ksh100,000 kutoka NGO ya kimataifa. Tuma Ksh1,500 ada ya usajili kwa 0734556688.", "sender": "0734556688", "expected": "FRAUD"},
        {"msg": "Habari, M-Shwari loan yako ya Ksh10,000 imeidhinishwa lakini lazima kwanza ulipe Ksh300 kuthibitisha akaunti.", "sender": "0745778899", "expected": "FRAUD"},
        {"msg": "Hongera mteja, umeshinda smartphone mpya kupitia promo ya Halotel. Tuma TZS5,000 ada ya ushuru kwa namba 0699112233 kupokea zawadi.", "sender": "0699112233", "expected": "FRAUD"},
    ]

    print("=" * 80)
    print("VIGILANT AI - RULE ENGINE v3.0 (Weighted, Forged-Receipt Hardened,")
    print("                                EN/SW/Sheng, KE+TZ)")
    print("=" * 80)

    passed = 0
    for case in test_cases:
        result = engine.analyze(case["msg"], case.get("sender"))
        ok = result["status"] == case["expected"]
        passed += int(ok)
        mark = "✅ PASS" if ok else "❌ FAIL"
        print(f"\n{mark} (expected {case['expected']}, got {result['status']})")
        print(f"📨 Sender : {case.get('sender', 'Unknown')}")
        print(f"Message   : {case['msg'][:95]}{'...' if len(case['msg']) > 95 else ''}")
        print(f"Status    : {result['status']} ({result['confidence']}) - Score: {result['score']}%")
        print(f"Advice    : {result['recommendation']}")
        if result["triggered_rules"]:
            print("Triggers:")
            for rule in sorted(result["triggered_rules"], key=lambda r: -r["weight"]):
                print(f"   • [{rule['category']}] {rule['name']} (w={rule['weight']}): {rule['explanation']}")
        print("-" * 80)

    print(f"\n{passed}/{len(test_cases)} test cases passed.")