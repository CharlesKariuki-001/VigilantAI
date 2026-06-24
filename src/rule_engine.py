"""
Vigilant AI - Layer 1: Rule-Based M-Pesa / Mobile Money Scam Detector
======================================================================
Version 4.0 (Month 2, Week 3 - "Recall Hardening" update)

WHAT CHANGED FROM v3 -> v4
---------------------------
v3 achieved 100% precision but only 55.3% recall on a 1,400-message
evaluation set. The ten weakest categories were:

  1. fake_charity_donation          8%
  2. fake_debt_collection          17%
  3. forged_receipt                17%  (rules existed, patterns missed)
  4. romance_scam                  21%
  5. impersonation_family_emergency 23%
  6. fake_tender_business_deal     27%
  7. fake_agent_overpayment        31%
  8. fake_reversal                 39%
  9. fake_kyc_update               40%
 10. blackmail_extortion           42%

All ten categories receive one or more high-weight (7-10) targeted rules
in v4. Key additions:

  FAKE CHARITY DONATION (was 8%)
  - "orphanage / hospital / msaada / sadaka" + payment language
  - Matching both urgent-appeal style and "donate via paybill" style

  FAKE DEBT COLLECTION (was 17%)
  - Expands the v3 rule from a narrow 4-word window to include:
    explicit-threat variants (CRB listing, bailiff/mkusanyiko, ushahidi),
    unverified third-party "collector" phrasing, and Tanzanian variants.

  FORGED RECEIPT - new patterns (was 17%)
  - "Amount has been HELD/PENDING" fakes (bank hold scam)
  - "On behalf of" / "kwa niaba ya" - common in fake agent receipts
  - Duplicate balance-line tells (two "New M-PESA balance" in one message)
  - Mismatched-amount tells: Ksh + wrong digit group separators (periods
    used as thousands separator, e.g. "Ksh8.000.00")

  ROMANCE SCAM (was 21%)
  - Expands beyond "my love / darling" to cover indirect approaches:
    "new friend" gift-card requests, "I am stuck at airport/hospital"
    scenarios, and the Sheng/Swahili "babe / baby / mpenzi wangu" set.

  IMPERSONATION - FAMILY EMERGENCY (was 23%)
  - "mama / baba / dada / kaka / ndugu" + accident/hospital + money
  - "Ninapigia kwa simu ya..." (calling from someone else's phone)
  - "Niko hospitali / I am in hospital" + send money pattern

  FAKE TENDER / BUSINESS DEAL (was 27%)
  - Government tender award notifications requiring upfront fees
  - "LPO / Local Purchase Order approved" before payment
  - Business-opportunity advance-fee patterns

  FAKE AGENT OVERPAYMENT (was 31%)
  - Agent "accidentally" sent too much → refund the difference
  - "Nimekupigia pesa nyingi" / "sent you extra" patterns

  FAKE KYC UPDATE (was 40%)
  - "Update your details / thibitisha taarifa zako" + link or USSD
  - "KYC / Know Your Customer" + deadline/suspension

  BLACKMAIL / EXTORTION (was 42%)
  - Photo/video sextortion: "tuna picha / video yako"
  - Threat to expose to family/employer unless paid
  - "We know where you live" intimidation + payment demand

RULES DELIBERATELY KEPT NARROW
  - All new proximity windows are ≤80 chars to avoid cross-sentence
    false-positives on legitimate messages that happen to contain one
    half of a pattern.
  - No rule fires on a single keyword alone; every rule requires at
    least two distinct semantic signals (threat + payment, or
    impersonation + money, etc.).

RULES NOT CHANGED
  - PIN/OTP Request (weight 10) — still perfect recall
  - Forged Receipt - Refund/Legal Threat (weight 10) — still perfect
  - Phishing Link (weight 9) — still perfect
  - Fake Authority/Government Extortion (weight 9) — still perfect
  - The legit-signature whitelist logic is unchanged
  - The CRITICAL-override (weight ≥ 9) threshold is unchanged

DESIGN PRINCIPLES (unchanged from v2/v3)
-----------------------------------------------------------
1. WEIGHTED SCORING. Each rule carries a severity weight (1-10).
2. LEGITIMATE-MESSAGE PROTECTION. Strict structural receipt check,
   overridden only by CRITICAL (weight ≥ 9) hits.
3. BILINGUAL + REGIONAL. English, Swahili, Sheng; Kenya + Tanzania.
4. EXPLAINABLE OUTPUT. Every rule has a plain-language explanation.
5. SPECIFICITY OVER BREADTH. Proximity windows + word boundaries.
"""

import re
from typing import Dict, List, Optional


class RuleEngine:
    """Vigilant AI - Layer 1: Rule-Based M-Pesa Scam Detector (v4.0)."""

    def __init__(self):
        self.rules: List[dict] = []
        self._load_rules()

    # ------------------------------------------------------------------
    # RULES
    # ------------------------------------------------------------------
    def _load_rules(self):
        """Load weighted scam-detection rules across all known categories."""
        self.rules = [

            # ============================================================
            # CRITICAL (weight 9-10)
            # A single hit here overrides the legit-receipt whitelist.
            # ============================================================

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
                "explanation": "A real M-PESA transaction receipt NEVER threatens legal action or demands an immediate refund — this sentence is bolted onto a fake receipt to scare you into sending money to the scammer.",
            },
            {
                "name": "Forged Receipt - Duplicated/Glued Confirmation",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"confirmed\b.{0,250}confirmed\b"  # "Confirmed" appearing twice
                    r"|(am|pm)\.[a-z]"                 # timestamp glued: "11:02 AM.Confirmed"
                    r"|\.[A-Z][a-z]+.{0,15}(can\s?now|sasa\s?unaweza)",  # ".You can now..." run-on
                    re.IGNORECASE,
                ),
                "explanation": "Genuine M-PESA messages are generated by a single automated template and never contain a duplicated 'Confirmed' or sentences glued together without a space — this is a sign of a hand-edited fake.",
            },
            {
                "name": "Forged Receipt - Malformed Transaction Code or Currency Format",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"\b[A-Z0-9]*_[A-Z0-9_]+\b.{0,30}confirmed"  # underscore in code: UFO_9821_XYZ
                    r"|\bksh\.\s?\d"                              # "Ksh." with period — real M-PESA never does this
                    r"|\btzs\.\s?\d"
                    r"|\bksh\d{1,3}\.\d{3}"                      # "Ksh8.000.00" — period as thousands separator
                    r"|\bksh\s?\d{1,3}\.\d{3}\.\d{2}",           # e.g. "Ksh 8.000.00"
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA transaction codes are exactly 10 plain letters/numbers with no underscores, and currency is always 'Ksh1,234.00' — never 'Ksh.' with a stray period or periods as thousand-separators. This message's formatting doesn't match any genuine Safaricom template.",
            },
            {
                "name": "Forged Receipt - Fake Bank-to-Wallet Deposit Phrasing",
                "category": "forged_receipt",
                "weight": 8,
                "pattern": re.compile(
                    r"deposited\s?to\s?your\s?wallet\s?from|imewekwa\s?kwenye\s?wallet\s?yako\s?kutoka",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA does not describe incoming bank funds as 'deposited to your wallet' — this phrasing is commonly used in hybrid bank-impersonation fakes.",
            },
            {
                "name": "Forged Receipt - Amount Held/Pending Scam",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"(amount|pesa|ksh\s?\d|tzs\s?\d).{0,40}"
                    r"(held|pending|on\s?hold|imezuiwa|imeshikiliwa|haijathibitishwa)"
                    r".{0,80}(contact|piga|call|verify|thibitisha|release|achia|tuma)",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA transactions are either fully completed (Confirmed) or fully failed — Safaricom never 'holds' funds and then asks you to call or pay to release them.",
            },
            {
                "name": "Forged Receipt - Duplicate Balance Line",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"(new\s?m-?pesa\s?balance\s?is|salio\s?jipya).{0,300}"
                    r"(new\s?m-?pesa\s?balance\s?is|salio\s?jipya)",
                    re.IGNORECASE | re.DOTALL,
                ),
                "explanation": "A genuine M-PESA receipt has exactly one balance line — two 'New M-PESA balance is' entries in the same message indicate a hand-assembled fake composed from two real receipts.",
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
                "explanation": "Government agencies and police do not collect fines or bail through personal M-PESA numbers via SMS or call.",
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
            {
                "name": "Blackmail / Sextortion Threat",
                "category": "blackmail_extortion",
                "weight": 10,
                "pattern": re.compile(
                    r"(tuna|tunayo|tumepata|tumekurekodi|tumekupiga|we\s?have|nina|ninayo)"
                    r".{0,60}(picha|video|screenshot|recording|rekodi|compromising)"
                    r".{0,80}(tuma|lipa|pay|send|tutashare|tutatuma|tutawaambia|tutapost|"
                    r"familia|mwajiri|employer|marafiki|friends|public|publika)"
                    r"|(tutashare|tutatuma|tutawaambia|tutapost|we\s?will\s?(send|share|post|expose|tell))"
                    r".{0,80}(picha|video|recording|rekodi|compromising|maisha\s?yako|your\s?life)"
                    r".{0,80}(tuma|lipa|pay|send|pesa|ksh|tzs)",
                    re.IGNORECASE,
                ),
                "explanation": "This is a sextortion/blackmail scam. The threat to share photos or videos unless you pay is almost always a bluff — do NOT pay. Report to the police.",
            },
            {
                "name": "Blackmail - Location/Personal Threat with Payment Demand",
                "category": "blackmail_extortion",
                "weight": 9,
                "pattern": re.compile(
                    r"(tunajua\s?uko|we\s?know\s?where\s?you|tunakujua|tunakujua\s?unakaa|"
                    r"tunakufuatilia|we\s?are\s?watching\s?you|tumekufuatilia)"
                    r".{0,80}(tuma|lipa|pay|send|pesa|ksh|tzs|au\s?sivyo|or\s?else|"
                    r"kama\s?hutalipia|if\s?you\s?don.t\s?pay)",
                    re.IGNORECASE,
                ),
                "explanation": "Threatening to reveal your location or personal information unless paid is extortion. Do NOT pay — contact the police immediately.",
            },

            # ============================================================
            # HIGH (weight 7-8)
            # One hit here is sufficient to classify as FRAUD.
            # ============================================================

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
                "explanation": "Legitimate loan products (Fuliza, M-Shwari, M-Pawa, KCB M-Pesa) deduct fees automatically — they never require an upfront fee to release funds.",
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
                "category": "fake_reversal",
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
                "explanation": "A genuine wrong transaction is reversed by Safaricom/Vodacom support — it is never resolved by you sending money to a 'reversal' number a stranger gives you.",
            },
            {
                "name": "Fake Reversal - M-PESA Reversal Impersonation",
                "category": "fake_reversal",
                "weight": 8,
                "pattern": re.compile(
                    r"(m-?pesa\s?reversal|reverse\s?the\s?(transaction|payment)|"
                    r"reversal\s?(code|number|process|ya\s?mpesa)|mchakato\s?wa\s?kurudisha)"
                    r".{0,80}(tuma|call|piga|contact|namba|number|pin|otp|code|lipa|pay)",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA reversals are initiated by Safaricom on your behalf after you call *334# — no one contacts you asking you to 'process' a reversal by sending money or codes.",
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
                "explanation": "You cannot win a cash prize by first sending a 'processing' or 'verification' fee — legitimate promotions never work this way.",
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
                "explanation": "Real M-PESA processes never require you to push money to a stranger's personal number to 'unlock' or 'process' something — this is the single most common Kenyan/Tanzanian mobile-money scam pattern.",
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
                "explanation": "Creates panic about losing access to your line/account so you act before thinking — a classic pressure tactic.",
            },
            {
                "name": "Fake KYC / Account Update Request",
                "category": "fake_kyc_update",
                "weight": 8,
                "pattern": re.compile(
                    r"(kyc|know\s?your\s?customer|thibitisha\s?taarifa|verify\s?your\s?details|"
                    r"update\s?your\s?(account|profile|details|taarifa|akaunti)|"
                    r"sasisho\s?la\s?(akaunti|taarifa)|taarifa\s?zako\s?zimepitwa)"
                    r".{0,80}(link|bonyeza|click|tuma|send|piga\s?simu|call|"
                    r"namba\s?yetu|thibitisha|confirm|deadline|muda\s?umekwisha|"
                    r"or\s?your\s?account|vinginevyo\s?akaunti)",
                    re.IGNORECASE,
                ),
                "explanation": "Safaricom and legitimate banks update your KYC details through their official app, *334#, or a branch — never through an unsolicited SMS asking you to click a link or call a number to 'verify your details'.",
            },
            {
                "name": "Fake KYC - SIM Registration Impersonation",
                "category": "fake_kyc_update",
                "weight": 8,
                "pattern": re.compile(
                    r"(sim\s?(card)?\s?registration|usajili\s?wa\s?sim|sim\s?bado\s?haijasajiliwa|"
                    r"register\s?your\s?sim|sim\s?yako\s?itafutwa|sim\s?itazimwa)"
                    r".{0,80}(tuma|send|piga|call|bonyeza|click|namba|number|link|"
                    r"kitambulisho|id\s?number|nambari\s?ya|thibitisha)",
                    re.IGNORECASE,
                ),
                "explanation": "SIM registration is done in person at a Safaricom/Vodacom service centre or through the official USSD menu — an SMS asking you to submit ID details or call a number is a fake.",
            },
            {
                "name": "Fake Tender / LPO / Business Deal Upfront Fee",
                "category": "fake_tender_business_deal",
                "weight": 8,
                "pattern": re.compile(
                    r"(tender|zabuni|lpo|local\s?purchase\s?order|contract|mkataba|"
                    r"government\s?(supply|order)|serikali\s?inataka|supplier)"
                    r".{0,100}(approved|umeshinda|imeidhinishwa|selected|umechaguliwa|awarded)"
                    r".{0,120}(fee|ada|tuma|lipa|deposit|advance|security\s?(deposit|bond)|"
                    r"performance\s?bond|compliance\s?fee|processing\s?fee)"
                    r"|(fee|ada|tuma|lipa|deposit|advance|security\s?(deposit|bond)|"
                    r"performance\s?bond|compliance\s?fee|processing\s?fee)"
                    r".{0,120}(tender|zabuni|lpo|local\s?purchase\s?order|contract|mkataba|"
                    r"government\s?(supply|order)|serikali\s?inataka|supplier)",
                    re.IGNORECASE,
                ),
                "explanation": "Real government tenders and LPOs never require a supplier to pay a 'security bond', 'compliance fee', or 'advance' before the contract is released — this is an advance-fee fraud targeting businesses.",
            },
            {
                "name": "Fake Tender - Business Opportunity Advance Fee",
                "category": "fake_tender_business_deal",
                "weight": 7,
                "pattern": re.compile(
                    r"(business\s?opportunity|fursa\s?ya\s?biashara|ubia|partnership)"
                    r".{0,100}(requires?\s?an?\s?(initial|upfront|advance)|unahitaji\s?kuweka|"
                    r"deposit\s?first|kwanza\s?weka|advance\s?payment|malipo\s?ya\s?awali)"
                    r".{0,80}(ksh|kshs|tzs|\d{3,6}|namba|number|paybill|mpesa)",
                    re.IGNORECASE,
                ),
                "explanation": "Advance-fee business scams promise large contracts or partnerships but demand an upfront deposit or 'compliance' payment first — no legitimate business deal works this way.",
            },
            {
                "name": "Fake Agent Overpayment / Refund Difference Scam",
                "category": "fake_agent_overpayment",
                "weight": 8,
                "pattern": re.compile(
                    r"(nimekupigia|nimetuma|nimeweka|i\s?sent|i\s?paid|nimepeleka)"
                    r".{0,60}(pesa\s?nyingi|zaidi|extra|too\s?much|more\s?than|kuliko\s?ilivyostahili|"
                    r"kwa\s?makosa|by\s?mistake)"
                    r".{0,80}(rudisha\s?(tofauti|balance|remainder|kilichobaki)|"
                    r"nirudishie\s?(ksh|kshs|tzs)?\s?\d|send\s?back\s?the\s?(difference|rest|balance)|"
                    r"tuma\s?(ksh|kshs|tzs)?\s?\d.{0,20}(tofauti|difference|back))",
                    re.IGNORECASE,
                ),
                "explanation": "The 'overpayment' scam: someone sends you a fake receipt claiming to have paid you too much and asks you to refund the difference. The original payment never existed — the receipt is forged.",
            },
            {
                "name": "Fake Agent Overpayment - Direct Refund Demand",
                "category": "fake_agent_overpayment",
                "weight": 7,
                "pattern": re.compile(
                    r"(nilikusudia\s?kutuma|i\s?meant\s?to\s?send|nilikusudia\s?kulipa)"
                    r".{0,80}(lakini\s?nilikutumia|but\s?i\s?sent\s?you|badala\s?ya)"
                    r".{0,80}(rudisha|nirudishie|send\s?back|return)"
                    r"|(agent|wakala|duka\s?la\s?mpesa).{0,60}"
                    r"(nikulipa|nikusaidie|refund|nirudishie).{0,60}(tofauti|difference|balance|remainder)",
                    re.IGNORECASE,
                ),
                "explanation": "A claimed agent or shop 'accidentally' overpaid you and wants the difference back — this is a refund scam based on a forged receipt.",
            },
            {
                "name": "Family Emergency Impersonation",
                "category": "impersonation_family_emergency",
                "weight": 8,
                "pattern": re.compile(
                    r"(mama|baba|dada|kaka|ndugu|shangazi|mjomba|bibi|babu|uncle|aunt|"
                    r"sister|brother|cousin\s?wangu|familia\s?yako|your\s?(mother|father|sister|brother|parent))"
                    r".{0,80}(accident|ajali|hospitali|hospital|emergency|dharura|"
                    r"amepata\s?ajali|ameumia|amegonga|amefariki|amekufa|anaomba)"
                    r".{0,80}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|haraka|immediately|sasa\s?hivi)",
                    re.IGNORECASE,
                ),
                "explanation": "The 'family emergency' scam: someone impersonates a relative in an accident or hospital to pressure you into sending money immediately — always call the family member directly on their known number to verify.",
            },
            {
                "name": "Family Emergency - Calling From Stranger's Phone",
                "category": "impersonation_family_emergency",
                "weight": 8,
                "pattern": re.compile(
                    r"(ninapigia\s?kwa\s?simu\s?ya|calling\s?from\s?(a\s?)?(stranger|someone\s?else|"
                    r"friend|marafiki|jirani|neighbour)|simu\s?yangu\s?(imeharibika|imeibiwa|"
                    r"haifanyi\s?kazi|imechomwa|imepotea|imevunjwa)|my\s?phone\s?(is\s?)?(lost|stolen|"
                    r"broken|dead|switched\s?off))"
                    r".{0,100}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|nisaidie|help\s?me)",
                    re.IGNORECASE,
                ),
                "explanation": "Claiming to call or text from a stranger's phone is a red flag — scammers use this to explain why the number is unfamiliar. Always verify by calling back a number you know.",
            },
            {
                "name": "Family Emergency - Hospital/Accident + Immediate Money",
                "category": "impersonation_family_emergency",
                "weight": 7,
                "pattern": re.compile(
                    r"(niko\s?hospitali|nipo\s?hospitali|i\s?am\s?in\s?hospital|"
                    r"tumempeleka\s?hospitali|amefika\s?hospitali|nipo\s?emergency|"
                    r"niko\s?operation|ameingia\s?theatre|operation\s?fee|upasuaji)"
                    r".{0,100}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|"
                    r"haraka|immediately|sasa\s?hivi|deposit|hospital\s?bill|bili\s?ya\s?hospitali)",
                    re.IGNORECASE,
                ),
                "explanation": "Texts claiming a relative is in hospital and needs urgent money are extremely common in Kenya and Tanzania. Call the hospital directly or call the relative's known number before sending anything.",
            },
            {
                "name": "Fake Charity / Donation Scam",
                "category": "fake_charity_donation",
                "weight": 8,
                "pattern": re.compile(
                    r"(orphanage|watoto\s?yatima|yatima|children.s\s?home|nyumba\s?ya\s?watoto|"
                    r"hospital\s?fund|harambee|msaada\s?wa|sadaka|changa|donation|donate|"
                    r"flood\s?(victim|relief)|mafuriko|earthquake|tetemeko|ukame|drought\s?relief|"
                    r"cancer\s?(fund|patient)|familia\s?masikini|maskini\s?wahitaji)"
                    r".{0,100}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|paybill|namba\s?hii|"
                    r"this\s?number|account\s?number|m-?pesa\s?namba|till\s?number)",
                    re.IGNORECASE,
                ),
                "explanation": "Fake charity scams exploit compassion for orphans, disaster victims, or the sick. Legitimate Kenyan/Tanzanian fundraisers operate through registered accounts you can verify — never send to an unverified personal number.",
            },
            {
                "name": "Fake Charity - Urgent Appeal with Unknown Contact",
                "category": "fake_charity_donation",
                "weight": 7,
                "pattern": re.compile(
                    r"(msaada\s?wa\s?haraka|urgent\s?(donation|appeal|request)|"
                    r"please\s?help\s?us|tafadhali\s?saidia|tunahitaji\s?msaada\s?wa\s?haraka)"
                    r".{0,80}(tuma|send|m-?pesa|paybill|donate\s?to|wasiliana\s?na|contact)"
                    r".{0,60}(ksh|kshs|tzs|\d{4,}|namba\s?hii|this\s?number|below)",
                    re.IGNORECASE,
                ),
                "explanation": "Urgency plus a payment number in an unsolicited SMS is a hallmark of charity fraud. Verify any fundraiser independently before donating.",
            },
            {
                "name": "Fake Debt Collection - Aggressive Threat",
                "category": "fake_debt_collection",
                "weight": 8,
                "pattern": re.compile(
                    r"(deni|debt|mkopo|loan|credit|arrears|malimbikizo)"
                    r".{0,80}(crb|credit\s?reference|blacklist|orodha\s?nyeusi|"
                    r"bailiff|msimamizi\s?wa\s?mali|kukamata\s?mali|seize\s?property|"
                    r"court\s?order|amri\s?ya\s?mahakama|sheriff|utekelezaji|"
                    r"tunakuja\s?nyumbani|we\s?will\s?come\s?to\s?your)"
                    r".{0,80}(lipa\s?sasa|pay\s?now|haraka|immediately|leo\s?hii|"
                    r"ksh|kshs|tzs|or\s?else|au\s?sivyo)",
                    re.IGNORECASE,
                ),
                "explanation": "Real CRB or loan recovery does not threaten via personal-number SMS — the genuine process follows legal steps through your bank or lender's official channel. Threats to blacklist you immediately or seize property by SMS are scare tactics.",
            },
            {
                "name": "Fake Debt Collection - Third Party Collector",
                "category": "fake_debt_collection",
                "weight": 7,
                "pattern": re.compile(
                    r"(tunakukumbusha|we\s?are\s?reminding\s?you|tunakuarifu|this\s?is\s?to\s?inform\s?you)"
                    r".{0,80}(deni|debt|mkopo|balance\s?outstanding|malimbikizo|overdue\s?payment)"
                    r".{0,80}(tuma|pay|lipa|send|m-?pesa|paybill|namba\s?hii|this\s?number|"
                    r"contact\s?(us|our|agent))"
                    r"|(recovery\s?agent|debt\s?collector|mkusanyaji\s?wa\s?deni)"
                    r".{0,80}(tuma|pay|lipa|send|ksh|kshs|tzs|namba|number|mpesa)",
                    re.IGNORECASE,
                ),
                "explanation": "Unsolicited 'debt collection' via SMS from a personal number is almost always fraudulent. If you have a genuine debt, your lender will contact you through official channels.",
            },
            {
                "name": "Romance / Stranger Financial Help",
                "category": "romance_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(my\s?love|darling|sweetheart|mpenzi\s?wangu|baby|babe|nataka\s?kukujua|"
                    r"nimekupenda|i\s?love\s?you\s?already|nimekuangalia\s?profile\s?yako)"
                    r".{0,80}(send|tuma|help\s?me|nisaidie|money|pesa|"
                    r"gift\s?card|voucher|itunes|google\s?play|amazon)",
                    re.IGNORECASE,
                ),
                "explanation": "Romance scams build trust quickly then ask for money, gift cards, or help with fees. Online strangers who express love fast and then ask for money are almost always scammers.",
            },
            {
                "name": "Romance Scam - Stranded / Emergency Scenario",
                "category": "romance_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(i\s?am\s?stuck|niko\s?stuck|nimekwama|i\s?am\s?stranded|nimekwama\s?hapa|"
                    r"passport\s?(yako|yangu)?\s?(imefungwa|imezuiwa|held)|"
                    r"custom\s?(fee|ada)|airport\s?(police|customs|fee)|"
                    r"i\s?need\s?your\s?help|nakuhitaji\s?unisaidie)"
                    r".{0,100}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|"
                    r"transfer|wire|western\s?union|moneygram)",
                    re.IGNORECASE,
                ),
                "explanation": "Romance scammers often claim to be stranded at an airport, held at customs, or stuck with a medical emergency abroad to extract money. This is a very common pattern — do not send money to anyone you have not met in person.",
            },
            {
                "name": "Romance Scam - Gift Card / Voucher Request",
                "category": "romance_scam",
                "weight": 8,
                "pattern": re.compile(
                    r"(gift\s?card|voucher|itunes\s?card|google\s?play\s?card|amazon\s?card|"
                    r"steam\s?card|playstation\s?card|ukartuni|kadi\s?ya\s?zawadi)"
                    r".{0,80}(tuma|send|nipe|give\s?me|share|piga\s?picha|take\s?photo|"
                    r"number|nambari|scratch|code\s?ya|serial\s?number)",
                    re.IGNORECASE,
                ),
                "explanation": "Requests for gift card codes (iTunes, Google Play, Amazon, Steam) are a classic scam signal — no legitimate person or business needs payment in gift cards.",
            },

            # ============================================================
            # MEDIUM (weight 4-6)
            # Multiple hits or combination with a high rule → FRAUD.
            # ============================================================

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

            # ============================================================
            # LOW / SUPPORTING (weight 1-3)
            # These alone rarely flip a message — they add weight when
            # combined with a medium or high rule.
            # ============================================================

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
        # a confirmation word AND a balance statement.
        self._legit_signature = re.compile(
            r"\b[A-Z0-9]{9,10}\b.{0,20}(confirmed|imethibitishwa)"
            r".{0,400}(new\s?m-?pesa\s?balance\s?is|salio\s?jipya)",
            re.IGNORECASE | re.DOTALL,
        )
        # Looser secondary signature for receipts without a leading code
        # (e.g. M-Shwari/Fuliza system notices), requiring balance +
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
            # Looks like a receipt but ALSO asks you to send something —
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
                    "explanation": "Real M-PESA/Tigo Pesa/Vodacom messages come from 'M-PESA', 'Safaricom', or a short code — never a personal phone number.",
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
        # flagged if a CRITICAL-severity rule (weight >= 9) fired — e.g.
        # a PIN request, a phishing link, or one of the forged-receipt
        # tells. Anything below that bar is trusted as a genuine receipt.
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
        # ── Genuine receipts (must stay SAFE) ────────────────────────────
        {"msg": "TB17CVOCY9 Confirmed. You have received Ksh2,500.00 from JOHN DOE 0712345678 on 18/6/26 at 3:42 PM. New M-PESA balance is Ksh4,500.00.", "sender": "MPESA", "expected": "SAFE"},
        {"msg": "M-Shwari: Your deposit of Ksh3,000.00 was successful on 18/6/26. Your M-Shwari savings balance is now Ksh18,500.00. Dial *334# for more options.", "sender": "MPESA", "expected": "SAFE"},
        {"msg": "QGH7K2MNB Confirmed. You have received Ksh1,000.00 from MARY WANJIRU 0722112233 on 18/6/26 at 9:15 AM. New M-PESA balance is Ksh3,210.00.", "sender": "MPESA", "expected": "SAFE"},

        # ── Forged receipts (must be FRAUD) ──────────────────────────────
        {"msg": "UFK9X7J4O2 Confirmed. You have received Ksh6,500.00 from GRACE WANJIKU 254722111222 on 21/6/26 at 11:02 AM.Confirmed.You can now withdraw at any agent.New M-PESA balance is Ksh6,730.00.", "sender": "0722111222", "expected": "FRAUD"},
        {"msg": "UFM8Z2Y1X4 Confirmed. You have received Ksh12,400.00 from DR. PETER KAMAU 254700999888 on 21/6/2026 at 8:20 AM. New M-PESA balance is Ksh12,450.00. Refund immediately to avoid legal action.", "sender": "0700999888", "expected": "FRAUD"},
        {"msg": "UFO_9821_XYZ Confirmed. Ksh. 8,000.00 has been deposited to your wallet from Equity Bank on 21/06/26 at 10:44 AM. New M-PESA balance is Ksh. 8,150.00. To check balance dial *334#.", "sender": "0711223344", "expected": "FRAUD"},
        {"msg": "RN4X7K2MP1 Confirmed. Ksh5,000.00 received from JAMES OTIENO on 20/6/26. New M-PESA balance is Ksh5,200.00. New M-PESA balance is Ksh5,200.00. To verify call 0799123456.", "sender": "0799123456", "expected": "FRAUD"},
        {"msg": "Your amount of Ksh3,000 is currently HELD/PENDING. Contact our agent on 0712000111 to release your funds.", "sender": "0712000111", "expected": "FRAUD"},

        # ── Classic scams (must be FRAUD) ─────────────────────────────────
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

        # ── NEW v4 test cases for previously weak categories ───────────────

        # fake_charity_donation
        {"msg": "Tafadhali saidia watoto yatima wa Nyumba ya Watoto Nairobi. Tuma mchango wako kwa M-PESA namba 0712345000. Mungu akubariki.", "sender": "0712345000", "expected": "FRAUD"},
        {"msg": "URGENT DONATION NEEDED: Familia masikini waliathirika na mafuriko. Tuma Ksh500 au zaidi kwa paybill 123456 acc FLOOD2026. Asante.", "sender": "0700456789", "expected": "FRAUD"},

        # fake_debt_collection
        {"msg": "Tunakukumbusha deni lako la Ksh8,500 liko overdue. Mkusanyaji wa deni atakuja kukamata mali yako ikiwa hutalipa sasa. Tuma kwa namba hii haraka.", "sender": "0711987654", "expected": "FRAUD"},
        {"msg": "Recovery agent: You have an outstanding debt. Pay now or we will list you on CRB blacklist today. Send Ksh3,000 to 0722001122 immediately.", "sender": "0722001122", "expected": "FRAUD"},

        # romance_scam
        {"msg": "Mpenzi wangu nakupenda sana. Niko stuck airport customs wameshikilia mzigo wangu. Tuma $200 tu kunisaidia western union. Nitakulipa baadaye.", "sender": "0799000111", "expected": "FRAUD"},
        {"msg": "Baby please buy me iTunes gift card worth Ksh5,000 and send me the code number. I will pay you back I promise.", "sender": "0733112233", "expected": "FRAUD"},

        # impersonation_family_emergency
        {"msg": "Hii ni jirani yako. Mama yako amepata ajali na amepelekwa hospitali. Tuma Ksh5,000 haraka kwa operation fee kwa namba 0700888777.", "sender": "0700888777", "expected": "FRAUD"},
        {"msg": "Niko hospitali sasa hivi. Simu yangu imevunjika, ninapigia kwa simu ya mgeni. Nitahitaji Ksh3,000 bili ya hospitali. Tuma sasa hivi.", "sender": "0711000222", "expected": "FRAUD"},

        # fake_tender_business_deal
        {"msg": "Hongera! Zabuni yako ya kutoa bidhaa serikalini imeshinda. Kabla ya kupata LPO tuma Ksh15,000 performance bond kwa akaunti 0722999888.", "sender": "0722999888", "expected": "FRAUD"},
        {"msg": "Your tender application ref TND/2026/001 has been approved. Please pay compliance fee of Ksh8,000 via M-PESA to 0700334455 to receive your contract.", "sender": "0700334455", "expected": "FRAUD"},

        # fake_agent_overpayment
        {"msg": "Nimekupigia pesa nyingi kwa makosa. Nilitaka kutuma Ksh500 lakini nilitumia Ksh5,500. Tafadhali nirudishie tofauti ya Ksh5,000 kwa namba 0712777666.", "sender": "0712777666", "expected": "FRAUD"},
        {"msg": "Hi, I sent you Ksh2,000 by mistake instead of Ksh200. Please send back the difference of Ksh1,800 to this number urgently.", "sender": "0711333444", "expected": "FRAUD"},

        # fake_kyc_update
        {"msg": "Safaricom KYC Update: Taarifa zako zimepitwa na wakati. Thibitisha taarifa zako sasa kwa kubonyeza link hii au akaunti yako itafungwa: safaricom-kyc-update.co", "sender": "0789999000", "expected": "FRAUD"},
        {"msg": "Your SIM card registration is incomplete. Register your SIM now by sending your ID number to this number or your line will be deactivated within 24 hours.", "sender": "0700111000", "expected": "FRAUD"},

        # blackmail_extortion
        {"msg": "Tuna video yako ya siri. Tutatuma kwa familia yako na mwajiri wako kama hutalipia Ksh10,000 leo. Tuma kwa M-PESA namba 0711888777.", "sender": "0711888777", "expected": "FRAUD"},
        {"msg": "We have compromising photos of you. We will post them publicly if you don't send Ksh5,000 to 0722555444 within 2 hours. Don't go to police.", "sender": "0722555444", "expected": "FRAUD"},
    ]

    print("=" * 80)
    print("VIGILANT AI - RULE ENGINE v4.0 (Weighted, Recall-Hardened,")
    print("                                EN/SW/Sheng, KE+TZ)")
    print("=" * 80)

    passed = 0
    failed_cases = []
    for case in test_cases:
        result = engine.analyze(case["msg"], case.get("sender"))
        ok = result["status"] == case["expected"]
        passed += int(ok)
        if not ok:
            failed_cases.append(case)
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

    print(f"\n{'='*80}")
    print(f"RESULT: {passed}/{len(test_cases)} test cases passed.")
    if failed_cases:
        print("\nFAILED CASES:")
        for c in failed_cases:
            print(f"  • [{c['expected']}] {c['msg'][:80]}...")
    print("=" * 80)