"""
Vigilant AI - Layer 1: Rule-Based M-Pesa / Mobile Money Scam Detector
======================================================================
Version 5.0 (Month 2, Week 3 - "Recall Surge" update)

WHAT CHANGED FROM v4 -> v5
---------------------------
v4 reached 100% precision but only 63.0% recall on 1,400 messages.
The remaining weak categories and their v4 recall:

  FORGED RECEIPT             17%  → Massive new pattern coverage
  FAKE DEBT COLLECTION       19%  → Broader threat + collector vocab
  FAKE TENDER/BUSINESS       27%  → More upfront-fee phrasing
  FAKE AGENT OVERPAYMENT     31%  → More "sent too much" variants
  IMPERSONATION FAMILY EMG   38%  → More emergency + borrow phrasing
  FAKE REVERSAL              41%  → More "wrong send" + reversal scam
  FAKE KYC UPDATE            40%  → More verification/update hooks
  BLACKMAIL / EXTORTION      42%  → More threat vocabulary
  ROMANCE SCAM               ~50% → More grooming + request patterns
  INVESTMENT SCAM            ~50% → More MLM/ponzi language
  FAKE PRIZE WINNER          ~55% → More "claim" variants
  JOB / RECRUITMENT          ~55% → More overseas-job fee patterns
  FAKE LOAN                  ~60% → More fee-upfront variants

STRATEGY FOR v5
  1. Each weak category gets 1–3 ADDITIONAL rules OR significant
     expansion of existing patterns.
  2. Proximity windows are loosened from {0,60} → {0,120} where the
     two signals (threat + payment) rarely appear on their own.
  3. New synonym chains cover Sheng, Kiswahili dialects, and Tanzanian
     Swahili variants that v4 missed.
  4. A new "catch-all" moderate-weight rule targets the universal
     "send money to this number" pattern more broadly.
  5. Every new rule still requires dual semantic signals to preserve
     100% precision.

DESIGN PRINCIPLES (unchanged)
  1. WEIGHTED SCORING (1–10)
  2. LEGIT-RECEIPT PROTECTION overridden only by weight ≥ 9 CRITICAL hits
  3. BILINGUAL + REGIONAL (English / Swahili / Sheng; KE + TZ)
  4. EXPLAINABLE OUTPUT
  5. SPECIFICITY: proximity windows + word boundaries
"""

import re
from typing import Dict, List, Optional


class RuleEngine:
    """Vigilant AI - Layer 1: Rule-Based M-Pesa Scam Detector (v5.0)."""

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
                    r"\b(tuma|peleka|share|send|confirm|enter|weka|toa|provide|nipe)\b.{0,30}"
                    r"\b(pin|m-?pin|otp|password|siri|namba\s?ya\s?siri|secret\s?number|"
                    r"activation\s?code|verification\s?code|code\s?ya\s?uthibitisho)\b"
                    r"|\b(pin|otp|siri|password)\b.{0,30}"
                    r"\b(tuma|peleka|share|send|thibitisha|confirm|weka|nipe)\b",
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
                "explanation": "A real M-PESA receipt NEVER threatens legal action or demands an immediate refund — this is bolted onto a fake receipt to scare you into sending money.",
            },
            {
                "name": "Forged Receipt - Duplicated/Glued Confirmation",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"confirmed\b.{0,250}confirmed\b"
                    r"|(am|pm)\.[a-z]"
                    r"|\.[A-Z][a-z]+.{0,15}(can\s?now|sasa\s?unaweza)",
                    re.IGNORECASE,
                ),
                "explanation": "Genuine M-PESA messages never contain a duplicated 'Confirmed' or sentences glued together — this is a hand-edited fake.",
            },
            {
                "name": "Forged Receipt - Malformed Transaction Code or Currency Format",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"\b[A-Z0-9]*_[A-Z0-9_]+\b.{0,30}confirmed"
                    r"|\bksh\.\s?\d"
                    r"|\btzs\.\s?\d"
                    r"|\bksh\d{1,3}\.\d{3}"
                    r"|\bksh\s?\d{1,3}\.\d{3}\.\d{2}",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA codes are 10 plain alphanumeric chars (no underscores), and currency is 'Ksh1,234.00' — never 'Ksh.' with a stray period or periods as thousand-separators.",
            },
            {
                "name": "Forged Receipt - Fake Bank-to-Wallet Deposit Phrasing",
                "category": "forged_receipt",
                "weight": 8,
                "pattern": re.compile(
                    r"deposited\s?to\s?your\s?wallet\s?from|imewekwa\s?kwenye\s?wallet\s?yako\s?kutoka",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA does not say 'deposited to your wallet' — this is hybrid bank-impersonation fake phrasing.",
            },
            {
                "name": "Forged Receipt - Amount Held/Pending Scam",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"(amount|pesa|ksh\s?\d|tzs\s?\d|funds|malipo|fedha).{0,60}"
                    r"(held|pending|on\s?hold|imezuiwa|imeshikiliwa|haijathibitishwa|"
                    r"processing|inashughulikiwa|under\s?review|inachunguzwa)"
                    r".{0,100}(contact|piga|call|verify|thibitisha|release|achia|tuma|"
                    r"piga\s?simu|wasiliana|namba\s?hii|this\s?number)",
                    re.IGNORECASE,
                ),
                "explanation": "Safaricom never 'holds' funds — transactions are either Confirmed or failed. Anyone asking you to call/pay to release 'held' funds is a scammer.",
            },
            {
                "name": "Forged Receipt - Duplicate Balance Line",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"(new\s?m-?pesa\s?balance\s?is|salio\s?jipya|balance\s?is\s?ksh).{0,300}"
                    r"(new\s?m-?pesa\s?balance\s?is|salio\s?jipya|balance\s?is\s?ksh)",
                    re.IGNORECASE | re.DOTALL,
                ),
                "explanation": "A genuine receipt has exactly one balance line — two balance lines = hand-assembled fake from two real receipts.",
            },
            {
                "name": "Forged Receipt - 'On Behalf Of' Agent Fake",
                "category": "forged_receipt",
                "weight": 8,
                "pattern": re.compile(
                    r"(on\s?behalf\s?of|kwa\s?niaba\s?ya|acting\s?as\s?agent\s?for)"
                    r".{0,100}(confirmed|imewekwa|imethibitishwa|received|umepokea)"
                    r".{0,100}(tuma|rudisha|refund|rejesha|send\s?back|nirudishie|wasiliana)",
                    re.IGNORECASE,
                ),
                "explanation": "Genuine M-PESA receipts are sent directly by Safaricom — no agent acts 'on behalf of' the system to collect money from you.",
            },
            {
                "name": "Forged Receipt - Suspicious Instruction After Balance",
                "category": "forged_receipt",
                "weight": 9,
                "pattern": re.compile(
                    r"(new\s?m-?pesa\s?balance|salio\s?jipya|new\s?balance).{0,150}"
                    r"(tuma|send|rudisha|rejesha|piga\s?simu|call|contact|wasiliana|"
                    r"lipa|pay|namba\s?hii|this\s?number|our\s?agent|wakala\s?wetu)",
                    re.IGNORECASE | re.DOTALL,
                ),
                "explanation": "A genuine receipt only tells you your new balance — it NEVER follows up with an instruction to send money, call a number, or contact an agent.",
            },
            {
                "name": "Forged Receipt - Wrong/Short Transaction Code",
                "category": "forged_receipt",
                "weight": 8,
                "pattern": re.compile(
                    r"\b(confirmed|imethibitishwa)\b.{0,30}"
                    r"(?!\b[A-Z0-9]{9,10}\b)"  # absence of valid 9-10 char code
                    r"(ksh|tzs)\s?\d.{0,60}"
                    r"(send|tuma|rudisha|refund|call|piga|contact|wasiliana)",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA 'Confirmed' messages always have a valid 9–10 character alphanumeric transaction code — a fake receipt without one that also requests action is suspicious.",
            },
            {
                "name": "Forged Receipt - Pesa Imewasili / Funds Arrived Fake",
                "category": "forged_receipt",
                "weight": 8,
                "pattern": re.compile(
                    r"(pesa\s?imewasili|fedha\s?zimepokelewa|funds?\s?have\s?(been\s?)?(received|arrived)|"
                    r"payment\s?(has\s?been\s?)?received\s?successfully|malipo\s?yamepokelewa)"
                    r".{0,150}(tuma|rudisha|send\s?back|nirudishie|lipa|pay|"
                    r"contact|piga\s?simu|wasiliana|namba\s?hii|this\s?number|agent|wakala)",
                    re.IGNORECASE,
                ),
                "explanation": "A fake 'funds received' notification is often sent before the real payment to trick you into dispatching goods or money — real receipts never ask you to do anything in return.",
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
                "explanation": "Link sends you to a fake page to steal your M-PESA login or PIN. Official Safaricom/Vodacom never verify accounts via random links.",
            },
            {
                "name": "Fake Authority / Government Extortion",
                "category": "fake_authority_extortion",
                "weight": 9,
                "pattern": re.compile(
                    r"(polisi|police|askari|traffic|trafiki|ntsa|kra|kplc|nhif|nssf|huduma\s?namba|"
                    r"government|serikali|court|mahakama|magistrate|ura|tra|tanroads|"
                    r"immigration|uhamiaji|dci|interpol|efcc|anti.?corruption)"
                    r".{0,80}(faini|fine|lipa|pay|tuma\s?ksh|tuma\s?tzs|refund|msamaha|"
                    r"kushtakiwa|kesi|nikuachilie|avoid.{0,10}(charge|case)|"
                    r"settle|malipo\s?ya|ada\s?ya|tosha)",
                    re.IGNORECASE,
                ),
                "explanation": "Government agencies and police do not collect fines or bail through personal M-PESA numbers via SMS.",
            },
            {
                "name": "Prisoner / Inheritance Scam",
                "category": "prisoner_inheritance_scam",
                "weight": 9,
                "pattern": re.compile(
                    r"(mfungwa|prisoner|inmate|kamiti|ukonga|prison|jela|remand|kingolwira)"
                    r".{0,80}(urithi|inheritance|mali|pesa\s?nyingi|fortune|wakili|advocate|lawyer)"
                    r"|(wakili|advocate|lawyer|daktari).{0,40}(kamiti|ukonga|prison|mfungwa)"
                    r".{0,60}(ada|fee|tuma|lipa)",
                    re.IGNORECASE,
                ),
                "explanation": "Classic 'prisoner left you an inheritance' scam, common around Kamiti and Ukonga prisons.",
            },
            {
                "name": "Blackmail / Sextortion Threat",
                "category": "blackmail_extortion",
                "weight": 10,
                "pattern": re.compile(
                    r"(tuna|tunayo|tumepata|tumekurekodi|tumekupiga|we\s?have|nina|ninayo|"
                    r"tumekuona|tumekufanya|we\s?recorded|tumefanikiwa)"
                    r".{0,80}(picha|video|screenshot|recording|rekodi|compromising|"
                    r"akili\s?ya\s?aibu|nyenzo\s?za\s?aibu|evidence|ushahidi\s?wa\s?aibu)"
                    r".{0,100}(tuma|lipa|pay|send|tutashare|tutatuma|tutawaambia|tutapost|"
                    r"familia|mwajiri|employer|marafiki|friends|public|publika|"
                    r"mtandaoni|online|facebook|twitter|whatsapp)"
                    r"|(tutashare|tutatuma|tutawaambia|tutapost|we\s?will\s?(send|share|post|expose|tell|release))"
                    r".{0,80}(picha|video|recording|rekodi|compromising|maisha\s?yako|your\s?life)"
                    r".{0,80}(tuma|lipa|pay|send|pesa|ksh|tzs)",
                    re.IGNORECASE,
                ),
                "explanation": "This is a sextortion/blackmail scam. The threat to share photos or videos is almost always a bluff — do NOT pay. Report to the police.",
            },
            {
                "name": "Blackmail - Location/Personal Threat with Payment Demand",
                "category": "blackmail_extortion",
                "weight": 9,
                "pattern": re.compile(
                    r"(tunajua\s?uko|we\s?know\s?where\s?you|tunakujua|tunakujua\s?unakaa|"
                    r"tunakufuatilia|we\s?are\s?watching\s?you|tumekufuatilia|"
                    r"tunajua\s?nyumba\s?yako|we\s?know\s?your\s?(address|home|location)|"
                    r"tunakufuatilia\s?kila\s?siku)"
                    r".{0,100}(tuma|lipa|pay|send|pesa|ksh|tzs|au\s?sivyo|or\s?else|"
                    r"kama\s?hutalipia|if\s?you\s?don.t\s?pay|utajutia|you\s?will\s?regret)",
                    re.IGNORECASE,
                ),
                "explanation": "Threatening to reveal your location or personal info unless paid is extortion. Do NOT pay — contact the police immediately.",
            },
            {
                "name": "Blackmail - Expose / Shame Threat",
                "category": "blackmail_extortion",
                "weight": 9,
                "pattern": re.compile(
                    r"(tutakuaibisha|we\s?will\s?(ruin|destroy|expose|embarrass)\s?you|"
                    r"tutaharibu\s?jina\s?lako|tutafichua\s?siri\s?zako|"
                    r"everyone\s?will\s?know|kila\s?mtu\s?atajua|tutawaambia\s?wote)"
                    r".{0,100}(tuma|lipa|pay|send|pesa|ksh|tzs|"
                    r"au\s?sivyo|or\s?else|ndani\s?ya|within\s?\d+\s?(hours?|masaa?))",
                    re.IGNORECASE,
                ),
                "explanation": "Threats to publicly shame or expose you unless you pay are blackmail. Do NOT pay — report immediately.",
            },

            # ============================================================
            # HIGH (weight 7-8)
            # One hit here is sufficient to classify as FRAUD.
            # ============================================================

            # ── FAKE LOAN ────────────────────────────────────────────────

            {
                "name": "Upfront Fee for Loan / Fuliza / M-Shwari",
                "category": "fake_loan",
                "weight": 8,
                "pattern": re.compile(
                    r"(fuliza|m-?shwari|m-?pawa|kcb\s?m-?pesa|mkopo|loan|credit|"
                    r"tala|branch\s?loan|zenka|timiza|okoa\s?jahazi|pesa\s?pap)"
                    r".{0,150}(processing\s?fee|activation\s?fee|insurance\s?fee|"
                    r"deposit\s?insurance|\bada\s?ya\b|\bbima\b|registration\s?fee|"
                    r"service\s?charge|kulipa\s?kwanza|clear(ed)?\s?a.{0,15}(charge|fee)|"
                    r"tuma\s?(ksh|kshs|tzs)?\s?\d|ulipia\s?kwanza|advance\s?fee)"
                    r"|(unahitaji\s?kulipa|lazima(\s?\w+){0,2}\s?(u)?lipe|must\s?(pay|clear)|"
                    r"you\s?must\s?clear|itabidi\s?ulipe)"
                    r".{0,200}(fuliza|m-?shwari|m-?pawa|loan|mkopo|fee|charge|insurance|bima)"
                    r"|(fuliza|m-?shwari|m-?pawa|loan|mkopo)"
                    r".{0,200}(unahitaji\s?kulipa|lazima(\s?\w+){0,2}\s?(u)?lipe|must\s?(pay|clear)|"
                    r"you\s?must\s?clear|itabidi\s?ulipe)",
                    re.IGNORECASE,
                ),
                "explanation": "Legitimate loan products deduct fees automatically — they never require an upfront fee to release funds.",
            },
            {
                "name": "Fake Loan - Guaranteed Approval Upfront Fee",
                "category": "fake_loan",
                "weight": 8,
                "pattern": re.compile(
                    r"(mkopo\s?wa|loan\s?of|credit\s?of)\s?(ksh|kshs|tzs)?\s?\d.{0,80}"
                    r"(imeidhinishwa|approved|umepata|granted|umekubaliwa)"
                    r".{0,120}(lipa|tuma|pay|send|weka|deposit).{0,60}"
                    r"(ksh|kshs|tzs|\d{3,6}|ada|fee|charge|insurance|bima|"
                    r"processing|activation|security)",
                    re.IGNORECASE,
                ),
                "explanation": "Scammers claim your loan is approved but require you to pay a fee first — real loan products never work this way.",
            },
            {
                "name": "Fake Loan - Quick Cash / Haraka Pesa Upfront",
                "category": "fake_loan",
                "weight": 7,
                "pattern": re.compile(
                    r"(pesa\s?haraka|quick\s?cash|instant\s?(loan|pesa|money)|"
                    r"mkopo\s?wa\s?haraka|haraka\s?pesa|tunakupa\s?pesa)"
                    r".{0,120}(tuma|lipa|pay|send|weka|deposit).{0,60}"
                    r"(ksh|kshs|tzs|\d{3,4}|ada|fee|charge|registration|security|kwanza)",
                    re.IGNORECASE,
                ),
                "explanation": "Offers of instant cash loans that require an upfront payment are scams — legitimate digital lenders disburse directly to your M-PESA.",
            },

            # ── FAKE REVERSAL ─────────────────────────────────────────────

            {
                "name": "Fake Reversal / Sent-By-Mistake Request",
                "category": "fake_reversal",
                "weight": 7,
                "pattern": re.compile(
                    r"(nimetuma|nilituma|sent|niliituma|tuma|ulipokea|umepokea|received|"
                    r"nimekutumia|nimepeleka\s?pesa)"
                    r".{0,80}(kwa\s?makosa|by\s?mistake|kimakosa|wrong\s?number|"
                    r"namba\s?isiyo\s?sahihi|badala\s?ya|accidentally|kwa\s?bahati\s?mbaya)"
                    r".{0,100}(rudisha|rejesha|return|send\s?back|nirudishie|namba\s?hii|"
                    r"tuma\s?kwa\s?namba|tuma|return\s?the\s?money|pesa\s?zangu)"
                    r"|reversal\s?request.{0,80}(piga|call|tuma)"
                    r"|(kimakosa|by\s?mistake|badala\s?ya|accidentally).{0,100}"
                    r"(rudisha|rejesha|nirudishie|send\s?back|return)",
                    re.IGNORECASE,
                ),
                "explanation": "A genuine wrong transaction is reversed by Safaricom support — never by you sending money to a stranger.",
            },
            {
                "name": "Fake Reversal - M-PESA Reversal Impersonation",
                "category": "fake_reversal",
                "weight": 8,
                "pattern": re.compile(
                    r"(m-?pesa\s?reversal|reverse\s?the\s?(transaction|payment)|"
                    r"reversal\s?(code|number|process|ya\s?mpesa)|mchakato\s?wa\s?kurudisha|"
                    r"transaction\s?reversal|kurudisha\s?pesa\s?yako)"
                    r".{0,100}(tuma|call|piga|contact|namba|number|pin|otp|code|lipa|pay|"
                    r"thibitisha|confirm|processing\s?fee|ada)",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA reversals are initiated by Safaricom on your behalf — no one contacts you to 'process' a reversal by sending money or codes.",
            },
            {
                "name": "Fake Reversal - Pesa Zilienda Mbaya",
                "category": "fake_reversal",
                "weight": 7,
                "pattern": re.compile(
                    r"(pesa\s?zilienda|pesa\s?ilipotea|pesa\s?imeenda|money\s?went|"
                    r"nilituma\s?pesa\s?ya|sent\s?your\s?money\s?by|funds?\s?sent\s?by\s?mistake)"
                    r".{0,80}(namba\s?yako|to\s?your\s?number|kwako\s?kwa|to\s?you\s?by)"
                    r".{0,80}(rudisha|rejesha|send\s?back|return|nirudishie|tuma\s?kwa|"
                    r"tuma\s?(ksh|tzs|kshs)?\s?\d)",
                    re.IGNORECASE,
                ),
                "explanation": "Claiming money was accidentally sent to your number and asking you to return it is the 'wrong-number' scam — the original transfer never happened.",
            },
            {
                "name": "Fake Reversal - Safaricom Reversal Agent Impersonation",
                "category": "fake_reversal",
                "weight": 8,
                "pattern": re.compile(
                    r"(safaricom\s?(reversal\s?)?agent|m-?pesa\s?(reversal\s?)?support|"
                    r"our\s?reversal\s?team|timu\s?ya\s?kurudisha\s?pesa|"
                    r"reversal\s?department|idara\s?ya\s?kurudisha)"
                    r".{0,100}(tuma|send|lipa|pay|confirm|thibitisha|pin|otp|code|"
                    r"namba|number|ksh|tzs|kshs|\d{3,6})",
                    re.IGNORECASE,
                ),
                "explanation": "There is no 'Safaricom reversal agent' who contacts you by SMS — this is impersonation designed to steal your money or credentials.",
            },

            # ── JOB / RECRUITMENT ─────────────────────────────────────────

            {
                "name": "Job / Recruitment Upfront Fee Scam",
                "category": "job_recruitment_scam",
                "weight": 8,
                "pattern": re.compile(
                    r"(job|kazi|vacancy|hiring|shortlisted|recruitment|hr|data\s?entry|"
                    r"dubai|qatar|saudi|kuwait|abu\s?dhabi|abroad|ng.?o\s?job|"
                    r"un\s?job|nafasi\s?ya\s?kazi|nafasi\s?imetangazwa|tumekuchagua)"
                    r".{0,100}(processing\s?fee|registration\s?fee|training\s?fee|visa\s?fee|"
                    r"\bada\s?ya\b|tuma\s?(ksh|kshs|tzs)|paybill|usafiri|"
                    r"medical\s?fee|uniform\s?fee|clearance\s?fee|security\s?deposit|"
                    r"orientation\s?fee|induction\s?fee|application\s?fee)",
                    re.IGNORECASE,
                ),
                "explanation": "A real employer never asks a candidate to pay any fee before being hired.",
            },
            {
                "name": "Job Scam - Work From Home Upfront Payment",
                "category": "job_recruitment_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(work\s?from\s?home|fanya\s?kazi\s?nyumbani|online\s?job|"
                    r"kazi\s?ya\s?mtandaoni|earn\s?from\s?home|pata\s?pesa\s?nyumbani|"
                    r"part.?time\s?job|kazi\s?ya\s?ziada|remote\s?job|typing\s?job)"
                    r".{0,100}(registration|usajili|deposit|weka|tuma|send|lipa|pay|"
                    r"ada\s?ya|fee|charge|ksh|kshs|tzs|\d{3,5})",
                    re.IGNORECASE,
                ),
                "explanation": "Legitimate work-from-home opportunities do not charge registration or startup fees.",
            },

            # ── FAKE SCHOLARSHIP ──────────────────────────────────────────

            {
                "name": "Fake Scholarship / Grant Fee",
                "category": "fake_scholarship",
                "weight": 8,
                "pattern": re.compile(
                    r"(scholarship|ufadhili|grant|ngo|bursary|masomo|bursari|"
                    r"fully\s?funded|umepata\s?ufadhili|umeshinda\s?bursari|"
                    r"higher\s?education\s?grant|education\s?fund)"
                    r".{0,80}(registration\s?fee|\bada\s?ya\b|processing\s?fee|"
                    r"tuma\s?(ksh|kshs|tzs)|application\s?fee|commitment\s?fee|"
                    r"confirm\s?fee|deposit|clearance\s?fee)",
                    re.IGNORECASE,
                ),
                "explanation": "Genuine scholarships and grants do not require upfront fees sent via M-PESA.",
            },

            # ── FAKE PRIZE WINNER ─────────────────────────────────────────

            {
                "name": "Fake Prize / Promo Winner",
                "category": "fake_prize_winner",
                "weight": 7,
                "pattern": re.compile(
                    r"(umeshinda|hongera|won|winner|prize|jackpot|zawadi|bonasi|bonus|"
                    r"congratulations|selected|umechaguliwa|uliyoshinda|bahati\s?nasibu|"
                    r"lucky\s?draw|raffle|promo\s?winner|top\s?winner|grand\s?prize|"
                    r"kura\s?yako\s?imechaguliwa|nambari\s?yako\s?imechaguliwa)"
                    r".{0,150}(ksh|kshs|tzs|shillings|elfu|million|\d{2,3},?\d{3})"
                    r".{0,100}?(tuma|send|fee|ada|claim|kupokea|processing|kulipia|"
                    r"activate|unlock|release|tax|ushuru|custom\s?duty)?"
                    r"|(tuma|send).{0,40}(ksh|kshs|tzs)?.{0,30}(kulipia|\bada\s?ya\b).{0,40}"
                    r"(zawadi|bahati\s?nasibu|umeshinda|uliyoshinda|promo|prize|jackpot)",
                    re.IGNORECASE,
                ),
                "explanation": "You cannot win a prize by first paying a fee — this is one of the most common mobile-money scam patterns.",
            },
            {
                "name": "Fake Prize - Tax/Clearance Fee to Collect",
                "category": "fake_prize_winner",
                "weight": 7,
                "pattern": re.compile(
                    r"(prize|zawadi|winnings|jackpot|award|payout).{0,80}"
                    r"(tax|ushuru|clearance\s?fee|release\s?fee|custom\s?duty|duty\s?fee|"
                    r"ada\s?ya\s?ushuru|itabidi\s?ulipe|must\s?pay|unahitaji\s?kulipa)"
                    r".{0,80}(ksh|kshs|tzs|\d{3,6}|tuma|lipa|send|pay|namba\s?hii)",
                    re.IGNORECASE,
                ),
                "explanation": "A real lottery or prize never requires you to pay tax or clearance fees upfront via M-PESA — prize tax is deducted at source by registered operators.",
            },

            # ── SEND TO NUMBER ─────────────────────────────────────────────

            {
                "name": "Send Money to Bare Number (No Official Receipt)",
                "category": "send_to_number_request",
                "weight": 7,
                "pattern": re.compile(
                    r"(tuma|send)\s?(kwa)?\s?(kwenye)?\s?(hii)?\s?namba"
                    r".{0,80}(ksh|kshs|tzs|\d{3,6})"
                    r".{0,100}(kulipia|\bada\s?ya\b|fee|deposit|usajili|processing|registration|"
                    r"insurance|activation|kuhamisha|transfer|kuweka|confirm)",
                    re.IGNORECASE,
                ),
                "explanation": "Real M-PESA processes never require you to push money to a stranger's number to 'unlock' or 'process' something.",
            },
            {
                "name": "Universal Paybill/Till Scam Request",
                "category": "send_to_number_request",
                "weight": 7,
                "pattern": re.compile(
                    r"(paybill|till\s?number|lipa\s?na\s?m-?pesa|buy\s?goods)"
                    r".{0,60}(\d{5,7})"
                    r".{0,80}(ada|fee|deposit|registration|processing|activation|"
                    r"insurance|kulipia|claim|collect|receive|kupokea)",
                    re.IGNORECASE,
                ),
                "explanation": "Scammers frequently use paybill or till numbers to collect fees under false pretences — any unsolicited message with a paybill number asking you to pay a fee is a red flag.",
            },

            # ── ACCOUNT SUSPENSION ────────────────────────────────────────

            {
                "name": "Account Suspension / Lock Threat",
                "category": "account_suspension_threat",
                "weight": 7,
                "pattern": re.compile(
                    r"(account|akaunti|line|simu|sim|mpesa|m-?pesa|wallet|namba\s?yako)"
                    r".{0,60}(suspend|suspended|blocked|itafungwa|fungwa|locked|closed|"
                    r"terminate|deactivate|simamishwa|zimwa|itazimwa|itafutwa|"
                    r"kufungwa\s?kesho|will\s?be\s?deactivated|will\s?be\s?suspended)",
                    re.IGNORECASE,
                ),
                "explanation": "Creates panic about losing access to your account to stop you thinking — a classic pressure tactic.",
            },

            # ── FAKE KYC ──────────────────────────────────────────────────

            {
                "name": "Fake KYC / Account Update Request",
                "category": "fake_kyc_update",
                "weight": 8,
                "pattern": re.compile(
                    r"(kyc|know\s?your\s?customer|thibitisha\s?taarifa|verify\s?your\s?details|"
                    r"update\s?your\s?(account|profile|details|taarifa|akaunti)|"
                    r"sasisho\s?la\s?(akaunti|taarifa)|taarifa\s?zako\s?zimepitwa|"
                    r"update\s?your\s?mpesa|sasisha\s?akaunti\s?yako|"
                    r"account\s?verification\s?required|thibitisha\s?akaunti\s?yako)"
                    r".{0,100}(link|bonyeza|click|tuma|send|piga\s?simu|call|"
                    r"namba\s?yetu|thibitisha|confirm|deadline|muda\s?umekwisha|"
                    r"or\s?your\s?account|vinginevyo\s?akaunti|ussd|jibu\s?ujumbe|"
                    r"reply\s?with|send\s?your|tuma\s?namba|tuma\s?id)",
                    re.IGNORECASE,
                ),
                "explanation": "Safaricom and legitimate banks update KYC through official channels — never unsolicited SMS asking you to click a link or call a number.",
            },
            {
                "name": "Fake KYC - SIM Registration Impersonation",
                "category": "fake_kyc_update",
                "weight": 8,
                "pattern": re.compile(
                    r"(sim\s?(card)?\s?registration|usajili\s?wa\s?sim|sim\s?bado\s?haijasajiliwa|"
                    r"register\s?your\s?sim|sim\s?yako\s?itafutwa|sim\s?itazimwa|"
                    r"sim\s?yako\s?haijakamilika|sim\s?registration\s?incomplete|"
                    r"line\s?yako\s?itafutwa|namba\s?yako\s?itafutwa)"
                    r".{0,100}(tuma|send|piga|call|bonyeza|click|namba|number|link|"
                    r"kitambulisho|id\s?number|nambari\s?ya|thibitisha|confirm|"
                    r"jibu|reply|born|tarehe\s?ya\s?kuzaliwa|date\s?of\s?birth)",
                    re.IGNORECASE,
                ),
                "explanation": "SIM registration is done in-person or via official USSD — not by submitting ID details in response to an SMS.",
            },
            {
                "name": "Fake KYC - Personal Details Request via SMS",
                "category": "fake_kyc_update",
                "weight": 7,
                "pattern": re.compile(
                    r"(tuma|send|jibu|reply|provide|toa|nipe)"
                    r".{0,60}(id\s?number|nambari\s?ya\s?kitambulisho|passport\s?number|"
                    r"date\s?of\s?birth|tarehe\s?ya\s?kuzaliwa|mother.s\s?name|"
                    r"jina\s?la\s?mama|full\s?name\s?and|jina\s?lako\s?kamili)"
                    r".{0,80}(to\s?verify|kuthibitisha|account|akaunti|sim|mpesa|"
                    r"kuthibitisha\s?akaunti|to\s?avoid|kuepuka|kufungwa|suspension)",
                    re.IGNORECASE,
                ),
                "explanation": "No legitimate mobile service asks you to SMS your ID number, passport, or birth date — this is identity theft.",
            },

            # ── FAKE TENDER / BUSINESS DEAL ───────────────────────────────

            {
                "name": "Fake Tender / LPO / Business Deal Upfront Fee",
                "category": "fake_tender_business_deal",
                "weight": 8,
                "pattern": re.compile(
                    r"(tender|zabuni|lpo|local\s?purchase\s?order|contract|mkataba|"
                    r"government\s?(supply|order|contract)|serikali\s?inataka|supplier|"
                    r"supply\s?tender|tender\s?award|tender\s?notice|zabuni\s?imeshinda)"
                    r".{0,120}(approved|umeshinda|imeidhinishwa|selected|umechaguliwa|"
                    r"awarded|imekupata|you\s?have\s?been\s?selected)"
                    r".{0,150}(fee|ada|tuma|lipa|deposit|advance|security\s?(deposit|bond)|"
                    r"performance\s?bond|compliance\s?fee|processing\s?fee|"
                    r"clearance\s?fee|tax\s?clearance|cr12|registration\s?fee)"
                    r"|(fee|ada|tuma|lipa|deposit|advance|security\s?(deposit|bond)|"
                    r"performance\s?bond|compliance\s?fee|processing\s?fee)"
                    r".{0,150}(tender|zabuni|lpo|local\s?purchase\s?order|contract|mkataba|"
                    r"government\s?(supply|order)|serikali\s?inataka|supplier)",
                    re.IGNORECASE,
                ),
                "explanation": "Real government tenders and LPOs never require a supplier to pay a fee before the contract is released — this is advance-fee fraud.",
            },
            {
                "name": "Fake Tender - Business Opportunity Advance Fee",
                "category": "fake_tender_business_deal",
                "weight": 7,
                "pattern": re.compile(
                    r"(business\s?opportunity|fursa\s?ya\s?biashara|ubia|partnership|"
                    r"joint\s?venture|biashara\s?ya\s?pamoja|deal\s?ya\s?biashara|"
                    r"lucrative\s?(deal|opportunity)|faida\s?kubwa)"
                    r".{0,120}(requires?\s?an?\s?(initial|upfront|advance)|unahitaji\s?kuweka|"
                    r"deposit\s?first|kwanza\s?weka|advance\s?payment|malipo\s?ya\s?awali|"
                    r"commitment\s?fee|registration\s?fee|entry\s?fee|membership\s?fee)"
                    r".{0,100}(ksh|kshs|tzs|\d{3,6}|namba|number|paybill|mpesa|tuma|lipa)",
                    re.IGNORECASE,
                ),
                "explanation": "Advance-fee business scams promise large contracts but demand upfront payment first — no legitimate deal works this way.",
            },
            {
                "name": "Fake Tender - Government Impersonation Supply Order",
                "category": "fake_tender_business_deal",
                "weight": 8,
                "pattern": re.compile(
                    r"(ministry|wizara|county\s?government|serikali\s?ya\s?kaunti|"
                    r"kenya\s?power|kplc|kenya\s?pipeline|kebs|kirdi|kenha|"
                    r"national\s?hospital|national\s?government\s?agency)"
                    r".{0,120}(supply|kutoa\s?bidhaa|deliver|delivering|supplier\s?needed)"
                    r".{0,120}(fee|ada|deposit|bond|tuma|lipa|pay|ksh|kshs|\d{3,6})",
                    re.IGNORECASE,
                ),
                "explanation": "Government ministries and agencies do not recruit suppliers via unsolicited SMS with upfront payment demands.",
            },

            # ── FAKE AGENT OVERPAYMENT ────────────────────────────────────

            {
                "name": "Fake Agent Overpayment / Refund Difference Scam",
                "category": "fake_agent_overpayment",
                "weight": 8,
                "pattern": re.compile(
                    r"(nimekupigia|nimetuma|nimeweka|i\s?sent|i\s?paid|nimepeleka|"
                    r"nimekutumia|nilitumia|naomba\s?urudishe)"
                    r".{0,80}(pesa\s?nyingi|zaidi|extra|too\s?much|more\s?than|"
                    r"kuliko\s?ilivyostahili|kwa\s?makosa|by\s?mistake|accidentally|"
                    r"nimekosea|nilikosea|nimekupigia\s?zaidi)"
                    r".{0,100}(rudisha\s?(tofauti|balance|remainder|kilichobaki)|"
                    r"nirudishie\s?(ksh|kshs|tzs)?\s?\d|send\s?back\s?the\s?(difference|rest|balance|change)|"
                    r"tuma\s?(ksh|kshs|tzs)?\s?\d.{0,20}(tofauti|difference|back|change)|"
                    r"rudisha\s?ksh|return\s?ksh|nirudishie\s?pesa|send\s?me\s?back)",
                    re.IGNORECASE,
                ),
                "explanation": "The overpayment scam: someone claims to have paid you too much and asks for the difference — the original payment is forged.",
            },
            {
                "name": "Fake Agent Overpayment - Direct Refund Demand",
                "category": "fake_agent_overpayment",
                "weight": 7,
                "pattern": re.compile(
                    r"(nilikusudia\s?kutuma|i\s?meant\s?to\s?send|nilikusudia\s?kulipa|"
                    r"nilitaka\s?kutuma|i\s?wanted\s?to\s?send|nilitaka\s?kulipa)"
                    r".{0,100}(lakini\s?nilikutumia|but\s?i\s?sent\s?you|badala\s?ya|"
                    r"instead\s?i\s?sent|nilikosea|nilikupigia\s?zaidi)"
                    r".{0,100}(rudisha|nirudishie|send\s?back|return)"
                    r"|(agent|wakala|duka\s?la\s?mpesa|mpesa\s?agent)"
                    r".{0,80}(nikulipa|nikusaidie|refund|nirudishie|rejesha).{0,60}"
                    r"(tofauti|difference|balance|remainder|kilichobaki|change)",
                    re.IGNORECASE,
                ),
                "explanation": "A claimed agent 'accidentally' overpaid you and wants the difference back — always check your M-PESA statement before refunding anyone.",
            },
            {
                "name": "Fake Agent Overpayment - Excess Cash Request",
                "category": "fake_agent_overpayment",
                "weight": 7,
                "pattern": re.compile(
                    r"(nimekupa|nimekutumia|i\s?gave\s?you|i\s?sent\s?you)\s?"
                    r"(ksh|kshs|tzs)?\s?\d.{0,60}"
                    r"(lakini\s?nilitaka|but\s?i\s?only\s?wanted|badala\s?ya|instead\s?of)\s?"
                    r"(ksh|kshs|tzs)?\s?\d.{0,80}"
                    r"(tofauti|difference|change|kilichobaki|remainder|the\s?rest)"
                    r".{0,60}(tuma|rudisha|nirudishie|send|return|rejesha)",
                    re.IGNORECASE,
                ),
                "explanation": "Scammer claims exact figures to make the overpayment seem real — verify via your own M-PESA statement before sending anything.",
            },

            # ── FAMILY EMERGENCY ──────────────────────────────────────────

            {
                "name": "Family Emergency Impersonation",
                "category": "impersonation_family_emergency",
                "weight": 8,
                "pattern": re.compile(
                    r"(mama|baba|dada|kaka|ndugu|shangazi|mjomba|bibi|babu|uncle|aunt|"
                    r"sister|brother|cousin\s?wangu|familia\s?yako|mtoto\s?wako|mwana\s?wako|"
                    r"your\s?(mother|father|sister|brother|parent|child|son|daughter)|"
                    r"rafiki\s?yako\s?amepata|mtu\s?wako\s?wa\s?karibu)"
                    r".{0,100}(accident|ajali|hospitali|hospital|emergency|dharura|"
                    r"amepata\s?ajali|ameumia|amegonga|amefariki|amekufa|anaomba|"
                    r"amepigwa|ameibiwa|amefungwa|amezuiliwa|ako\s?hatarini|"
                    r"intensive\s?care|icu|coma|amepoteza\s?fahamu)"
                    r".{0,100}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|"
                    r"haraka|immediately|sasa\s?hivi|urgently|haraka\s?sana|deposit)",
                    re.IGNORECASE,
                ),
                "explanation": "Family emergency scam — always call the family member directly on their known number before sending money.",
            },
            {
                "name": "Family Emergency - Calling From Stranger's Phone",
                "category": "impersonation_family_emergency",
                "weight": 8,
                "pattern": re.compile(
                    r"(ninapigia\s?kwa\s?simu\s?ya|calling\s?from\s?(a\s?)?(stranger|someone\s?else|"
                    r"friend|marafiki|jirani|neighbour|mtu\s?mwingine|mgeni)|"
                    r"simu\s?yangu\s?(imeharibika|imeibiwa|haifanyi\s?kazi|imechomwa|"
                    r"imepotea|imevunjika|imezimika|haina\s?betri|haina\s?malipo|"
                    r"inacharjiwa|niko\s?bila\s?simu)|"
                    r"my\s?phone\s?(is\s?)?(lost|stolen|broken|dead|switched\s?off|"
                    r"charging|off|no\s?credit|no\s?airtime))"
                    r".{0,120}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|nisaidie|help\s?me|"
                    r"nahitaji\s?msaada|ninahitaji\s?pesa)",
                    re.IGNORECASE,
                ),
                "explanation": "Claiming to use a stranger's phone explains why the number is unfamiliar — always verify by calling back a number you know.",
            },
            {
                "name": "Family Emergency - Hospital/Accident + Immediate Money",
                "category": "impersonation_family_emergency",
                "weight": 7,
                "pattern": re.compile(
                    r"(niko\s?hospitali|nipo\s?hospitali|i\s?am\s?in\s?hospital|"
                    r"tumempeleka\s?hospitali|amefika\s?hospitali|nipo\s?emergency|"
                    r"niko\s?operation|ameingia\s?theatre|operation\s?fee|upasuaji|"
                    r"nimepata\s?ajali|nimeumia|nimegonga|nimevunjika|niko\s?injured|"
                    r"niko\s?ward|niko\s?icu|admission\s?fee|deposit\s?ya\s?hospitali)"
                    r".{0,120}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|"
                    r"haraka|immediately|sasa\s?hivi|deposit|hospital\s?bill|"
                    r"bili\s?ya\s?hospitali|treatment\s?fee|dawa\s?ya|dawa\s?zinahitajika)",
                    re.IGNORECASE,
                ),
                "explanation": "Hospital emergency texts demanding urgent money are extremely common in Kenya and Tanzania — call the hospital directly before sending.",
            },
            {
                "name": "Family Emergency - Borrow / Nikopiwe Pesa",
                "category": "impersonation_family_emergency",
                "weight": 7,
                "pattern": re.compile(
                    r"(nikopiwe|nakopa|borrow\s?me|lend\s?me|nikopeshe|"
                    r"can\s?you\s?(lend|send)\s?me|ninaweza\s?kukopa|"
                    r"nisaidie\s?kidogo|help\s?me\s?with\s?a\s?little|"
                    r"nitatumia\s?kesho|nitarudisha\s?baadaye|i\s?will\s?pay\s?back)"
                    r".{0,80}(ksh|kshs|tzs|\d{3,6}|pesa|peas|hela|cash|mia|elfu)"
                    r".{0,80}(haraka|sasa\s?hivi|urgently|leo\s?leo|right\s?now|"
                    r"nahitaji\s?sana|very\s?urgent|dharura|emergency|jambo\s?la\s?dharura)",
                    re.IGNORECASE,
                ),
                "explanation": "Urgent borrowing requests from unknown numbers — especially with time pressure — are a very common scam format in Kenya and Tanzania.",
            },

            # ── FAKE CHARITY ──────────────────────────────────────────────

            {
                "name": "Fake Charity / Donation Scam",
                "category": "fake_charity_donation",
                "weight": 8,
                "pattern": re.compile(
                    r"(orphanage|watoto\s?yatima|yatima|children.s\s?home|nyumba\s?ya\s?watoto|"
                    r"hospital\s?fund|harambee|msaada\s?wa|sadaka|changa|donation|donate|"
                    r"flood\s?(victim|relief)|mafuriko|earthquake|tetemeko|ukame|drought\s?relief|"
                    r"cancer\s?(fund|patient)|familia\s?masikini|maskini\s?wahitaji|"
                    r"wagonjwa\s?maskini|watoto\s?wa\s?mitaani|street\s?children|"
                    r"mchango\s?wa|tunaomba\s?msaada|relief\s?fund|humanitarian)"
                    r".{0,120}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|paybill|namba\s?hii|"
                    r"this\s?number|account\s?number|m-?pesa\s?namba|till\s?number|"
                    r"donate\s?to|changiza\s?kwa|weka\s?kwa)",
                    re.IGNORECASE,
                ),
                "explanation": "Fake charity scams exploit compassion — verify any fundraiser independently before donating.",
            },
            {
                "name": "Fake Charity - Urgent Appeal with Unknown Contact",
                "category": "fake_charity_donation",
                "weight": 7,
                "pattern": re.compile(
                    r"(msaada\s?wa\s?haraka|urgent\s?(donation|appeal|request|help)|"
                    r"please\s?help\s?us|tafadhali\s?saidia|tunahitaji\s?msaada\s?wa\s?haraka|"
                    r"help\s?us\s?save|saidia\s?kuokoa|tunaomba\s?kwa\s?unyenyekevu|"
                    r"hali\s?ni\s?mbaya\s?sana|situation\s?is\s?critical|hali\s?ya\s?dharura)"
                    r".{0,100}(tuma|send|m-?pesa|paybill|donate\s?to|wasiliana\s?na|contact|"
                    r"changiza|weka\s?pesa|contribute)"
                    r".{0,80}(ksh|kshs|tzs|\d{4,}|namba\s?hii|this\s?number|below|"
                    r"hapo\s?chini|account\s?number)",
                    re.IGNORECASE,
                ),
                "explanation": "Urgency + a payment number in an unsolicited SMS is a hallmark of charity fraud.",
            },
            {
                "name": "Fake Charity - Church/Pastor Money Request",
                "category": "fake_charity_donation",
                "weight": 7,
                "pattern": re.compile(
                    r"(pastor|mchungaji|bishop|father|padre|sheikh|imam|kanisa|church|"
                    r"msikiti|mosque|vifaa\s?vya\s?kanisa|jengo\s?la\s?kanisa|"
                    r"church\s?construction|ujenzi\s?wa\s?kanisa|church\s?project)"
                    r".{0,100}(tuma|send|changiza|donate|lipa|pay|pesa|ksh|kshs|tzs|"
                    r"paybill|namba\s?hii|this\s?number|mpesa\s?namba)"
                    r".{0,80}(\d{5,}|ksh\s?\d|tzs\s?\d|elfu|thousand|million)",
                    re.IGNORECASE,
                ),
                "explanation": "Religious authority impersonation is used to lower your guard — verify any church donation request directly with your known church contact.",
            },

            # ── FAKE DEBT COLLECTION ──────────────────────────────────────

            {
                "name": "Fake Debt Collection - Aggressive Threat",
                "category": "fake_debt_collection",
                "weight": 8,
                "pattern": re.compile(
                    r"(deni|debt|mkopo|loan|credit|arrears|malimbikizo|"
                    r"outstanding\s?balance|overdue\s?payment|malipo\s?yaliyochelewa)"
                    r".{0,100}(crb|credit\s?reference|blacklist|orodha\s?nyeusi|"
                    r"bailiff|msimamizi\s?wa\s?mali|kukamata\s?mali|seize\s?property|"
                    r"court\s?order|amri\s?ya\s?mahakama|sheriff|utekelezaji|"
                    r"tunakuja\s?nyumbani|we\s?will\s?come\s?to\s?your|"
                    r"mali\s?yako\s?itachukuliwa|your\s?property\s?will\s?be\s?seized|"
                    r"tutashitaki|we\s?will\s?sue\s?you)"
                    r".{0,100}(lipa\s?sasa|pay\s?now|haraka|immediately|leo\s?hii|"
                    r"ksh|kshs|tzs|or\s?else|au\s?sivyo|within\s?\d+\s?(hours?|masaa?))",
                    re.IGNORECASE,
                ),
                "explanation": "Real CRB or loan recovery follows legal steps through your bank — immediate SMS threats to blacklist or seize property are scare tactics.",
            },
            {
                "name": "Fake Debt Collection - Third Party Collector",
                "category": "fake_debt_collection",
                "weight": 7,
                "pattern": re.compile(
                    r"(tunakukumbusha|we\s?are\s?reminding\s?you|tunakuarifu|"
                    r"this\s?is\s?to\s?inform\s?you|unaombwa\s?kulipa|you\s?are\s?requested\s?to\s?pay|"
                    r"tunakujulisha\s?kuhusu)"
                    r".{0,100}(deni|debt|mkopo|balance\s?outstanding|malimbikizo|"
                    r"overdue\s?payment|arrears|malipo\s?yaliyochelewa)"
                    r".{0,100}(tuma|pay|lipa|send|m-?pesa|paybill|namba\s?hii|this\s?number|"
                    r"contact\s?(us|our|agent)|wasiliana\s?na)"
                    r"|(recovery\s?agent|debt\s?collector|mkusanyaji\s?wa\s?deni|"
                    r"loan\s?recovery\s?team|timu\s?ya\s?kukusanya\s?deni)"
                    r".{0,100}(tuma|pay|lipa|send|ksh|kshs|tzs|namba|number|mpesa)",
                    re.IGNORECASE,
                ),
                "explanation": "Unsolicited debt collection via SMS from a personal number is almost always fraudulent.",
            },
            {
                "name": "Fake Debt Collection - Final Notice Threat",
                "category": "fake_debt_collection",
                "weight": 7,
                "pattern": re.compile(
                    r"(final\s?notice|last\s?warning|onyo\s?la\s?mwisho|hii\s?ni\s?onyo\s?la\s?mwisho|"
                    r"hatua\s?za\s?kisheria|legal\s?action\s?will\s?be\s?taken|"
                    r"tutachukua\s?hatua|we\s?will\s?take\s?action)"
                    r".{0,100}(deni|debt|mkopo|loan|arrears|outstanding|malimbikizo)"
                    r".{0,100}(tuma|pay|lipa|send|ksh|kshs|tzs|namba|number|mpesa|paybill|"
                    r"au\s?sivyo|or\s?else|within\s?\d+)",
                    re.IGNORECASE,
                ),
                "explanation": "Final notice threats via SMS from personal numbers are not legally enforceable — your real lender contacts you through official channels.",
            },
            {
                "name": "Fake Debt Collection - CRB Listing Threat",
                "category": "fake_debt_collection",
                "weight": 7,
                "pattern": re.compile(
                    r"(tutakuweka\s?crb|we\s?will\s?list\s?you\s?on\s?crb|"
                    r"utawekwa\s?kwenye\s?orodha\s?nyeusi|blacklisted\s?on\s?crb|"
                    r"crb\s?(listing|report|blacklist)|credit\s?bureau\s?(listing|report)|"
                    r"taarifa\s?yako\s?itaenda\s?crb)"
                    r".{0,80}(kama\s?hutalipia|if\s?you\s?don.t\s?pay|unless\s?you\s?pay|"
                    r"lipa\s?kwanza|pay\s?first|tuma\s?sasa|send\s?now|"
                    r"ksh|kshs|tzs|\d{3,6}|namba\s?hii|this\s?number)",
                    re.IGNORECASE,
                ),
                "explanation": "CRB listings follow formal processes through your lender — they cannot be triggered by SMS from a stranger demanding immediate payment.",
            },

            # ── ROMANCE SCAM ──────────────────────────────────────────────

            {
                "name": "Romance / Stranger Financial Help",
                "category": "romance_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(my\s?love|darling|sweetheart|mpenzi\s?wangu|baby|babe|nataka\s?kukujua|"
                    r"nimekupenda|i\s?love\s?you\s?already|nimekuangalia\s?profile\s?yako|"
                    r"nilikuona\s?facebook|nilikuona\s?instagram|nilikupata\s?mtandaoni|"
                    r"i\s?found\s?you\s?online|nakupenda\s?sana|i\s?have\s?strong\s?feelings)"
                    r".{0,100}(send|tuma|help\s?me|nisaidie|money|pesa|"
                    r"gift\s?card|voucher|itunes|google\s?play|amazon|"
                    r"transfer|western\s?union|moneygram|wire)",
                    re.IGNORECASE,
                ),
                "explanation": "Romance scams build trust fast then ask for money — do not send money to online strangers.",
            },
            {
                "name": "Romance Scam - Stranded / Emergency Scenario",
                "category": "romance_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(i\s?am\s?stuck|niko\s?stuck|nimekwama|i\s?am\s?stranded|nimekwama\s?hapa|"
                    r"passport\s?(yako|yangu)?\s?(imefungwa|imezuiwa|held|confiscated)|"
                    r"custom\s?(fee|ada|cleared)|airport\s?(police|customs|fee|detained)|"
                    r"i\s?need\s?your\s?help|nakuhitaji\s?unisaidie|"
                    r"niko\s?kizuizini|i\s?am\s?detained|nimeshikiliwa|"
                    r"i\s?missed\s?my\s?flight|nimekosa\s?ndege|stranded\s?at)"
                    r".{0,120}(tuma|send|lipa|pay|pesa|ksh|kshs|tzs|"
                    r"transfer|wire|western\s?union|moneygram|bitcoin|crypto)",
                    re.IGNORECASE,
                ),
                "explanation": "Romance scammers claim to be stranded, detained at customs, or in a medical emergency abroad — do not send money to anyone you haven't met in person.",
            },
            {
                "name": "Romance Scam - Gift Card / Voucher Request",
                "category": "romance_scam",
                "weight": 8,
                "pattern": re.compile(
                    r"(gift\s?card|voucher|itunes\s?card|google\s?play\s?card|amazon\s?card|"
                    r"steam\s?card|playstation\s?card|ukartuni|kadi\s?ya\s?zawadi|"
                    r"apple\s?card|vanilla\s?card|prepaid\s?card|recharge\s?card)"
                    r".{0,100}(tuma|send|nipe|give\s?me|share|piga\s?picha|take\s?photo|"
                    r"number|nambari|scratch|code\s?ya|serial\s?number|pin\s?number|"
                    r"the\s?code|namba\s?ya|tuma\s?code|share\s?the\s?code)",
                    re.IGNORECASE,
                ),
                "explanation": "Gift card codes are untraceable — no legitimate person or business needs payment in gift cards.",
            },
            {
                "name": "Romance Scam - Investment / Crypto Opportunity",
                "category": "romance_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(my\s?love|darling|baby|babe|mpenzi|sweetheart|nakupenda)"
                    r".{0,150}(invest|investment|crypto|bitcoin|forex|trading|"
                    r"double\s?your\s?money|guaranteed\s?(profit|return)|"
                    r"ninatumia\s?platform|platform\s?yangu|ongeza\s?pesa)",
                    re.IGNORECASE,
                ),
                "explanation": "Romance scammers often pivot to investment schemes after establishing trust — if an online 'friend' or romantic contact suggests an investment, it is a scam.",
            },

            # ── INVESTMENT SCAM ───────────────────────────────────────────

            {
                "name": "Investment / Double-Your-Money Scam",
                "category": "investment_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(invest|investment|double\s?your\s?money|guaranteed\s?(profit|return|faida)|"
                    r"ongeza\s?pesa|zidisha\s?pesa|pesa\s?inakua|returns?\s?of\s?\d+\s?%|"
                    r"faida\s?ya\s?\d+\s?%|earn\s?\d+\s?%|pata\s?\d+\s?%|"
                    r"high\s?returns?|fixed\s?returns?|passive\s?income|kipato\s?cha\s?kawaida)"
                    r".{0,100}(tuma|send|weka|deposit|invest\s?now|anza\s?leo|start\s?today|"
                    r"join\s?now|jiunge\s?sasa|ksh|kshs|tzs|\d{3,6}|platform|app)",
                    re.IGNORECASE,
                ),
                "explanation": "Promises of guaranteed or unusually high returns are hallmarks of investment fraud.",
            },
            {
                "name": "Investment Scam - MLM / Pyramid Recruitment",
                "category": "investment_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(recruit|wasiliana\s?na|refer\s?friends|"
                    r"kuleta\s?watu|bring\s?members|jiunge\s?na\s?timu|join\s?our\s?team|"
                    r"downline|upline|mlm|pyramid|ponzi)"
                    r".{0,100}(ksh|kshs|tzs|\d{3,6}|tuma|invest|weka|deposit|"
                    r"earn|pata|faida|profit|returns?)",
                    re.IGNORECASE,
                ),
                "explanation": "MLM and pyramid schemes require you to recruit others to earn — most participants lose money. Avoid.",
            },
            {
                "name": "Investment Scam - Forex/Crypto Trading Platform",
                "category": "investment_scam",
                "weight": 7,
                "pattern": re.compile(
                    r"(forex|fx\s?trading|crypto|bitcoin|ethereum|usdt|binance|"
                    r"trading\s?platform|binary\s?options|stock\s?trading\s?app)"
                    r".{0,100}(guaranteed|assured|hakika|promised|tutakutengenezea|"
                    r"we\s?guarantee|minimum\s?return|daily\s?profits?|faida\s?kila\s?siku)"
                    r".{0,100}(tuma|send|weka|deposit|invest|ksh|kshs|tzs|\d{4,})",
                    re.IGNORECASE,
                ),
                "explanation": "No forex or crypto trading platform can guarantee returns — these messages are investment fraud.",
            },

            # ── FAKE DELIVERY ─────────────────────────────────────────────

            {
                "name": "Fake Delivery / Parcel Payment",
                "category": "fake_delivery_payment",
                "weight": 7,
                "pattern": re.compile(
                    r"(parcel|delivery|jumia|kilimall|courier|bidhaa|kufikishwa|"
                    r"package|kifurushi|order\s?yako|mzigo|shipment|mazao|goods)"
                    r".{0,80}(pay|lipa|tuma|confirm|fees|ada|kulipia|"
                    r"customs|ushuru|duty|clearance|release\s?fee|delivery\s?fee)"
                    r"|(pay|lipa|tuma|kulipia|fees|ada)"
                    r".{0,60}(parcel|delivery|jumia|kilimall|courier|bidhaa|kufikishwa|package)",
                    re.IGNORECASE,
                ),
                "explanation": "Legitimate delivery services bill through their own checkout — not via a random SMS number.",
            },

            # ── MEDIUM WEIGHT ─────────────────────────────────────────────

            {
                "name": "Debt Collection Threat (Unverified)",
                "category": "fake_debt_collection",
                "weight": 5,
                "pattern": re.compile(
                    r"(deni|debt|loan).{0,60}(lipa\s?sasa|pay\s?now|crb|blacklist|"
                    r"tutakushitaki|legal\s?action|court)",
                    re.IGNORECASE,
                ),
                "explanation": "Real CRB/loan recovery comes through your bank's official channel, not an unsolicited SMS.",
            },
            {
                "name": "Safaricom / Vodacom Impersonation",
                "category": "impersonation",
                "weight": 5,
                "pattern": re.compile(
                    r"(safaricom|vodacom|airtel|telkom|customer\s?care|m-?pesa\s?support|"
                    r"safaricom\s?team|mpesa\s?team|official\s?safaricom)"
                    r".{0,60}(verify|update|confirm|call\s?this|tuma|send|"
                    r"account\s?issue|click\s?here|bonyeza|link\s?hii)",
                    re.IGNORECASE,
                ),
                "explanation": "Official telcos do not initiate unsolicited SMS asking you to verify account details or click links.",
            },
            {
                "name": "Account Suspension / Lock Threat",
                "category": "account_suspension_threat",
                "weight": 5,
                "pattern": re.compile(
                    r"(account|akaunti|line|simu|sim|mpesa|m-?pesa)"
                    r".{0,40}(suspend|suspended|blocked|itafungwa|fungwa|locked|closed|"
                    r"terminate|deactivate|simamishwa|zimwa)",
                    re.IGNORECASE,
                ),
                "explanation": "Account suspension threats are used to create panic so you act without thinking.",
            },
            {
                "name": "SIM Swap Warning",
                "category": "sim_swap",
                "weight": 5,
                "pattern": re.compile(
                    r"(sim\s?swap|line\s?transferred|new\s?sim|sim\s?registered|"
                    r"sim\s?yako\s?imehamishiwa|your\s?sim\s?has\s?been\s?swapped)",
                    re.IGNORECASE,
                ),
                "explanation": "Used to panic victims into revealing personal or PIN details to 'protect' their line.",
            },

            # ── LOW / SUPPORTING ──────────────────────────────────────────

            {
                "name": "Urgency Pressure Language",
                "category": "urgency",
                "weight": 2,
                "pattern": re.compile(
                    r"\b(urgent|immediately|act\s?now|within\s?\d+\s?(minutes|hours|hrs)|"
                    r"haraka|sasa\s?hivi|leo\s?leo|kabla\s?ya|deadline|"
                    r"muda\s?unaisha|time\s?is\s?running\s?out|muda\s?mfupi|"
                    r"last\s?chance|nafasi\s?ya\s?mwisho|jaza\s?sasa)\b",
                    re.IGNORECASE,
                ),
                "explanation": "False urgency stops victims thinking clearly — a classic pressure tactic.",
            },
            {
                "name": "Personal Number Claims to Be M-PESA/Bank",
                "category": "sender_mismatch",
                "weight": 3,
                "pattern": re.compile(
                    r"(this is|hii ni|mimi ni|i am)\s?(m-?pesa|safaricom|vodacom|bank|"
                    r"equity|kcb|cooperative|barclays|stanbic|standard\s?chartered|"
                    r"ncba|dtb|absa|family\s?bank)",
                    re.IGNORECASE,
                ),
                "explanation": "Genuine M-PESA/bank alerts come from the official short sender ID, never from a message claiming 'this is M-PESA' from a personal number.",
            },
            {
                "name": "Confidentiality Instruction (Social Engineering)",
                "category": "social_engineering",
                "weight": 3,
                "pattern": re.compile(
                    r"(usimwambie\s?mtu\s?yeyote|don.t\s?tell\s?anyone|keep\s?this\s?secret|"
                    r"hii\s?ni\s?siri\s?yetu|this\s?is\s?between\s?us|"
                    r"usishirikishe\s?familia|don.t\s?involve\s?family|"
                    r"usiniambie\s?wengine|this\s?is\s?confidential|"
                    r"nenda\s?peke\s?yako|go\s?alone|usiambie\s?mtu)",
                    re.IGNORECASE,
                ),
                "explanation": "Scammers ask you to keep the transaction secret to prevent family or friends from warning you — a major red flag.",
            },
        ]

        # Money-request / PIN-request signal used to override legit-protection.
        self._override_pattern = re.compile(
            r"\b(tuma|send|peleka|lipa|lipe|kulipa|kulipia|rudisha|rejesha)\b"
            r".{0,40}\b(ksh|kshs|tzs|pin|fee|ada|insurance|bima|namba|number)\b"
            r"|\bpin\b.{0,25}\b(tuma|send|share|confirm|weka|nipe)\b"
            r"|\b(lazima|unahitaji|must|itabidi)\b.{0,25}\b(lipa|lipe|pay|clear|tuma|send)\b",
            re.IGNORECASE,
        )

        # Strict structural signature of a genuine M-PESA/Tigo Pesa/Halotel receipt.
        self._legit_signature = re.compile(
            r"\b[A-Z0-9]{9,10}\b.{0,20}(confirmed|imethibitishwa)"
            r".{0,400}(new\s?m-?pesa\s?balance\s?is|salio\s?jipya)",
            re.IGNORECASE | re.DOTALL,
        )
        # Looser secondary signature for M-Shwari/Fuliza system notices.
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
        a genuine transaction receipt AND contains no explicit money/PIN request.
        CRITICAL rules (weight >= 9) override this in analyze().
        """
        has_structure = bool(self._legit_signature.search(text)) or bool(
            self._legit_signature_soft.search(text)
        )
        if not has_structure:
            return False
        if self._override_pattern.search(text):
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

        # Suspicious sender heuristic.
        if sender and re.search(
            r"^\+?(254|255)?0?7\d{8}$|^\+?(254|255)?0?6\d{8}$",
            str(sender).replace(" ", ""),
        ):
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

        critical_hit = any(r["weight"] >= 9 for r in triggered_rules)
        if legit and not critical_hit:
            return {
                "status": "SAFE",
                "confidence": "HIGH",
                "score": 0,
                "triggered_rules": [],
                "recommendation": "✅ This matches the structure of a genuine M-PESA/mobile-money notification. Still double-check the sender ID if in doubt.",
            }

        score = min(round((total_weight / max_possible) * 100 * 4), 100)

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
        {
            "msg": "TB17CVOCY9 Confirmed. You have received Ksh2,500.00 from JOHN DOE 0712345678 on 18/6/26 at 3:42 PM. New M-PESA balance is Ksh4,500.00.",
            "sender": "MPESA", "expected": "SAFE",
        },
        {
            "msg": "M-Shwari: Your deposit of Ksh3,000.00 was successful on 18/6/26. Your M-Shwari savings balance is now Ksh18,500.00. Dial *334# for more options.",
            "sender": "MPESA", "expected": "SAFE",
        },
        {
            "msg": "QGH7K2MNB Confirmed. You have received Ksh1,000.00 from MARY WANJIRU 0722112233 on 18/6/26 at 9:15 AM. New M-PESA balance is Ksh3,210.00.",
            "sender": "MPESA", "expected": "SAFE",
        },

        # ── Forged receipts ───────────────────────────────────────────────
        {
            "msg": "UFK9X7J4O2 Confirmed. You have received Ksh6,500.00 from GRACE WANJIKU 254722111222 on 21/6/26 at 11:02 AM.Confirmed.You can now withdraw at any agent.New M-PESA balance is Ksh6,730.00.",
            "sender": "0722111222", "expected": "FRAUD",
        },
        {
            "msg": "UFM8Z2Y1X4 Confirmed. You have received Ksh12,400.00 from DR. PETER KAMAU 254700999888 on 21/6/2026 at 8:20 AM. New M-PESA balance is Ksh12,450.00. Refund immediately to avoid legal action.",
            "sender": "0700999888", "expected": "FRAUD",
        },
        {
            "msg": "UFO_9821_XYZ Confirmed. Ksh. 8,000.00 has been deposited to your wallet from Equity Bank on 21/06/26 at 10:44 AM. New M-PESA balance is Ksh. 8,150.00. To check balance dial *334#.",
            "sender": "0711223344", "expected": "FRAUD",
        },
        {
            "msg": "RN4X7K2MP1 Confirmed. Ksh5,000.00 received from JAMES OTIENO on 20/6/26. New M-PESA balance is Ksh5,200.00. New M-PESA balance is Ksh5,200.00. To verify call 0799123456.",
            "sender": "0799123456", "expected": "FRAUD",
        },
        {
            "msg": "Your amount of Ksh3,000 is currently HELD/PENDING. Contact our agent on 0712000111 to release your funds.",
            "sender": "0712000111", "expected": "FRAUD",
        },
        # NEW v5 forged receipt cases
        {
            "msg": "Pesa imewasili! Ksh10,000 imepokelewa kwenye akaunti yako. Tuma Ksh500 kwa wakala wetu 0744112233 kuthibitisha.", "sender": "0744112233", "expected": "FRAUD",
        },
        {
            "msg": "Payment received successfully. Ksh7,500 has been credited to your account. Please contact our agent on 0700445566 to process your funds.",
            "sender": "0700445566", "expected": "FRAUD",
        },
        {
            "msg": "On behalf of Equity Bank, your funds of Ksh50,000 have been confirmed. Please call 0799887766 to release the funds.",
            "sender": "0799887766", "expected": "FRAUD",
        },

        # ── Classic scams ─────────────────────────────────────────────────
        {
            "msg": "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.", "sender": "0712345678", "expected": "FRAUD",
        },
        {
            "msg": "Akaunti yako itafungwa leo kama hutathibitisha PIN.", "sender": "Safaricom", "expected": "FRAUD",
        },
        {
            "msg": "Loan yako imeapproved. Tuma Ksh 200 processing fee.", "sender": "0721123456", "expected": "FRAUD",
        },
        {
            "msg": "WEWE umechaguliwa kufanya kazi Dubai mshahara wa $2000. Tuma Ksh3,500 ada ya visa kwa Paybill 567890 Acc: JOBS2026.",
            "sender": "0700112233", "expected": "FRAUD",
        },
        {
            "msg": "Hujambo, mfungwa Kamiti Maximum anataka kuwasiliana nawe kuhusu urithi mkubwa. Piga 0798123456.",
            "sender": "0798123456", "expected": "FRAUD",
        },
        {
            "msg": "Habari, Polisi Trafiki, gari lako limepigwa picha ukivuka taa nyekundu, tuma Ksh3,000 fine kwa 0712009911.",
            "sender": "0712009911", "expected": "FRAUD",
        },
        {
            "msg": "Bonyeza hapa kuthibitisha M-Pesa yako: m-pesa-secure-update.com, vinginevyo akaunti itazimwa kesho.",
            "sender": "0789112233", "expected": "FRAUD",
        },
        {
            "msg": "NIMETUMA pesa kwa makosa kwa namba yako, tafadhali nirudishie Ksh2,000 kwa 0723445566.",
            "sender": "0723445566", "expected": "FRAUD",
        },
        {
            "msg": "Habari mzuri, umepata ufadhili wa masomo wa Ksh100,000 kutoka NGO ya kimataifa. Tuma Ksh1,500 ada ya usajili kwa 0734556688.",
            "sender": "0734556688", "expected": "FRAUD",
        },
        {
            "msg": "Habari, M-Shwari loan yako ya Ksh10,000 imeidhinishwa lakini lazima kwanza ulipe Ksh300 kuthibitisha akaunti.",
            "sender": "0745778899", "expected": "FRAUD",
        },
        {
            "msg": "Hongera mteja, umeshinda smartphone mpya kupitia promo ya Halotel. Tuma TZS5,000 ada ya ushuru kwa namba 0699112233 kupokea zawadi.",
            "sender": "0699112233", "expected": "FRAUD",
        },

        # ── NEW v5 additional category test cases ─────────────────────────

        # fake_charity_donation
        {
            "msg": "Tafadhali saidia watoto yatima wa Nyumba ya Watoto Nairobi. Tuma mchango wako kwa M-PESA namba 0712345000.",
            "sender": "0712345000", "expected": "FRAUD",
        },
        {
            "msg": "URGENT DONATION NEEDED: Familia masikini waliathirika na mafuriko. Tuma Ksh500 au zaidi kwa paybill 123456 acc FLOOD2026.",
            "sender": "0700456789", "expected": "FRAUD",
        },
        {
            "msg": "Mchungaji wetu anaomba msaada wa kujenga kanisa. Tuma chochote unachoweza kwa M-PESA 0733888999 akaunti CHURCH2026.",
            "sender": "0733888999", "expected": "FRAUD",
        },

        # fake_debt_collection
        {
            "msg": "Tunakukumbusha deni lako la Ksh8,500 liko overdue. Mkusanyaji wa deni atakuja kukamata mali yako ikiwa hutalipa sasa. Tuma kwa namba hii haraka.",
            "sender": "0711987654", "expected": "FRAUD",
        },
        {
            "msg": "Recovery agent: You have an outstanding debt. Pay now or we will list you on CRB blacklist today. Send Ksh3,000 to 0722001122 immediately.",
            "sender": "0722001122", "expected": "FRAUD",
        },
        {
            "msg": "Hii ni onyo la mwisho. Deni lako la Ksh5,000 halijalipiwa. Tutachukua hatua za kisheria ndani ya masaa 24. Tuma kwa namba hii sasa.",
            "sender": "0733445566", "expected": "FRAUD",
        },
        {
            "msg": "Tutakuweka CRB na credit yako itaathirika kama hutalipia mkopo wako leo. Tuma Ksh2,500 kwa namba hii mara moja.",
            "sender": "0700112345", "expected": "FRAUD",
        },

        # romance_scam
        {
            "msg": "Mpenzi wangu nakupenda sana. Niko stuck airport customs wameshikilia mzigo wangu. Tuma $200 tu kunisaidia western union. Nitakulipa baadaye.",
            "sender": "0799000111", "expected": "FRAUD",
        },
        {
            "msg": "Baby please buy me iTunes gift card worth Ksh5,000 and send me the code number. I will pay you back I promise.",
            "sender": "0733112233", "expected": "FRAUD",
        },
        {
            "msg": "Nakupenda sana darling. Ninatumia forex platform inayotoa guaranteed returns ya 30%. Invest Ksh5,000 leo upate Ksh15,000 kesho.",
            "sender": "0711445566", "expected": "FRAUD",
        },

        # impersonation_family_emergency
        {
            "msg": "Hii ni jirani yako. Mama yako amepata ajali na amepelekwa hospitali. Tuma Ksh5,000 haraka kwa operation fee kwa namba 0700888777.",
            "sender": "0700888777", "expected": "FRAUD",
        },
        {
            "msg": "Niko hospitali sasa hivi. Simu yangu imevunjika, ninapigia kwa simu ya mgeni. Nitahitaji Ksh3,000 bili ya hospitali. Tuma sasa hivi.",
            "sender": "0711000222", "expected": "FRAUD",
        },
        {
            "msg": "Nikopiwe Ksh1,500 tu sasa hivi. Niko emergency ya kweli. Nitarudisha kesho asubuhi bila shaka. Haraka sana.",
            "sender": "0722334455", "expected": "FRAUD",
        },

        # fake_tender_business_deal
        {
            "msg": "Hongera! Zabuni yako ya kutoa bidhaa serikalini imeshinda. Kabla ya kupata LPO tuma Ksh15,000 performance bond kwa akaunti 0722999888.",
            "sender": "0722999888", "expected": "FRAUD",
        },
        {
            "msg": "Your tender application ref TND/2026/001 has been approved. Please pay compliance fee of Ksh8,000 via M-PESA to 0700334455 to receive your contract.",
            "sender": "0700334455", "expected": "FRAUD",
        },
        {
            "msg": "Kenya Power inatafuta suppliers wa haraka. Umechaguliwa. Tuma Ksh10,000 security deposit kwa 0711223344 kupata order.",
            "sender": "0711223344", "expected": "FRAUD",
        },

        # fake_agent_overpayment
        {
            "msg": "Nimekupigia pesa nyingi kwa makosa. Nilitaka kutuma Ksh500 lakini nilitumia Ksh5,500. Tafadhali nirudishie tofauti ya Ksh5,000 kwa namba 0712777666.",
            "sender": "0712777666", "expected": "FRAUD",
        },
        {
            "msg": "Hi, I sent you Ksh2,000 by mistake instead of Ksh200. Please send back the difference of Ksh1,800 to this number urgently.",
            "sender": "0711333444", "expected": "FRAUD",
        },
        {
            "msg": "Nimekupa Ksh3,000 lakini nilitaka Ksh300 tu. Tofauti ya Ksh2,700 nirudishie kwa namba yangu haraka.",
            "sender": "0700998877", "expected": "FRAUD",
        },

        # fake_kyc_update
        {
            "msg": "Safaricom KYC Update: Taarifa zako zimepitwa na wakati. Thibitisha taarifa zako sasa kwa kubonyeza link hii au akaunti yako itafungwa: safaricom-kyc-update.co",
            "sender": "0789999000", "expected": "FRAUD",
        },
        {
            "msg": "Your SIM card registration is incomplete. Register your SIM now by sending your ID number to this number or your line will be deactivated within 24 hours.",
            "sender": "0700111000", "expected": "FRAUD",
        },
        {
            "msg": "Tuma jina lako kamili na nambari ya kitambulisho kuthibitisha akaunti yako ya M-PESA au itafungwa leo usiku.",
            "sender": "0711556677", "expected": "FRAUD",
        },

        # blackmail_extortion
        {
            "msg": "Tuna video yako ya siri. Tutatuma kwa familia yako na mwajiri wako kama hutalipia Ksh10,000 leo. Tuma kwa M-PESA namba 0711888777.",
            "sender": "0711888777", "expected": "FRAUD",
        },
        {
            "msg": "We have compromising photos of you. We will post them publicly if you don't send Ksh5,000 to 0722555444 within 2 hours. Don't go to police.",
            "sender": "0722555444", "expected": "FRAUD",
        },
        {
            "msg": "Tutakuaibisha mbele ya wote kama hutalipia Ksh8,000 ndani ya masaa mawili. Tuma kwa namba hii sasa au utajutia.",
            "sender": "0733667788", "expected": "FRAUD",
        },

        # fake_reversal
        {
            "msg": "Safaricom reversal agent hapa. Tuma Ksh100 kuthibitisha reversal ya Ksh5,000 itakayorejeshwa kwenye akaunti yako.",
            "sender": "0700123456", "expected": "FRAUD",
        },
        {
            "msg": "Pesa zilienda kwa namba yako kwa bahati mbaya. Tafadhali nirudishie Ksh4,000 kwa namba hii haraka.",
            "sender": "0711223344", "expected": "FRAUD",
        },

        # investment_scam
        {
            "msg": "Invest Ksh1,000 na upate Ksh5,000 ndani ya siku 3. Guaranteed returns ya 500%. Join sasa namba hii.",
            "sender": "0722334455", "expected": "FRAUD",
        },
        {
            "msg": "Bitcoin trading platform inayotoa faida ya 30% kila siku. Weka Ksh5,000 leo upate Ksh6,500 kesho. Guaranteed!",
            "sender": "0711998877", "expected": "FRAUD",
        },

        # job_recruitment_scam
        {
            "msg": "Umechaguliwa kwa kazi ya data entry online. Mshahara Ksh30,000 kwa mwezi. Tuma Ksh500 registration fee kwa 0700445566.",
            "sender": "0700445566", "expected": "FRAUD",
        },
    ]

    print("=" * 80)
    print("VIGILANT AI - RULE ENGINE v5.0 (Recall-Surge, EN/SW/Sheng, KE+TZ)")
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
        if result["triggered_rules"]:
            print("Triggers:")
            for rule in sorted(result["triggered_rules"], key=lambda r: -r["weight"])[:3]:
                print(f"   • [{rule['category']}] {rule['name']} (w={rule['weight']})")
        print("-" * 80)

    print(f"\n{'='*80}")
    print(f"RESULT: {passed}/{len(test_cases)} test cases passed.")
    if failed_cases:
        print("\nFAILED CASES:")
        for c in failed_cases:
            print(f"  • [{c['expected']}] {c['msg'][:80]}...")
    print("=" * 80)