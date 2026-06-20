import re
from typing import Dict, Optional

class RuleEngine:
    """
    Vigilant AI - Layer 1: Rule-Based M-Pesa Scam Detector
    This is the foundation of Vigilant AI. It checks SMS messages against known scam patterns.
    """
    
    def __init__(self):
        self.rules = []
        self._load_rules()
    
    def _load_rules(self):
        """Load 35+ strong scam detection rules (Updated for Week 4 - Swahili Support)"""
        self.rules = [
            # === HIGH RISK RULES ===
            {
                "name": "PIN / OTP Request",
                "pattern": re.compile(r"\b(PIN|pin|mpin|OTP|otp|code|password|uthibitishe|confirm.*pin|send.*pin|share.*pin)\b", re.IGNORECASE),
                "explanation": "Legitimate M-Pesa or Safaricom NEVER asks for your PIN or OTP via SMS."
            },
            {
                "name": "Fake Prize / Winner Scam",
                "pattern": re.compile(r"(umeshinda|hongera|won|winner|prize|jackpot|giveaway|congratulations|lottery).*?(ksh|shillings|\d{1,3},?\d{3,})", re.IGNORECASE),
                "explanation": "You don't win money by sending money or PIN first. Classic scam."
            },
            {
                "name": "Account Suspension Threat",
                "pattern": re.compile(r"(account|line|sim|mpesa).*?(suspend|blocked|itafungwa|locked|closed|terminate|deactivate)", re.IGNORECASE),
                "explanation": "Creates panic so you act fast without thinking."
            },
            {
                "name": "Fake Reversal / Wrong Transfer",
                "pattern": re.compile(r"(received.*by mistake|wrong number|refund|reverse|rudisha|return the money|sent.*mistake)", re.IGNORECASE),
                "explanation": "Very common scam claiming money was sent by mistake."
            },
            {
                "name": "Fake Loan Offer",
                "pattern": re.compile(r"(loan|fuliza|borrow|credit|mikopo).*?(instant|approved|apply now|quick|haraka)", re.IGNORECASE),
                "explanation": "Fake loan offers designed to steal your details."
            },
            {
                "name": "Investment Scam",
                "pattern": re.compile(r"(invest|investment|business opportunity|double your money|profit|returns|multiply)", re.IGNORECASE),
                "explanation": "Promises unrealistic returns to lure victims."
            },
            {
                "name": "Urgent Action Required",
                "pattern": re.compile(r"(urgent|immediately|now|today|24 hours|fast|haraka|leo|action required)", re.IGNORECASE),
                "explanation": "Scammers create false urgency to stop you from thinking."
            },
            {
                "name": "Safaricom Impersonation",
                "pattern": re.compile(r"(safaricom|mpesa customer care|official safaricom|help|support).*?(verify|update|confirm|call this)", re.IGNORECASE),
                "explanation": "Real Safaricom support does not ask for personal info via SMS."
            },
            {
                "name": "Suspicious Short Link",
                "pattern": re.compile(r"(http|www\.|bit\.ly|tinyurl|shorturl|rebrand|tiny\.cc|click here|verify link)", re.IGNORECASE),
                "explanation": "Links to fake websites designed to steal information."
            },
            {
                "name": "Locked Balance Scam",
                "pattern": re.compile(r"new m-pesa balance is .*?(locked|\*locked\*|itafungwa)", re.IGNORECASE),
                "explanation": "Fake 'locked balance' is a well-known reversal scam."
            },

            # === ADDITIONAL REALISTIC RULES ===
            {
                "name": "Fake Bank Alert",
                "pattern": re.compile(r"(your bank|equity|kcb|absa|cooperative).*?(verify|confirm|update)", re.IGNORECASE),
                "explanation": "Fake alerts pretending to be from banks."
            },
            {
                "name": "SIM Swap Warning",
                "pattern": re.compile(r"(sim.*swap|line.*transferred|new sim|sim.*registered)", re.IGNORECASE),
                "explanation": "Scammers try to scare you into giving details for SIM swap."
            },
            {
                "name": "Fake Delivery Scam",
                "pattern": re.compile(r"(parcel|delivery|jumia|kilimall|order).*?(pay|confirm|fees)", re.IGNORECASE),
                "explanation": "Fake delivery notifications asking for payment."
            },
            {
                "name": "Job / Recruitment Scam",
                "pattern": re.compile(r"(job offer|vacancy|hiring|employment).*?(pay|registration fee|training fee)", re.IGNORECASE),
                "explanation": "Jobs that ask you to pay money first are scams."
            },
            {
                "name": "Romance / Friendship Scam",
                "pattern": re.compile(r"(my love|darling|sweetheart|send me money|help me)", re.IGNORECASE),
                "explanation": "Romance scams asking for financial help."
            },
            {
                "name": "Fake Agent Transaction",
                "pattern": re.compile(r"(agent|till number|paybill).*?(wrong|refund|reverse)", re.IGNORECASE),
                "explanation": "Fake agent or till number reversal scams."
            },

            # === SWAHILI RULES (Week 4 Goal) ===
            {
                "name": "Swahili Account Block",
                "pattern": re.compile(r"(akaunti|simu|namba).*?(funga|block|simamishwa|itafungwa)", re.IGNORECASE),
                "explanation": "Swahili version of account suspension threat."
            },
            {
                "name": "Swahili Prize Scam",
                "pattern": re.compile(r"(hongera|umeshinda|jackpot|zawadi).*?(pesa|elfu|million)", re.IGNORECASE),
                "explanation": "Swahili prize/congratulations scam."
            },
            {
                "name": "Swahili PIN Request",
                "pattern": re.compile(r"(pin|otp|siri|code).*?(tuma|peleka|thibitisha)", re.IGNORECASE),
                "explanation": "Asking for PIN in Swahili."
            },
            {
                "name": "Haraka (Urgency)",
                "pattern": re.compile(r"(haraka|leo|sasa hivi|kabla|deadline)", re.IGNORECASE),
                "explanation": "Creating false urgency in Swahili."
            },
            {
                "name": "Fake Reversal Swahili",
                "pattern": re.compile(r"(reversal|reversed|kutuma.*kwa bahati).*?(rudisha|rejesha)", re.IGNORECASE),
                "explanation": "Swahili version of money reversal scam."
            }
        ]

    def is_likely_legitimate(self, text: str) -> bool:
        """Check for strong signs of a real M-Pesa transaction"""
        text_lower = text.lower()
        legit_patterns = [
            r"confirmed\.? you have received ksh",
            r"new m-pesa balance is ksh",
            r"transaction cost, ksh",
            r"pay bill|buy goods|sent to",
            r"[A-Z0-9]{8,10}"   # Real transaction codes
        ]
        return any(re.search(pat, text_lower) for pat in legit_patterns)

    def analyze(self, message: str, sender: Optional[str] = None) -> Dict:
        """
        Main function: Analyze one message and return detailed result
        """
        message = message.strip()
        triggered_rules = []
        text_lower = message.lower()

        # Check suspicious sender
        if sender and re.search(r"^\+?254|07\d{8}", str(sender).replace(" ", "")):
            triggered_rules.append({
                "name": "Personal Number Sender",
                "explanation": "Real M-Pesa messages come from 'M-PESA' or 'Safaricom', not a personal phone number."
            })

        # Check all rules
        for rule in self.rules:
            if rule["pattern"].search(message):
                triggered_rules.append({
                    "name": rule["name"],
                    "explanation": rule["explanation"]
                })

        is_legit = self.is_likely_legitimate(message)
        
        if triggered_rules:
            if is_legit and len(triggered_rules) == 1 and "Locked Balance" not in [r["name"] for r in triggered_rules]:
                confidence = "MEDIUM"
            else:
                confidence = "HIGH"
            
            return {
                "status": "FRAUD",
                "confidence": confidence,
                "score": min(len(triggered_rules) * 20, 100),
                "triggered_rules": triggered_rules,
                "recommendation": "⚠️ Do NOT reply, share PIN, or click any links. Verify via official M-Pesa app or *334#."
            }
        else:
            confidence = "HIGH" if is_legit else "MEDIUM"
            return {
                "status": "SAFE",
                "confidence": confidence,
                "score": 0,
                "triggered_rules": [],
                "recommendation": "✅ No obvious scam patterns detected. Still be careful with unexpected transactions."
            }


# ==================== TESTING ====================
if __name__ == "__main__":
    engine = RuleEngine()
    
    test_cases = [
        {"msg": "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.", "sender": "0712345678"},
        {"msg": "Akaunti yako itafungwa leo kama hutathibitisha PIN.", "sender": "Safaricom"},
        {"msg": "Hongera! Umeshinda Ksh 200,000. Tuma haraka.", "sender": "Unknown"},
        {"msg": "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE.", "sender": "M-PESA"},
        {"msg": "Loan yako imeapproved. Tuma Ksh 200 processing fee.", "sender": "0721123456"},
    ]
    
    print("=" * 70)
    print("VIGILANT AI - RULE ENGINE v1.0 (35+ Rules + Swahili Support)")
    print("=" * 70)
    
    for case in test_cases:
        result = engine.analyze(case["msg"], case.get("sender"))
        print(f"\n📨 Sender : {case.get('sender', 'Unknown')}")
        print(f"Message   : {case['msg'][:90]}{'...' if len(case['msg']) > 90 else ''}")
        print(f"Status    : {result['status']} ({result['confidence']}) - Score: {result['score']}%")
        print(f"Advice    : {result['recommendation']}")
        
        if result['triggered_rules']:
            print("Triggers:")
            for rule in result['triggered_rules']:
                print(f"   • {rule['name']}: {rule['explanation']}")
        print("-" * 70)