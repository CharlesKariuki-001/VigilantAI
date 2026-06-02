import re

# Enhanced Scam Patterns based on real M-Pesa fraud (2025-2026 reports)
SCAM_PATTERNS = [
    {
        "name": "PIN Request",
        "pattern": r"\b(PIN|pin|mpin|send.*pin|share.*pin|uthibitishe|confirm.*pin)\b",
        "reason": "Legitimate M-Pesa or Safaricom NEVER asks for your PIN via SMS"
    },
    {
        "name": "Fake Prize/Lottery",
        "pattern": r"(umeshinda|hongera|you have won|winner|prize|giveaway|jackpot|ksh\s*\d{1,3},?\d{3})",
        "reason": "Classic lottery scam — no legitimate prize requires you to send money/PIN first"
    },
    {
        "name": "Account Threat / Urgency",
        "pattern": r"(account.*(suspend|blocked|itafungwa|locked|closed)|suspended|immediately|urgent|action now)",
        "reason": "Creates panic to rush you into sharing details"
    },
    {
        "name": "Fake Reversal / Wrong Transfer",
        "pattern": r"(received.*by mistake|wrong number|refund|reverse|rudisha|return the money|tumia.*agent)",
        "reason": "Common scam: Fake 'sent by mistake' message + follow-up call to refund"
    },
    {
        "name": "Suspicious Link",
        "pattern": r"(http|www\.|bit\.ly|tinyurl|click here|verify|confirm).*?(?!safaricom\.co\.ke)",
        "reason": "Scammers use shortened or fake links to phishing sites"
    },
    {
        "name": "Fake Safaricom / Support",
        "pattern": r"(safaricom.*(help|support|customer care|0722|0800)|call this number|dial.*[0-9]{4})",
        "reason": "Official Safaricom support is 0722 000 100 or 100. They don't ask for PIN"
    },
    {
        "name": "Locked Balance",
        "pattern": r"new m-pesa balance is .*?(locked|\*locked\*)",
        "reason": "Classic sign of fake 'old-style' reversal scam messages"
    }
]

def is_likely_legitimate(text: str) -> bool:
    """Quick check for patterns that strongly suggest a real M-Pesa message"""
    text_lower = text.lower()
    legit_indicators = [
        r"confirmed\.? you have received ksh",
        r"new m-pesa balance is ksh",
        r"transaction cost, ksh",
        r"pay bill|buy goods|sent to",
        r"[A-Z0-9]{8,10}"  # Transaction code like TB17CVOCY9
    ]
    return any(re.search(pat, text_lower) for pat in legit_indicators)

def check_message(text: str, sender: str = None):
    """
    Enhanced M-Pesa scam detector.
    - sender: Optional, e.g. 'M-PESA' or phone number
    """
    text_lower = text.lower()
    triggered_rules = []
    
    # Check sender (very strong signal)
    if sender and re.search(r"^\+?254|07\d{8}", sender.replace(" ", "")):
        triggered_rules.append({
            "rule": "Sender is personal number",
            "reason": "Real M-Pesa messages come from 'M-PESA' or 'Safaricom', not a phone number"
        })
    
    for rule in SCAM_PATTERNS:
        if re.search(rule["pattern"], text_lower, re.IGNORECASE):
            triggered_rules.append({
                "rule": rule["name"],
                "reason": rule["reason"]
            })
    
    # Legitimacy check to reduce false positives
    is_legit = is_likely_legitimate(text)
    
    if triggered_rules:
        confidence = "HIGH" if len(triggered_rules) > 2 or (sender and "personal" in triggered_rules[0]["rule"]) else "MEDIUM"
        if is_legit and "Locked Balance" in [r["rule"] for r in triggered_rules]:
            confidence = "HIGH"  # Fake locked balance is very suspicious even if format looks legit
        
        return {
            "status": "FRAUD",
            "confidence": confidence,
            "triggers": triggered_rules,
            "message": "⚠️ This message shows signs of fraud. Do NOT respond, share PIN, or click links. Verify via *334# or M-Pesa app."
        }
    else:
        confidence = "HIGH" if is_legit else "MEDIUM"
        return {
            "status": "SAFE",
            "confidence": confidence,
            "triggers": [],
            "message": "✅ No obvious scam patterns. Still verify large/unexpected transactions via official channels."
        }

# Updated Test Cases (realistic examples)
if __name__ == "__main__":
    test_cases = [
        {
            "msg": "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
            "sender": "0712345678"
        },
        {
            "msg": "Your M-Pesa account will be suspended. Click http://bit.ly/mpesa-verify to reactivate.",
            "sender": "Safaricom"
        },
        {
            "msg": "MCG8AU052I Confirmed. You have received Ksh5,850.00 from SYLVESTER OJUMA 0717061230 on 16/3/18. New M-PESA balance is Ksh(LOCKED).",
            "sender": "0712345678"  # Fake sender = high risk
        },
        {
            "msg": "TB17CVOCY9 Confirmed. You have received Ksh2,500.00 from JOHN DOE on 12/05/26 at 14:30. New M-PESA balance is Ksh12,450.00.",
            "sender": "M-PESA"
        },
        {
            "msg": "Hongera! You have won Ksh 100,000. Send Ksh 500 to claim your prize.",
            "sender": "Unknown"
        }
    ]
    
    print("=" * 60)
    print("VIGILANT AI - Enhanced M-Pesa Scam Detector")
    print("=" * 60)
    
    for case in test_cases:
        msg = case["msg"]
        sender = case.get("sender")
        print(f"\nSender : {sender or 'Unknown'}")
        print(f"Message: {msg[:80]}{'...' if len(msg) > 80 else ''}")
        result = check_message(msg, sender)
        print(f"Status : {result['status']} ({result['confidence']})")
        print(f"Advice : {result['message']}")
        if result['triggers']:
            for t in result['triggers']:
                print(f"   • {t['rule']}: {t['reason']}")
        print("-" * 60)