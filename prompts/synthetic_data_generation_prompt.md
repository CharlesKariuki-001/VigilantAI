# Synthetic Scam SMS Generation — Month 2 / Week 1, Day 5

Paste ONE block below at a time into Claude or ChatGPT. Run it once per
category (21 categories listed) and once for a `legit` batch. Save each
response as a separate CSV in `data/synthetic/` — e.g.
`synthetic_claude_trusted_contact_redirect.csv`.

Doing one category per prompt (rather than "generate 500 mixed examples")
gives far more realistic, non-repetitive phrasing, and makes it trivial to
spot-check quality per category afterward.

## The prompt template

Copy this whole block, fill in {CATEGORY} and {CATEGORY_DESCRIPTION} from
the table below, and send it:

---
You are helping build a fraud-detection training dataset for Kenyan M-Pesa
mobile money users. Generate 40 realistic SMS messages that are examples of
the "{CATEGORY}" scam category: {CATEGORY_DESCRIPTION}

Requirements:
- Mix English, Swahili, and Sheng/code-switched phrasing (roughly 40% English,
  40% Swahili, 20% mixed/Sheng) — vary which language dominates each message.
- Vary phrasing, sender claims, amounts, and urgency level — no two messages
  should follow an identical template.
- Keep each message under 160 characters, like a real SMS.
- Include realistic but clearly fake details (made-up amounts, fake reference
  codes, generic Kenyan names) — do not use real phone numbers or real
  organisation contact details.
- Do NOT add commentary, numbering prose, or explanations — output ONLY a
  CSV with this exact header and these exact columns:

message_text,label,language,fraud_category
"<message text here>",fraud,en,{CATEGORY_SLUG}

Use "en" for English-dominant, "sw" for Swahili-dominant, "sheng" for
Sheng/slang-heavy, "mixed" for genuinely code-switched messages.
Output raw CSV only, properly quoted, no markdown code fences, no extra text.
---

## Category table — run one prompt per row

| {CATEGORY} | {CATEGORY_SLUG} | {CATEGORY_DESCRIPTION} |
|---|---|---|
| PIN/OTP Request | pin_otp_request | Messages asking the recipient to share their M-Pesa PIN, OTP, or password to "verify" something |
| Fake Prize / Winner | fake_prize_winner | Messages claiming the recipient won a cash prize, jackpot, or giveaway and must act to claim it |
| Account Suspension Threat | account_suspension_threat | Messages threatening that the M-Pesa line/account will be suspended or blocked unless the recipient acts immediately |
| Fake Reversal / Wrong Transfer | fake_reversal | Messages claiming money was sent "by mistake" and asking the recipient to send it back |
| Fake Loan Offer | fake_loan | Messages offering instant/pre-approved loans that require a small upfront "processing fee" |
| Investment Scam | investment_scam | Messages promising guaranteed high returns on a vague "business opportunity" or investment |
| Safaricom/Bank Impersonation | safaricom_impersonation | Messages pretending to be from Safaricom or a bank's official support line, asking to "verify" account details |
| Suspicious Link | suspicious_link | Messages with a shortened or suspicious link to "verify", "claim", or "update" something |
| SIM Swap Warning | sim_swap_warning | Messages referencing a SIM swap or line transfer, designed to scare the recipient into sharing details |
| Trusted Contact Money Redirect | trusted_contact_redirect | Messages impersonating a friend/relative/employer mid-conversation, asking the recipient to send money to "this number" because their old number changed |
| Fake Secret Society / Get-Rich Recruitment | fake_secret_society | Messages inviting the recipient to join a "brotherhood"/wealth club requiring a joining fee for guaranteed riches |
| Fake Landlord / Rental Deposit | fake_landlord | Messages advertising an attractive rental house and demanding a deposit before any viewing |
| USSD Dial Code Manipulation | ussd_manipulation | Messages instructing the recipient to dial a specific USSD code to "receive" a prize or reversal |
| Fake Government/Tax Refund | fake_government_refund | Messages impersonating KRA, NHIF/SHA, or NSSF claiming the recipient is owed a refund requiring registration with personal ID details |
| Fake Agent Visit / SIM Upgrade | fake_agent_visit | Messages claiming to be from an M-Pesa agent or technician offering an in-person or phone "SIM upgrade" |
| Crypto / Forex / Trading Bot | crypto_forex_scam | Messages promoting a crypto, forex, or "trading bot" scheme with guaranteed daily profits |
| Chama / SACCO Contribution | chama_sacco_scam | Messages impersonating a savings-group (chama/SACCO) official requesting an urgent contribution |
| Money Mule Recruitment | money_mule_recruitment | Messages recruiting the recipient to receive and forward money through their account for a cut/commission |
| Fake Customer Care Callback | fake_customer_care | Messages directing the recipient to call an unofficial number for "customer care" |
| Fake Utility/Bill Disconnection | fake_utility_bill | Messages impersonating KPLC or a water company threatening disconnection unless an urgent payment is made |
| Fake Charity/Disaster Relief | fake_charity | Messages soliciting donations for a disaster or tragedy that exploit real or fabricated events |

## Don't forget the legit batch

---
Generate 80 realistic Kenyan SMS messages that are completely legitimate
and NOT fraud — a mix of:
- Real-format M-Pesa transaction confirmations (the actual Safaricom format:
  reference code, "Confirmed. You have received/sent Ksh X from/to NAME",
  new balance, transaction cost)
- Ordinary personal texts between friends/family in English/Swahili/Sheng
  that mention money casually but are NOT scams (e.g. "nitumie hiyo 500
  nikuje class", "thanks for the fare bro")
- Genuine bank/utility notifications with normal, non-urgent tone

Vary language the same way as before (English/Swahili/Sheng mix). Output
ONLY raw CSV, no commentary, with this exact header:

message_text,label,language,fraud_category
"<message text here>",legit,en,n/a
---

## After generating

1. Save each batch as data/synthetic/synthetic_<source>_<category>.csv
2. Spot-check 5-10 rows per file by eye — delete anything repetitive,
   nonsensical, or off-category.
3. Run `python scripts/build_dataset.py` — it auto-discovers everything in
   data/synthetic/ and merges it into data/scam_dataset.csv.