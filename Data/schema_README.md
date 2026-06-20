# Vigilant AI — Canonical Dataset Schema

Every source that feeds the dataset (your own collected messages, community
reports, external open datasets, synthetic batches) gets normalized into
**one** schema before it lands in `data/scam_dataset.csv`. This is what
Month 3's ML classifier will train on, so getting this right now saves you
from a painful re-label later.

## Columns

| Column            | Type   | Required | Notes |
|-------------------|--------|----------|-------|
| `message_text`    | string | yes      | The raw SMS/message content, unmodified |
| `label`           | string | yes      | Exactly `fraud` or `legit` (lowercase) |
| `language`         | string | yes      | One of: `en`, `sw`, `sheng`, `mixed` |
| `fraud_category`  | string | yes if fraud, else `n/a` | Must match a name in `RULE_CATEGORIES` below |
| `source`          | string | yes      | Where it came from — see Source Tags |
| `date_collected`  | string | yes      | ISO format `YYYY-MM-DD` |

## Fraud category tags (keep these in sync with `rule_engine.py` rule names)

pin_otp_request

fake_prize_winner

account_suspension_threat

fake_reversal

fake_loan

investment_scam

safaricom_impersonation

suspicious_link

locked_balance

fake_bank_alert

sim_swap_warning

fake_delivery

job_recruitment_scam

romance_scam

fake_agent_transaction

trusted_contact_redirect

fake_secret_society

fake_landlord

ussd_manipulation

fake_government_refund

fake_agent_visit

crypto_forex_scam

chama_sacco_scam

money_mule_recruitment

fake_customer_care

fake_utility_bill

fake_charity

other

## Source tags

| Tag | Meaning |
|---|---|
| `month1_collection` | Messages you personally collected in Month 1 (your existing `scam_examples.csv`) |
| `community_report`  | Submitted through the app's "Report a scam" feature |
| `ca_kenya`          | Pulled from CA Kenya consumer fraud bulletins |
| `twitter_x`         | Found via Grok/X search of Kenyan scam reports |
| `synthetic_claude`  | Generated using the prompt in `prompts/synthetic_data_generation_prompt.md` with Claude |
| `synthetic_chatgpt` | Same, generated with ChatGPT |
| `external_swahili_sms_dataset` | Henry Dioniz's Kaggle "Swahili SMS Detection Dataset" — **Tanzania-context, re-validate against Kenyan M-Pesa patterns before trusting labels at face value** |
| `legit_sample`      | Genuine M-Pesa confirmations / legitimate messages, needed so the model learns what "safe" looks like too |

## Why `legit` examples matter just as much as `fraud` ones

Your rule engine test suite is fraud-heavy. The ML classifier in Month 3
needs roughly **as many genuine, boring, legitimate messages** (real M-Pesa
confirmations, real bank alerts, normal personal texts) as fraud examples,
or the model will learn "any message = fraud" and your false-positive rate
will be unusable. Budget at least 40% of Week 1-4 collection toward
`legit_sample` and `month1_collection` legitimate messages.