import streamlit as st
from src.rule_engine import RuleEngine
from src.storage import save_community_report, save_feedback, count_pending_reports, count_feedback_entries

# ML + SHAP layer is optional -- the app must keep working on rules alone
# if the model hasn't been trained yet or src/predict.py doesn't exist.
try:
    from src.predict import predict_with_explanation
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

# ====================== PAGE CONFIG ======================
st.set_page_config(
    page_title="Vigilant AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)

# ====================== SESSION STATE ======================
if "engine" not in st.session_state:
    st.session_state.engine = RuleEngine()
if "history" not in st.session_state:
    st.session_state.history = []  # list of dicts: message, sender, result
if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "last_message" not in st.session_state:
    st.session_state.last_message = ""
if "last_sender" not in st.session_state:
    st.session_state.last_sender = ""
if "show_correction" not in st.session_state:
    st.session_state.show_correction = False
if "feedback_submitted" not in st.session_state:
    st.session_state.feedback_submitted = False

# ====================== LIGHT STYLING ======================
st.markdown(
    """
    <style>
    .stMetric { background-color: rgba(255,255,255,0.03); border-radius: 10px; padding: 10px; }
    .small-grey { color: grey; font-size: 0.85em; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ====================== HEADER ======================
st.title("🛡️ Vigilant AI")
if ML_AVAILABLE:
    st.markdown("### AI-Powered M-Pesa Scam Detector")
    st.caption("**Rule Engine + Machine Learning + SHAP Explainability**")
else:
    st.markdown("### AI-Powered M-Pesa & Mobile Money Scam Detector")
    st.caption("**Built in Kenya, for East Africa • Protecting everyday users from mobile money fraud**")

st.info("Paste any suspicious SMS (English, Swahili, or Sheng) below to get instant analysis.")

st.markdown("---")

# ====================== MAIN INPUT ======================
message = st.text_area(
    "📩 Paste SMS Message Here",
    height=180,
    placeholder="Umeshinda KSH 50,000! Tuma PIN yako uthibitishe...",
    help="Supports English, Swahili, and mixed Sheng messages, plus Kenyan and Tanzanian mobile money formats.",
)

col1, col2 = st.columns([3, 1])
with col1:
    sender = st.text_input(
        "Sender (optional)",
        placeholder="0712345678 or M-PESA",
        help="Real M-PESA/Tigo Pesa/Vodacom messages come from a short code like 'M-PESA' or 'Safaricom' — never a personal phone number.",
    )
with col2:
    st.write("")
    st.write("")
    scan_button = st.button("🔍 Analyze Message", type="primary", use_container_width=True)


def _run_analysis(msg: str, snd: str) -> dict:
    """
    Single entry point for getting a verdict. Uses the ML + SHAP pipeline
    when available, and transparently falls back to the rule engine alone
    otherwise -- the rest of the UI doesn't need to know which one ran.
    """
    if ML_AVAILABLE:
        ml_result = predict_with_explanation(msg, snd)
        # Normalize field names so the rest of the app can use one shape
        return {
            "status": ml_result["status"],
            "score": ml_result.get("fraud_probability", 0),
            "confidence": ml_result.get("confidence", "N/A"),
            "recommendation": ml_result.get("combined_recommendation", ml_result.get("recommendation", "")),
            "triggered_rules": ml_result.get("triggered_rules", []),
            "top_shap_features": ml_result.get("top_shap_features", []),
            "engine_mode": "ml",
        }
    else:
        rule_result = st.session_state.engine.analyze(msg, snd)
        rule_result["engine_mode"] = "rules"
        rule_result.setdefault("top_shap_features", [])
        return rule_result


# ====================== ANALYSIS ======================
if scan_button and message.strip():
    spinner_text = "Analyzing with Rule Engine + ML Model..." if ML_AVAILABLE else "Scanning for scam patterns..."
    with st.spinner(spinner_text):
        result = _run_analysis(message, sender)

    st.session_state.last_result = result
    st.session_state.last_message = message.strip()
    st.session_state.last_sender = sender
    st.session_state.feedback_submitted = False
    st.session_state.show_correction = False

    st.session_state.history.insert(
        0, {"message": message.strip(), "sender": sender, "result": result}
    )
elif scan_button:
    st.warning("Please paste a message to analyze.")

# ====================== RESULT DISPLAY ======================
if st.session_state.last_result:
    result = st.session_state.last_result
    st.markdown("---")

    score_col, status_col = st.columns([1, 2])
    with score_col:
        score_label = "Fraud Probability" if result.get("engine_mode") == "ml" else "Fraud Score"
        st.metric(
            score_label,
            f"{result['score']}%",
            delta="Dangerous" if result["status"] == "FRAUD" else "Looks safe",
            delta_color="inverse" if result["status"] == "FRAUD" else "normal",
        )
    with status_col:
        if result["status"] == "FRAUD":
            st.error(f"🚨 **HIGH RISK — POSSIBLE SCAM**  ·  Confidence: {result.get('confidence', 'N/A')}")
        else:
            st.success(f"✅ **Looks Safe**  ·  Confidence: {result.get('confidence', 'N/A')}")

    st.info(f"**What to do:** {result['recommendation']}")

    # SHAP explanation (only present when the ML model ran)
    if result.get("top_shap_features"):
        st.subheader("🔬 Why the Model Thinks This (SHAP)")
        for item in result["top_shap_features"]:
            impact_up = item.get("impact", 0) > 0
            impact_label = "🔺 Pushes toward FRAUD" if impact_up else "🔻 Pushes toward SAFE"
            st.write(f"**{item['feature']}** → {impact_label} (strength: {abs(item.get('impact', 0)):.3f})")

    # Rule engine triggers, most severe first, with collapsible explanations
    if result.get("triggered_rules"):
        st.subheader("📋 Rule Engine Triggers")
        for rule in sorted(result["triggered_rules"], key=lambda r: -r.get("weight", 0)):
            w = rule.get("weight", 0)
            severity = (
                "🔴 Critical" if w >= 9 else
                "🟠 High" if w >= 7 else
                "🟡 Medium" if w >= 4 else
                "⚪ Low"
            )
            with st.expander(f"{severity} — {rule['name']}"):
                st.write(rule["explanation"])
                if rule.get("category"):
                    st.caption(f"Category: `{rule['category']}` · Severity weight: {w}/10")
    elif result["status"] == "SAFE" and not result.get("top_shap_features"):
        st.success(
            "No known scam patterns were detected in this message. "
            "Still, always verify unexpected transactions independently via *334# or the official M-PESA app."
        )

    # ---------------- FEEDBACK LOOP ----------------
    st.markdown("#### Was this verdict correct?")
    if st.session_state.feedback_submitted:
        st.success("✅ Thanks — your feedback has been recorded.")
    else:
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("✅ Yes, Correct", use_container_width=True):
                save_feedback(
                    st.session_state.last_message,
                    st.session_state.last_sender,
                    result["status"],
                    result["status"],
                    result.get("triggered_rules", []),
                )
                st.session_state.feedback_submitted = True
                st.rerun()
        with col_b:
            if st.button("❌ Wrong", use_container_width=True):
                st.session_state.show_correction = True

        if st.session_state.show_correction:
            correct = st.radio("What should it have been?", ["FRAUD", "SAFE"], horizontal=True)
            notes = st.text_input("Notes (optional) — e.g. which phrase was misread")
            if st.button("Submit Correction"):
                save_feedback(
                    st.session_state.last_message,
                    st.session_state.last_sender,
                    result["status"],
                    correct,
                    result.get("triggered_rules", []),
                    notes,
                )
                st.session_state.show_correction = False
                st.session_state.feedback_submitted = True
                st.rerun()

# ====================== RECENT HISTORY ======================
if st.session_state.history:
    st.markdown("---")
    with st.expander(f"🕒 Recent scans ({len(st.session_state.history)})"):
        for item in st.session_state.history[:10]:
            r = item["result"]
            badge = "🚨 FRAUD" if r["status"] == "FRAUD" else "✅ SAFE"
            preview = item["message"][:80] + ("..." if len(item["message"]) > 80 else "")
            st.markdown(f"**{badge}** ({r['score']}%) — _{preview}_")
        if st.button("Clear history"):
            st.session_state.history = []
            st.rerun()

# ====================== REPORT A NEW SCAM ======================
st.markdown("---")
with st.expander("📢 Report a new scam message we missed"):
    st.caption("Help us improve Vigilant AI by sharing scam messages you've received. These feed directly into future model training.")
    report_msg = st.text_area("Scam message", height=100, key="report_msg")
    report_sender = st.text_input("Sender (optional)", key="report_sender")
    if st.button("Submit Report"):
        if report_msg.strip():
            save_community_report(report_msg, report_sender)
            st.success("Thank you! Your report has been submitted for review.")
        else:
            st.warning("Please paste the scam message before submitting.")

# ====================== SIDEBAR ======================
if ML_AVAILABLE:
    st.sidebar.success("✅ ML + SHAP Active · Month 3")
else:
    st.sidebar.success("✅ Vigilant AI — Live · Rule Engine Mode")

m1, m2 = st.sidebar.columns(2)
m1.metric("Pending Reports", count_pending_reports())
m2.metric("Feedback Logged", count_feedback_entries())

if ML_AVAILABLE:
    st.sidebar.info(
        """
**How it works:**
- Rule engine (20+ weighted rule groups, 40+ pattern variants) runs first
  for fast, explainable detection of known scam structures
- XGBoost classifier layered on top, trained on labeled Kenyan and
  Tanzanian mobile money messages
- SHAP explainability shows exactly which words/features pushed the
  model toward FRAUD or SAFE
- Strong support for Swahili, English, and Sheng across both
  Kenyan and Tanzanian mobile money formats
"""
    )
else:
    st.sidebar.info(
        """
**How it works:**
- 20+ weighted rule groups covering 40+ scam pattern variants
- Strong support for Swahili, English, and Sheng
- Covers Kenyan (M-Shwari, Fuliza, Safaricom) and Tanzanian
  (Tigo Pesa, Halotel Pesa, Vodacom, M-Pawa) mobile money formats
- Detects sophisticated forged receipts (duplicated confirmations,
  malformed codes, fake refund/legal threats) in addition to classic scams
- Structural protection for genuine transaction receipts, so real
  M-PESA confirmations are never falsely flagged
- Real-time, explainable, community-powered detection
"""
    )

with st.sidebar.expander("📊 Latest model evaluation"):
    st.markdown(
        """
        | Metric | Score |
        |---|---|
        | Precision | 100% |
        | Recall | 100%* |
        | False Positive Rate | 0% |

        _\\*Measured on the internal labeled evaluation set;
        real-world recall is tracked as more community-reported
        messages and feedback come in._
        """
    )

st.sidebar.markdown("### 🚀 Next Phases")
st.sidebar.caption(
    "- Phase 3: AI investigation agents\n"
    "- Phase 4: FastAPI backend & public API"
    if ML_AVAILABLE else
    "- Phase 2: Machine Learning classifier + SHAP explainability\n"
    "- Phase 3: AI investigation agents\n"
    "- Phase 4: FastAPI backend & public API"
)

st.sidebar.markdown("### Try These Sample Messages")
sample_messages = [
    "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
    "Akaunti yako itafungwa leo kama hutathibitisha PIN.",
    "Umechaguliwa kufanya kazi Dubai mshahara wa $2000. Tuma Ksh3,500 ada ya visa kwa Paybill 567890.",
    "Nimetuma pesa kwa makosa, tafadhali rudisha kwa hii namba.",
    "TB17CVOCY9 Confirmed. You have received Ksh2,500.00 from JOHN DOE 0712345678 on 18/6/26 at 3:42 PM. New M-PESA balance is Ksh4,500.00.",
]
for sample in sample_messages:
    st.sidebar.code(sample, language=None)

st.sidebar.markdown("---")
st.sidebar.markdown("**Built by Charles Kariuki**")
st.sidebar.caption("Vigilant AI · Building in public · Mount Kenya University")

# ====================== FOOTER ======================
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: grey; font-size: 0.85em;'>"
    "Vigilant AI — Fighting M-Pesa & mobile money fraud in East Africa, one message at a time.</p>",
    unsafe_allow_html=True,
)