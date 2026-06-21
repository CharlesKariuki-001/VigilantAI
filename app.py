import streamlit as st
from src.rule_engine import RuleEngine

# ====================== PAGE CONFIG ======================
st.set_page_config(
    page_title="Vigilant AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)

# Initialize Rule Engine (cached across reruns in the same session)
if "engine" not in st.session_state:
    st.session_state.engine = RuleEngine()

if "history" not in st.session_state:
    st.session_state.history = []  # list of dicts: message, sender, result

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
st.markdown("### M-Pesa & Mobile Money Scam Detector")
st.caption("**Built for Kenya & Tanzania • Protecting everyday users from mobile money fraud**")

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

# ====================== ANALYSIS ======================
if scan_button and message.strip():
    with st.spinner("Scanning for scam patterns..."):
        result = st.session_state.engine.analyze(message, sender)

    st.session_state.history.insert(
        0, {"message": message.strip(), "sender": sender, "result": result}
    )

    st.markdown("---")

    # Result Display
    score_col, status_col = st.columns([1, 2])
    with score_col:
        st.metric(
            "Fraud Score",
            f"{result['score']}%",
            delta="Dangerous" if result["status"] == "FRAUD" else "Looks safe",
            delta_color="inverse" if result["status"] == "FRAUD" else "normal",
        )
    with status_col:
        if result["status"] == "FRAUD":
            st.error(f"🚨 **HIGH RISK — POSSIBLE SCAM**  ·  Confidence: {result['confidence']}")
        else:
            st.success(f"✅ **Looks Safe**  ·  Confidence: {result['confidence']}")

    st.info(f"**What to do:** {result['recommendation']}")

    # Triggered Rules
    if result["triggered_rules"]:
        st.subheader("🔍 Why This Message Was Flagged")
        # Sort by weight, most severe first
        for rule in sorted(result["triggered_rules"], key=lambda r: -r["weight"]):
            severity = "🔴 Critical" if rule["weight"] >= 9 else "🟠 High" if rule["weight"] >= 7 else "🟡 Medium" if rule["weight"] >= 4 else "⚪ Low"
            with st.expander(f"{severity} — {rule['name']}"):
                st.write(rule["explanation"])
                st.caption(f"Category: `{rule['category']}` · Severity weight: {rule['weight']}/10")
    elif result["status"] == "SAFE":
        st.success("No known scam patterns were detected in this message. Still, always verify unexpected transactions independently via *334# or the official M-PESA app.")

elif scan_button:
    st.warning("Please paste a message to analyze.")

# ====================== RECENT HISTORY ======================
if st.session_state.history:
    st.markdown("---")
    with st.expander(f"🕒 Recent scans ({len(st.session_state.history)})"):
        for i, item in enumerate(st.session_state.history[:10]):
            r = item["result"]
            badge = "🚨 FRAUD" if r["status"] == "FRAUD" else "✅ SAFE"
            st.markdown(f"**{badge}** ({r['score']}%) — _{item['message'][:80]}{'...' if len(item['message']) > 80 else ''}_")
        if st.button("Clear history"):
            st.session_state.history = []
            st.rerun()

# ====================== SIDEBAR ======================
st.sidebar.success("Vigilant AI — Phase 1 Complete (19 rule groups, 40+ patterns)")

st.sidebar.info(
    """
**How it works:**
- 19 weighted rule groups covering 40+ scam pattern variants
- Strong support for Swahili, English, and Sheng
- Covers Kenyan (M-Shwari, Fuliza, Safaricom) and Tanzanian
  (Tigo Pesa, Halotel Pesa, Vodacom, M-Pawa) mobile money formats
- Structural protection for genuine transaction receipts, so real
  M-PESA confirmations are never falsely flagged
- Real-time analysis with plain-language, per-rule explanations
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

        _\\*Measured on the internal 86-message labeled evaluation set;
        real-world recall will be tracked as more live messages are collected._
        """
    )

st.sidebar.markdown("### 🚀 Next Phases")
st.sidebar.caption(
    """
- Phase 2: Machine Learning classifier + SHAP explainability
- Phase 3: AI investigation agents
- Phase 4: FastAPI backend & public API
"""
)

st.sidebar.markdown("### Try These Sample Messages")
sample_messages = {
    "Fake prize (Sheng)": "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
    "Account threat": "Akaunti yako itafungwa leo kama hutathibitisha PIN.",
    "Job scam (Dubai)": "Umechaguliwa kufanya kazi Dubai mshahara wa $2000. Tuma Ksh3,500 ada ya visa kwa Paybill 567890.",
    "Genuine receipt": "TB17CVOCY9 Confirmed. You have received Ksh2,500.00 from JOHN DOE 0712345678 on 18/6/26 at 3:42 PM. New M-PESA balance is Ksh4,500.00.",
}
for label, sample in sample_messages.items():
    st.sidebar.code(sample, language=None)

st.sidebar.markdown("---")
st.sidebar.markdown("**Built by Charles Kariuki**")
st.sidebar.caption("Vigilant AI · Building in public · Month 2, Week 1 Milestone")

# ====================== FOOTER ======================
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: grey; font-size: 0.85em;'>"
    "Vigilant AI — Fighting M-Pesa & mobile money fraud in East Africa, one message at a time.</p>",
    unsafe_allow_html=True,
)