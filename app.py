import streamlit as st
from src.rule_engine import RuleEngine

# ====================== PAGE CONFIG ======================
st.set_page_config(
    page_title="Vigilant AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Initialize Rule Engine
if "engine" not in st.session_state:
    st.session_state.engine = RuleEngine()

# ====================== HEADER ======================
st.title("🛡️ Vigilant AI")
st.markdown("### M-Pesa Scam Detector")
st.caption("**Built for Kenya • Protecting everyday users from mobile money fraud**")

st.info("Paste any suspicious SMS (English or Swahili) below to get instant analysis.")

st.markdown("---")

# ====================== MAIN INPUT ======================
message = st.text_area(
    "📩 Paste SMS Message Here",
    height=180,
    placeholder="Umeshinda KSH 50,000! Tuma PIN yako uthibitishe...",
    help="Supports both English and Swahili messages"
)

col1, col2 = st.columns([3, 1])
with col1:
    sender = st.text_input(
        "Sender (optional)", 
        placeholder="0712345678 or M-PESA",
        help="Real M-Pesa usually comes from 'M-PESA' or 'Safaricom'"
    )
with col2:
    scan_button = st.button("🔍 Analyze Message", type="primary", use_container_width=True)

# ====================== ANALYSIS ======================
if scan_button and message.strip():
    with st.spinner("Scanning for scam patterns..."):
        result = st.session_state.engine.analyze(message, sender)

    st.markdown("---")

    # Result Display
    if result["status"] == "FRAUD":
        st.error("🚨 **HIGH RISK — POSSIBLE SCAM**")
        st.metric("Fraud Score", f"{result['score']}%", delta="Dangerous")
    else:
        st.success("✅ **Looks Safe**")
        st.metric("Fraud Score", f"{result['score']}%")

    st.info(f"**Recommendation:** {result['recommendation']}")

    # Triggered Rules
    if result["triggered_rules"]:
        st.subheader("🔍 Why This Message Was Flagged")
        for rule in result["triggered_rules"]:
            st.warning(f"**{rule['name']}**\n{rule['explanation']}")
    else:
        st.success("No scam patterns were detected in this message.")

elif scan_button:
    st.warning("Please paste a message to analyze.")

# ====================== SIDEBAR ======================
st.sidebar.success("Vigilant AI — Phase 1 Complete")

st.sidebar.info("""
**How it works:**
- 35+ rule-based detection patterns
- Strong support for Swahili + English
- Real-time analysis
""")

st.sidebar.markdown("### 🚀 Next Phases")
st.sidebar.caption("""
- Phase 2: Machine Learning + SHAP Explainability
- Phase 3: AI Investigation Agents
- Phase 4: FastAPI Backend & Public API
""")

st.sidebar.markdown("### Test These Messages")
st.sidebar.code("Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.")
st.sidebar.code("Akaunti yako itafungwa leo kama hutathibitisha")
st.sidebar.code("Hongera! You have won Ksh 200,000. Send Ksh 500.")
st.sidebar.code("TB17CVOCY9 Confirmed. You have received Ksh 2,500.")

st.sidebar.markdown("---")
st.sidebar.markdown("**Built by Charles Kariuki**")
st.sidebar.caption("Building in public • Week 4 Milestone")

# Footer
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: grey; font-size: 0.85em;'>"
    "Vigilant AI — Fighting M-Pesa fraud in Kenya, one message at a time.</p>",
    unsafe_allow_html=True
)