import streamlit as st
import traceback
from src.rule_engine import RuleEngine
from src.storage import save_community_report, save_feedback, count_pending_reports, count_feedback_entries

# ====================== ML + SHAP IMPORT WITH GRACEFUL FALLBACK ======================
ML_AVAILABLE = False
ML_IMPORT_ERROR = None
try:
    from src.predict import predict_with_explanation
    ML_AVAILABLE = True
except Exception as e:
    ML_IMPORT_ERROR = traceback.format_exc()

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
    st.session_state.history = []
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
    st.caption("**Rule Engine + XGBoost + SHAP Explainability**")
else:
    st.markdown("### AI-Powered M-Pesa Scam Detector")
    st.caption("**Built in Kenya, for East Africa • Protecting everyday users from mobile money fraud**")

st.info("Paste any suspicious SMS (English, Swahili, or Sheng) below to get instant analysis.")

st.markdown("---")

# ====================== MAIN INPUT ======================
message = st.text_area(
    "📩 Paste SMS Message Here",
    height=180,
    placeholder="Umeshinda KSH 50,000! Tuma PIN yako uthibitishe...",
    help="Supports English, Swahili, and mixed Sheng messages.",
)

col1, col2 = st.columns([3, 1])
with col1:
    sender = st.text_input(
        "Sender (optional)",
        placeholder="0712345678 or M-PESA",
        help="Real M-PESA usually comes from 'M-PESA' or 'Safaricom'",
    )
with col2:
    st.write("")
    st.write("")
    scan_button = st.button("🔍 Analyze Message", type="primary", use_container_width=True)

# ====================== ANALYSIS ======================
if scan_button and message.strip():
    spinner_text = "Analyzing with Rule Engine + ML + SHAP..." if ML_AVAILABLE else "Scanning for scam patterns..."
    with st.spinner(spinner_text):
        if ML_AVAILABLE:
            result = predict_with_explanation(message, sender)
        else:
            result = st.session_state.engine.analyze(message, sender)

    st.session_state.last_result = result
    st.session_state.last_message = message.strip()
    st.session_state.last_sender = sender
    st.session_state.feedback_submitted = False
    st.session_state.show_correction = False

    st.session_state.history.insert(
        0, {"message": message.strip()[:100] + ("..." if len(message) > 100 else ""), "sender": sender, "result": result}
    )

elif scan_button:
    st.warning("Please paste a message to analyze.")

# ====================== RESULT DISPLAY ======================
if st.session_state.last_result:
    result = st.session_state.last_result
    st.markdown("---")

    score_col, status_col = st.columns([1, 2])
    with score_col:
        score_label = "ML Fraud Probability" if ML_AVAILABLE else "Fraud Score"
        st.metric(
            score_label,
            f"{result.get('fraud_probability', result.get('score', 0))}%",
            delta="Dangerous" if result["status"] == "FRAUD" else "Looks safe",
            delta_color="inverse" if result["status"] == "FRAUD" else "normal",
        )
    with status_col:
        if result["status"] == "FRAUD":
            st.error(f"🚨 **HIGH RISK — POSSIBLE SCAM**  ·  Confidence: {result.get('confidence', 'HIGH')}")
        else:
            st.success(f"✅ **Looks Safe**  ·  Confidence: {result.get('confidence', 'HIGH')}")

    st.info(f"**What to do:** {result.get('recommendation', result.get('combined_recommendation', 'Be careful with unexpected transactions.'))}")

    # ====================== SHAP EXPLAINABILITY ======================
    if ML_AVAILABLE and result.get("top_shap_features"):
        st.subheader("🔬 Why the Model Thinks This (SHAP)")
        for item in result["top_shap_features"]:
            impact = item.get("impact", 0)
            direction = "🔺 Pushes toward FRAUD" if impact > 0 else "🔻 Pushes toward SAFE"
            st.write(f"**{item['feature']}** → {direction} (strength: {abs(impact):.3f})")

    # Rule Engine Triggers
    if result.get("triggered_rules"):
        st.subheader("📋 Rule Engine Triggers")
        for rule in sorted(result["triggered_rules"], key=lambda r: -r.get("weight", 0)):
            w = rule.get("weight", 0)
            severity = "🔴 Critical" if w >= 9 else "🟠 High" if w >= 7 else "🟡 Medium" if w >= 4 else "⚪ Low"
            with st.expander(f"{severity} — {rule['name']}"):
                st.write(rule["explanation"])
                if rule.get("category"):
                    st.caption(f"Category: `{rule['category']}` · Severity weight: {w}/10")

    # Feedback
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
            notes = st.text_input("Notes (optional)")
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

# ====================== REPORT A SCAM ======================
st.markdown("---")
with st.expander("📢 Report a new scam message we missed"):
    st.caption("Help us improve Vigilant AI by sharing scam messages you've received.")
    report_msg = st.text_area("Scam message", height=100, key="report_msg")
    report_sender = st.text_input("Sender (optional)", key="report_sender")
    if st.button("Submit Report"):
        if report_msg.strip():
            save_community_report(report_msg, report_sender)
            st.success("Thank you! Your report has been submitted.")
        else:
            st.warning("Please paste the message.")

# ====================== SIDEBAR ======================
if ML_AVAILABLE:
    st.sidebar.success("✅ ML + SHAP Active · Month 3")
else:
    st.sidebar.success("✅ Vigilant AI — Live · Rule Engine Mode")
    if ML_IMPORT_ERROR:
        with st.sidebar.expander("⚠️ ML Mode Debug"):
            st.code(ML_IMPORT_ERROR[-800:], language="text")  # Show last part of error

st.sidebar.metric("Pending Reports", count_pending_reports())
st.sidebar.metric("Feedback Logged", count_feedback_entries())

st.sidebar.markdown("### Try These Sample Messages")
for sample in [
    "Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
    "Nimetuma pesa kwa makosa, tafadhali rudisha kwa hii namba.",
    "TB17CVOCY9 Confirmed. You have received Ksh2,500 from JOHN DOE."
]:
    st.sidebar.code(sample)

st.sidebar.markdown("---")
st.sidebar.markdown("**Built by Charles Kariuki**")
st.sidebar.caption("Mount Kenya University • Building in Public")

# Footer
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: grey; font-size: 0.85em;'>"
    "Vigilant AI — Fighting M-Pesa fraud in Kenya, one message at a time.</p>",
    unsafe_allow_html=True,
)