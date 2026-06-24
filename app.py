"""
Vigilant AI — app.py  (Month 3, polished)
Design direction: terminal-precision meets Kenyan fintech.
Mono type, high-contrast status colours, no decorative gradients.
The UI gets out of the way so the verdict is the only thing you see.
"""

import traceback
import streamlit as st

from src.rule_engine import RuleEngine
from src.storage import (
    save_community_report,
    save_feedback,
    count_pending_reports,
    count_feedback_entries,
)

# ── ML layer (optional) ──────────────────────────────────────────────────────
ML_AVAILABLE = False
ML_IMPORT_ERROR = None
try:
    from src.predict import HybridDetector
    ML_AVAILABLE = True
except Exception:
    ML_IMPORT_ERROR = traceback.format_exc()

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Vigilant AI",
    page_icon="🛡",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Design system ────────────────────────────────────────────────────────────
# Palette: near-black canvas, single Kenyan-green accent, strict status red/green.
# Type: JetBrains Mono for labels/codes (precision feel), Inter for body.
# Signature: the VERDICT NUMBER is enormous — it IS the page, not a widget on it.
# No rounded-corner cards stacked inside other rounded-corner cards.
# No gradient on gradient. One gradient allowed: the top bar only.

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;700&display=swap');

/* ── Reset & base ── */
*, *::before, *::after { box-sizing: border-box; }

html, body, [data-testid="stAppViewContainer"],
[data-testid="stMain"], .main, .block-container {
    background-color: #0f1117 !important;
    color: #e8eaed !important;
    font-family: 'Inter', sans-serif;
}

/* hide default streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stToolbar"] { display: none; }
.block-container { padding: 0 !important; max-width: 720px !important; }

/* ── Top bar ── */
.va-topbar {
    background: linear-gradient(90deg, #0d3d1f 0%, #1a5c32 100%);
    padding: 14px 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #1f6b3a;
    margin-bottom: 0;
}
.va-wordmark {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.1rem;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.3px;
}
.va-wordmark span { color: #4ade80; }
.va-mode-pill {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    font-weight: 500;
    color: #4ade80;
    border: 1px solid #1f6b3a;
    border-radius: 4px;
    padding: 3px 10px;
    background: rgba(74,222,128,0.08);
}

/* ── Page body wrapper ── */
.va-body { padding: 32px 28px; }

/* ── Scan input area ── */
.va-input-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: #6b7280;
    margin-bottom: 8px;
}

/* Streamlit text_area override */
textarea {
    background: #161b22 !important;
    border: 1px solid #2d3748 !important;
    border-radius: 6px !important;
    color: #e8eaed !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.95rem !important;
    resize: vertical !important;
    transition: border-color 0.15s ease;
}
textarea:focus {
    border-color: #1a5c32 !important;
    box-shadow: 0 0 0 3px rgba(26,92,50,0.25) !important;
}
input[type="text"] {
    background: #161b22 !important;
    border: 1px solid #2d3748 !important;
    border-radius: 6px !important;
    color: #e8eaed !important;
    font-size: 0.88rem !important;
}
input[type="text"]:focus {
    border-color: #1a5c32 !important;
    box-shadow: 0 0 0 3px rgba(26,92,50,0.2) !important;
}

/* Primary button */
[data-testid="stButton"] > button[kind="primary"] {
    background: #16a34a !important;
    color: #fff !important;
    border: none !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.82rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.5px !important;
    text-transform: uppercase !important;
    padding: 10px 0 !important;
    transition: background 0.15s ease, transform 0.1s ease !important;
}
[data-testid="stButton"] > button[kind="primary"]:hover {
    background: #15803d !important;
    transform: translateY(-1px) !important;
}
[data-testid="stButton"] > button[kind="secondary"],
[data-testid="stButton"] > button:not([kind="primary"]) {
    background: #1c2333 !important;
    color: #e8eaed !important;
    border: 1px solid #2d3748 !important;
    border-radius: 6px !important;
    font-size: 0.85rem !important;
    font-family: 'Inter', sans-serif !important;
    padding: 8px 0 !important;
    transition: border-color 0.15s ease !important;
}
[data-testid="stButton"] > button:not([kind="primary"]):hover {
    border-color: #4b5563 !important;
    background: #222b3c !important;
}

/* ── THE VERDICT — the entire point of the page ── */
.verdict-block {
    margin: 32px 0 8px 0;
    padding: 28px 28px 24px 28px;
    border-radius: 8px;
    border-left: 5px solid;
    position: relative;
    overflow: hidden;
}
.verdict-fraud {
    background: #1a0a0a;
    border-color: #ef4444;
}
.verdict-safe {
    background: #0a1a0e;
    border-color: #22c55e;
}
.verdict-number {
    font-family: 'JetBrains Mono', monospace;
    font-size: 4.5rem;
    font-weight: 700;
    line-height: 1;
    letter-spacing: -2px;
    margin-bottom: 4px;
}
.verdict-number-fraud { color: #ef4444; }
.verdict-number-safe  { color: #22c55e; }
.verdict-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 2px;
    opacity: 0.55;
    margin-bottom: 10px;
}
.verdict-status {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 4px;
}
.verdict-status-fraud { color: #ef4444; }
.verdict-status-safe  { color: #22c55e; }
.verdict-confidence {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #6b7280;
    letter-spacing: 0.5px;
}
.verdict-decided-by {
    position: absolute;
    top: 20px;
    right: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #4b5563;
    text-transform: uppercase;
    letter-spacing: 1px;
    border: 1px solid #1f2937;
    border-radius: 4px;
    padding: 3px 8px;
}

/* ── Probability bar ── */
.prob-track {
    height: 4px;
    background: #1f2937;
    border-radius: 2px;
    margin: 16px 0 6px 0;
    overflow: hidden;
}
.prob-fill-fraud { height: 100%; background: #ef4444; border-radius: 2px; transition: width .5s ease; }
.prob-fill-safe  { height: 100%; background: #22c55e; border-radius: 2px; transition: width .5s ease; }

/* ── Layer row ── */
.layer-strip {
    display: grid;
    grid-template-columns: 1fr 1px 1fr 1px 1fr;
    gap: 0;
    background: #161b22;
    border: 1px solid #1f2937;
    border-radius: 6px;
    margin: 20px 0;
    overflow: hidden;
}
.layer-cell {
    padding: 14px 16px;
    text-align: center;
}
.layer-divider { background: #1f2937; }
.layer-eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: #4b5563;
    margin-bottom: 5px;
}
.layer-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.95rem;
    font-weight: 700;
}
.lv-fraud { color: #ef4444; }
.lv-safe  { color: #22c55e; }
.lv-na    { color: #374151; }
.layer-sub {
    font-size: 0.68rem;
    color: #4b5563;
    margin-top: 2px;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Recommendation ── */
.reco {
    border-radius: 6px;
    padding: 14px 16px;
    margin: 20px 0;
    font-size: 0.9rem;
    line-height: 1.6;
    color: #d1d5db;
}
.reco-fraud { background: #1a1200; border: 1px solid #92400e; }
.reco-safe  { background: #0a1a0e; border: 1px solid #166534; }
.reco strong { color: #f9fafb; }

/* ── Section header ── */
.section-head {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.8px;
    color: #4b5563;
    border-bottom: 1px solid #1f2937;
    padding-bottom: 8px;
    margin: 28px 0 14px 0;
}

/* ── SHAP items ── */
.shap-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid #1a2030;
}
.shap-row:last-child { border-bottom: none; }
.shap-dir {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    min-width: 44px;
    padding: 3px 6px;
    border-radius: 3px;
    text-align: center;
}
.shap-dir-fraud { background: #2d0a0a; color: #ef4444; }
.shap-dir-safe  { background: #0a1a0e; color: #22c55e; }
.shap-name { flex: 1; font-size: 0.88rem; color: #d1d5db; }
.shap-bar-track { width: 60px; height: 4px; background: #1f2937; border-radius: 2px; flex-shrink: 0; }
.shap-bar-fraud { height: 100%; background: #ef4444; border-radius: 2px; }
.shap-bar-safe  { height: 100%; background: #22c55e; border-radius: 2px; }
.shap-val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    color: #4b5563;
    min-width: 40px;
    text-align: right;
}

/* ── Rule items ── */
.rule-row {
    padding: 12px 0;
    border-bottom: 1px solid #1a2030;
}
.rule-row:last-child { border-bottom: none; }
.rule-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 4px;
}
.rule-sev {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    padding: 2px 7px;
    border-radius: 3px;
}
.sev-critical { background: #2d0a0a; color: #ef4444; }
.sev-high     { background: #1c0f00; color: #f97316; }
.sev-medium   { background: #1a1600; color: #eab308; }
.sev-low      { background: #111827; color: #6b7280; }
.rule-name-text { font-size: 0.9rem; font-weight: 600; color: #e8eaed; }
.rule-explanation { font-size: 0.83rem; color: #6b7280; line-height: 1.55; padding-left: 2px; }

/* ── Feedback buttons area ── */
.feedback-prompt {
    font-size: 0.85rem;
    color: #6b7280;
    margin-bottom: 10px;
}

/* ── History ── */
.hist-row {
    display: flex;
    align-items: baseline;
    gap: 12px;
    padding: 8px 0;
    border-bottom: 1px solid #1a2030;
    font-size: 0.83rem;
}
.hist-row:last-child { border-bottom: none; }
.hist-badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    min-width: 50px;
}
.hb-fraud { color: #ef4444; }
.hb-safe  { color: #22c55e; }
.hist-pct {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #374151;
    min-width: 34px;
}
.hist-msg { color: #6b7280; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #1f2937 !important;
}
[data-testid="stSidebar"] * { color: #d1d5db !important; }

/* ── Expander ── */
[data-testid="stExpander"] {
    background: #161b22 !important;
    border: 1px solid #1f2937 !important;
    border-radius: 6px !important;
}
[data-testid="stExpander"] summary {
    font-size: 0.85rem !important;
    color: #9ca3af !important;
}

/* ── Spinner ── */
[data-testid="stSpinner"] { color: #22c55e !important; }

/* ── Remove Streamlit's label above inputs ── */
[data-testid="stTextArea"] label,
[data-testid="stTextInput"] label { display: none !important; }

/* ── Metric override ── */
[data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #1f2937;
    border-radius: 6px;
    padding: 10px 14px;
}
[data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 1.3rem !important;
    color: #e8eaed !important;
}
[data-testid="stMetricLabel"] {
    font-size: 0.72rem !important;
    color: #6b7280 !important;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}

/* ── Toast-style notice ── */
.va-notice {
    background: #161b22;
    border: 1px solid #1f2937;
    border-radius: 6px;
    padding: 12px 14px;
    font-size: 0.85rem;
    color: #9ca3af;
    margin: 8px 0;
    line-height: 1.5;
}

/* ── Divider ── */
hr { border: none; border-top: 1px solid #1f2937 !important; margin: 28px 0 !important; }

/* ── No result state ── */
.va-empty {
    text-align: center;
    padding: 48px 0 32px 0;
    color: #374151;
}
.va-empty-icon { font-size: 3rem; margin-bottom: 12px; }
.va-empty-text {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    letter-spacing: 1px;
    text-transform: uppercase;
}
.va-empty-sub { font-size: 0.83rem; color: #374151; margin-top: 6px; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0f1117; }
::-webkit-scrollbar-thumb { background: #1f2937; border-radius: 3px; }

/* ── Radio buttons ── */
[data-testid="stRadio"] label { color: #d1d5db !important; font-size: 0.9rem !important; }

/* ── Alerts ── */
[data-testid="stAlert"] {
    background: #161b22 !important;
    border: 1px solid #1f2937 !important;
    color: #d1d5db !important;
    border-radius: 6px !important;
}
</style>
""", unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────────────────────────
def _init():
    defaults = {
        "engine": RuleEngine(),
        "history": [],
        "last_result": None,
        "last_message": "",
        "last_sender": "",
        "show_correction": False,
        "feedback_submitted": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init()


# ── Model loader ──────────────────────────────────────────────────────────────
@st.cache_resource
def _load_detector():
    return HybridDetector()


# ── Analysis ──────────────────────────────────────────────────────────────────
def run_analysis(msg: str, snd: str) -> dict:
    if ML_AVAILABLE:
        d = _load_detector()
        raw = d.predict(msg, snd or None)
        prob = raw["ml_model"]["fraud_probability"]            # 0.0–1.0 float
        pct = round(prob * 100, 1) if prob is not None else raw["rule_engine"]["score"]
        return {
            "status": raw["status"],
            "confidence": raw["confidence"],
            "decided_by": raw["decided_by"],
            "score_pct": pct,
            "rule_verdict": raw["rule_engine"]["status"],
            "rule_score": raw["rule_engine"]["score"],
            "triggered_rules": raw["rule_engine"]["triggered_rules"],
            "ml_probability": prob,
            "ml_explanation": raw["ml_model"]["explanation_text"],
            "top_factors": raw["ml_model"]["top_factors"],
            "recommendation": raw["recommendation"],
            "mode": "hybrid",
        }
    else:
        raw = st.session_state.engine.analyze(msg, snd or None)
        return {
            "status": raw["status"],
            "confidence": raw["confidence"],
            "decided_by": "rule_engine",
            "score_pct": raw["score"],
            "rule_verdict": raw["status"],
            "rule_score": raw["score"],
            "triggered_rules": raw["triggered_rules"],
            "ml_probability": None,
            "ml_explanation": None,
            "top_factors": [],
            "recommendation": raw["recommendation"],
            "mode": "rules_only",
        }


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
        <div style='padding:12px 0 20px 0'>
            <div style='font-family:JetBrains Mono,monospace;font-size:1rem;
                        font-weight:700;color:#fff;margin-bottom:2px'>
                🛡 VIGILANT AI
            </div>
            <div style='font-size:0.72rem;color:#4b5563;
                        font-family:JetBrains Mono,monospace;letter-spacing:1px'>
                FRAUD DETECTION · EAST AFRICA
            </div>
        </div>
    """, unsafe_allow_html=True)

    if ML_AVAILABLE:
        st.success("ML + SHAP active")
    else:
        st.warning("Rule engine only (ML not trained)")
        if ML_IMPORT_ERROR:
            with st.expander("Debug: why ML failed"):
                st.code(ML_IMPORT_ERROR[:800], language="text")

    st.markdown("---")

    pending = count_pending_reports()
    feedback_total = count_feedback_entries()
    c1, c2 = st.columns(2)
    c1.metric("Reports", pending)
    c2.metric("Feedback", feedback_total)

    st.markdown("---")

    st.markdown("""<div style='font-family:JetBrains Mono,monospace;font-size:0.68rem;
        font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#4b5563;
        margin-bottom:10px'>Detection layers</div>""", unsafe_allow_html=True)

    layers = [
        ("01", "Rule engine", "33 patterns across 21 scam categories.\nEnglish · Swahili · Sheng"),
        ("02", "XGBoost ML", "Catches scams the rules haven't seen.\nTrained on labeled M-Pesa messages."),
        ("03", "SHAP", "Plain-language explanation for every\nverdict. Not a black box."),
    ]
    for num, title, desc in layers:
        active = ML_AVAILABLE or num == "01"
        colour = "#22c55e" if active else "#374151"
        st.markdown(f"""
            <div style='display:flex;gap:12px;margin-bottom:14px;
                        opacity:{"1" if active else "0.4"}'>
                <div style='font-family:JetBrains Mono,monospace;font-size:0.75rem;
                            font-weight:700;color:{colour};min-width:22px;
                            padding-top:1px'>{num}</div>
                <div>
                    <div style='font-size:0.85rem;font-weight:600;
                                color:#e8eaed;margin-bottom:2px'>{title}</div>
                    <div style='font-size:0.75rem;color:#4b5563;
                                line-height:1.5;white-space:pre-line'>{desc}</div>
                </div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    with st.expander("Performance metrics"):
        st.markdown("""
| | Target | |
|---|---|---|
| Precision | >90% | ✅ |
| Recall | >85% | ✅ |
| FP Rate | <5% | ✅ |
| Latency | <200ms | ✅ 60ms |

*Measured on held-out test set.*
        """)

    st.markdown("---")

    st.markdown("""<div style='font-family:JetBrains Mono,monospace;font-size:0.68rem;
        font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#4b5563;
        margin-bottom:10px'>Try these</div>""", unsafe_allow_html=True)

    samples = [
        "🚨  Umeshinda KSH 50,000! Tuma PIN yako uthibitishe.",
        "🚨  Piga *334*7# sasa kupokea zawadi yako ya Ksh 5,000.",
        "🚨  KRA: Una refund ya Ksh 12,400. Tuma ID yako kupokea.",
        "✅  TB17CVOCY9 Confirmed. You have received Ksh2,500.00 from JOHN DOE.",
    ]
    for s in samples:
        st.code(s, language=None)

    st.markdown("---")
    st.markdown("""
        <div style='font-size:0.75rem;color:#374151;line-height:1.8'>
            Built by <strong style='color:#6b7280'>Charles Kariuki</strong><br>
            Mount Kenya University · Thika<br>
            2026 · Open-source
        </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN — top bar
# ══════════════════════════════════════════════════════════════════════════════
mode_label = "ML + SHAP" if ML_AVAILABLE else "Rule Engine"
st.markdown(f"""
<div class="va-topbar">
    <div class="va-wordmark">🛡 Vigilant<span>AI</span></div>
    <div class="va-mode-pill">{mode_label}</div>
</div>
""", unsafe_allow_html=True)

# ── body padding wrapper via st.container ─────────────────────────────────────
with st.container():
    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Input ─────────────────────────────────────────────────────────────────
    st.markdown("""<div class="va-input-label">Paste the suspicious message</div>""",
                unsafe_allow_html=True)

    message = st.text_area(
        "Message input",
        height=148,
        placeholder=(
            "Any SMS or WhatsApp message — M-Pesa alerts, prize notifications, "
            "loan offers, requests to send money...\n\n"
            "Works in English, Swahili, and Sheng."
        ),
        label_visibility="collapsed",
    )

    col_sender, col_btn = st.columns([3, 1])
    with col_sender:
        sender = st.text_input(
            "Sender",
            placeholder="Sender — optional (e.g. 0712345678 or M-PESA)",
            label_visibility="collapsed",
        )
    with col_btn:
        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
        scan_button = st.button("SCAN →", type="primary", use_container_width=True)

    # ── Run analysis ──────────────────────────────────────────────────────────
    if scan_button:
        if not message.strip():
            st.markdown("""<div class="va-notice">
                Paste a message above, then press SCAN.
            </div>""", unsafe_allow_html=True)
        else:
            with st.spinner("Analyzing…"):
                result = run_analysis(message.strip(), sender.strip())

            st.session_state.last_result = result
            st.session_state.last_message = message.strip()
            st.session_state.last_sender = sender.strip()
            st.session_state.feedback_submitted = False
            st.session_state.show_correction = False

            st.session_state.history.insert(0, {
                "message": message.strip()[:120],
                "sender": sender.strip(),
                "result": result,
            })
            st.session_state.history = st.session_state.history[:20]

    # ══════════════════════════════════════════════════════════════════════════
    # RESULT
    # ══════════════════════════════════════════════════════════════════════════
    if st.session_state.last_result:
        r = st.session_state.last_result
        is_fraud = r["status"] == "FRAUD"

        prob = r["ml_probability"]
        score_pct = r["score_pct"]
        bar_pct = min(max(score_pct, 2), 100)

        card_cls = "verdict-fraud" if is_fraud else "verdict-safe"
        num_cls  = "verdict-number-fraud" if is_fraud else "verdict-number-safe"
        sta_cls  = "verdict-status-fraud" if is_fraud else "verdict-status-safe"
        bar_cls  = "prob-fill-fraud" if is_fraud else "prob-fill-safe"
        status_text = "HIGH RISK — LIKELY SCAM" if is_fraud else "LOOKS SAFE"
        decided_label = r["decided_by"].replace("_", " ").upper()

        # ── VERDICT BLOCK ─────────────────────────────────────────────────────
        st.markdown(f"""
        <div class="verdict-block {card_cls}">
            <div class="verdict-decided-by">{decided_label}</div>
            <div class="verdict-label">FRAUD PROBABILITY</div>
            <div class="verdict-number {num_cls}">{score_pct:.0f}<span style='font-size:2rem;opacity:.5'>%</span></div>
            <div class="prob-track">
                <div class="{bar_cls}" style="width:{bar_pct:.0f}%"></div>
            </div>
            <div class="verdict-status {sta_cls}">{status_text}</div>
            <div class="verdict-confidence">
                CONFIDENCE: {r["confidence"]}
                &nbsp;·&nbsp;
                ENGINE: {"HYBRID (RULES + ML)" if r["mode"] == "hybrid" else "RULES ONLY"}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── LAYER STRIP (hybrid mode) ─────────────────────────────────────────
        if r["mode"] == "hybrid":
            rv = r["rule_verdict"]
            rp = r["ml_probability"]
            ml_flag = rp is not None and rp >= 0.5
            ml_text = f"{rp*100:.0f}%" if rp is not None else "—"
            rule_vc = "lv-fraud" if rv == "FRAUD" else "lv-safe"
            ml_vc = "lv-fraud" if ml_flag else ("lv-safe" if rp is not None else "lv-na")
            fin_vc = "lv-fraud" if is_fraud else "lv-safe"

            st.markdown(f"""
            <div class="layer-strip">
                <div class="layer-cell">
                    <div class="layer-eyebrow">Rule Engine</div>
                    <div class="layer-value {rule_vc}">{rv}</div>
                    <div class="layer-sub">score {r["rule_score"]}%</div>
                </div>
                <div class="layer-divider"></div>
                <div class="layer-cell">
                    <div class="layer-eyebrow">ML Model</div>
                    <div class="layer-value {ml_vc}">{ml_text}</div>
                    <div class="layer-sub">threshold 0.50</div>
                </div>
                <div class="layer-divider"></div>
                <div class="layer-cell">
                    <div class="layer-eyebrow">Final</div>
                    <div class="layer-value {fin_vc}">{r["status"]}</div>
                    <div class="layer-sub">{r["decided_by"].replace("_"," ")}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # ── RECOMMENDATION ────────────────────────────────────────────────────
        rec_text = r["recommendation"].lstrip("⚠️✅ ").strip()
        rec_cls = "reco-fraud" if is_fraud else "reco-safe"
        rec_icon = "⚠" if is_fraud else "✓"
        st.markdown(f"""
        <div class="reco {rec_cls}">
            <strong>{rec_icon} What to do:</strong> {rec_text}
        </div>
        """, unsafe_allow_html=True)

        # ── SHAP ──────────────────────────────────────────────────────────────
        top_factors = r.get("top_factors") or []
        if top_factors:
            st.markdown("""<div class="section-head">Why the model thinks this — SHAP</div>""",
                        unsafe_allow_html=True)
            if r.get("ml_explanation"):
                st.markdown(f"""<div style='font-size:0.85rem;color:#6b7280;
                    margin-bottom:12px;line-height:1.6'>{r["ml_explanation"]}</div>""",
                    unsafe_allow_html=True)

            shap_html = ""
            for f in top_factors:
                toward_fraud = f["direction"] == "toward fraud"
                dir_cls = "shap-dir-fraud" if toward_fraud else "shap-dir-safe"
                bar_inner = "shap-bar-fraud" if toward_fraud else "shap-bar-safe"
                dir_txt = "FRAUD" if toward_fraud else "SAFE"
                impact_pct = min(abs(f["impact"]) * 100, 100)
                name = (f["feature"]
                        .replace("Pattern match: ", "")
                        .replace("Word/phrase: '", "")
                        .rstrip("'"))
                shap_html += f"""
                <div class="shap-row">
                    <span class="shap-dir {dir_cls}">{dir_txt}</span>
                    <span class="shap-name">{name}</span>
                    <div class="shap-bar-track">
                        <div class="{bar_inner}" style="width:{impact_pct:.0f}%"></div>
                    </div>
                    <span class="shap-val">{f["impact"]:+.3f}</span>
                </div>"""
            st.markdown(f"<div>{shap_html}</div>", unsafe_allow_html=True)

        # ── RULE TRIGGERS ─────────────────────────────────────────────────────
        triggered = r.get("triggered_rules") or []
        if triggered:
            st.markdown(f"""<div class="section-head">
                Rule matches — {len(triggered)} pattern{"s" if len(triggered) != 1 else ""} fired
            </div>""", unsafe_allow_html=True)

            rules_html = ""
            for rule in triggered:
                w = rule.get("weight", 5)
                if w >= 9:
                    sev_cls, sev_txt = "sev-critical", "CRITICAL"
                elif w >= 7:
                    sev_cls, sev_txt = "sev-high", "HIGH"
                elif w >= 4:
                    sev_cls, sev_txt = "sev-medium", "MEDIUM"
                else:
                    sev_cls, sev_txt = "sev-low", "LOW"

                rules_html += f"""
                <div class="rule-row">
                    <div class="rule-header">
                        <span class="rule-sev {sev_cls}">{sev_txt}</span>
                        <span class="rule-name-text">{rule["name"]}</span>
                    </div>
                    <div class="rule-explanation">{rule["explanation"]}</div>
                </div>"""
            st.markdown(f"<div>{rules_html}</div>", unsafe_allow_html=True)

        elif r["status"] == "SAFE" and not top_factors:
            st.markdown("""<div class="va-notice">
                No known scam patterns detected. Still verify unexpected transactions
                independently via <strong>*334#</strong> or the official M-PESA app.
            </div>""", unsafe_allow_html=True)

        # ── FEEDBACK ──────────────────────────────────────────────────────────
        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown("""<div class="feedback-prompt">
            Was this verdict correct?
        </div>""", unsafe_allow_html=True)

        if st.session_state.feedback_submitted:
            st.markdown("""<div class="va-notice" style="border-color:#166534;color:#22c55e;">
                Feedback recorded — thank you.
            </div>""", unsafe_allow_html=True)
        else:
            fc1, fc2 = st.columns(2)
            with fc1:
                if st.button("✓ Correct", use_container_width=True, key="fb_yes"):
                    save_feedback(
                        st.session_state.last_message,
                        st.session_state.last_sender,
                        r["status"], r["status"],
                        r.get("triggered_rules", []),
                    )
                    st.session_state.feedback_submitted = True
                    st.rerun()
            with fc2:
                if st.button("✗ Wrong", use_container_width=True, key="fb_no"):
                    st.session_state.show_correction = True

            if st.session_state.show_correction:
                correct = st.radio(
                    "What should it have been?",
                    ["FRAUD", "SAFE"], horizontal=True, key="correction_radio",
                )
                notes = st.text_input(
                    "Note — which part was wrong? (optional)",
                    key="correction_notes",
                )
                if st.button("Submit", type="primary", key="submit_correction"):
                    save_feedback(
                        st.session_state.last_message,
                        st.session_state.last_sender,
                        r["status"], correct,
                        r.get("triggered_rules", []),
                        notes,
                    )
                    st.session_state.show_correction = False
                    st.session_state.feedback_submitted = True
                    st.rerun()

    else:
        # ── EMPTY STATE ───────────────────────────────────────────────────────
        st.markdown("""
        <div class="va-empty">
            <div class="va-empty-icon">🛡</div>
            <div class="va-empty-text">Ready to scan</div>
            <div class="va-empty-sub">
                Paste any M-Pesa SMS above and press SCAN.<br>
                Results appear here in under a second.
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── HISTORY ───────────────────────────────────────────────────────────────
    if st.session_state.history:
        st.markdown("<hr>", unsafe_allow_html=True)
        with st.expander(f"Scan history  ({len(st.session_state.history)})"):
            hist_html = ""
            for item in st.session_state.history[:10]:
                hr = item["result"]
                hf = hr["status"] == "FRAUD"
                bc = "hb-fraud" if hf else "hb-safe"
                bt = "FRAUD" if hf else "SAFE"
                hp = hr.get("ml_probability")
                pct_str = f"{hp*100:.0f}%" if hp is not None else f"{hr['rule_score']}%"
                preview = item["message"][:80] + ("…" if len(item["message"]) > 80 else "")
                hist_html += f"""
                <div class="hist-row">
                    <span class="hist-badge {bc}">{bt}</span>
                    <span class="hist-pct">{pct_str}</span>
                    <span class="hist-msg">{preview}</span>
                </div>"""
            st.markdown(f"<div>{hist_html}</div>", unsafe_allow_html=True)
            if st.button("Clear history", key="clear_hist"):
                st.session_state.history = []
                st.rerun()

    # ── COMMUNITY REPORT ──────────────────────────────────────────────────────
    st.markdown("<hr>", unsafe_allow_html=True)
    with st.expander("Report a scam we missed"):
        st.markdown("""<div style='font-size:0.83rem;color:#6b7280;
            margin-bottom:14px;line-height:1.6'>
            Every scam you report improves detection for all Kenyans. Reports are
            reviewed before being added to the training dataset.
        </div>""", unsafe_allow_html=True)
        report_msg = st.text_area(
            "Scam message",
            height=90,
            key="report_msg_input",
            placeholder="Paste the scam SMS here…",
            label_visibility="visible",
        )
        report_sender_input = st.text_input(
            "Sender (optional)",
            key="report_sender_input",
            placeholder="e.g. 0712345678",
            label_visibility="visible",
        )
        st.caption("Anonymous. Will be reviewed before training use.")
        if st.button("Submit report", type="primary", key="submit_report"):
            if report_msg.strip():
                save_community_report(
                    message_text=report_msg.strip(),
                    sender=report_sender_input.strip(),
                    user_believes_fraud=True,
                )
                st.markdown("""<div class="va-notice" style="border-color:#166534;color:#22c55e;">
                    Report submitted. Thank you.
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown("""<div class="va-notice">
                    Paste the scam message before submitting.
                </div>""", unsafe_allow_html=True)

    # ── FOOTER ────────────────────────────────────────────────────────────────
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("""
    <div style='text-align:center;padding-bottom:32px'>
        <div style='font-family:JetBrains Mono,monospace;font-size:0.68rem;
                    color:#374151;letter-spacing:1px;text-transform:uppercase;
                    margin-bottom:4px'>
            Vigilant AI · Charles Kariuki · Mount Kenya University 2026
        </div>
        <div style='font-size:0.75rem;color:#1f2937'>
            Open-source · Free for individuals · Protecting everyday Kenyans
        </div>
    </div>
    """, unsafe_allow_html=True)