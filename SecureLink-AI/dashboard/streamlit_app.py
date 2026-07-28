"""
SecureLink AI — Streamlit Dashboard

Six panels:
  1. URL Analyzer    — Manual URL submission + live report
  2. Scan History    — Filterable scan table + risk distribution chart
  3. Model Stats     — Accuracy, confusion matrix, ROC-AUC, feature importance
  4. SHAP Summary    — Global SHAP beeswarm plot
  5. Feedback Review — Flagged-as-wrong predictions
  6. Drift Monitor   — Average daily risk score over time

Theme: black / dark-blue / neon-green cybersecurity aesthetic.

Run:
    streamlit run dashboard/streamlit_app.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import configure_logging, get_settings
from app.database import create_tables, get_all_feedback, get_all_scans, get_global_stats
from app.model import get_metadata, load_model, is_synthetic_model
from app.utils import is_valid_url

configure_logging()

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecureLink AI — Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS: Cybersecurity dark theme ──────────────────────────────────────
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');

    :root {
        --bg-primary:    #0a0e1a;
        --bg-secondary:  #0d1328;
        --bg-card:       #111827;
        --border-color:  #1e2d4a;
        --neon-green:    #00ff88;
        --neon-blue:     #00d4ff;
        --neon-red:      #ff4757;
        --neon-yellow:   #ffa502;
        --text-primary:  #e8eaf6;
        --text-muted:    #7c8aaa;
    }

    html, body, .stApp {
        background-color: var(--bg-primary) !important;
        font-family: 'Inter', sans-serif;
        color: var(--text-primary);
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: var(--bg-secondary) !important;
        border-right: 1px solid var(--border-color);
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 1rem;
    }
    [data-testid="stMetricValue"] {
        color: var(--neon-green) !important;
        font-family: 'JetBrains Mono', monospace;
        font-size: 2rem !important;
    }

    /* Input fields */
    .stTextInput > div > div > input {
        background-color: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        color: var(--text-primary) !important;
        font-family: 'JetBrains Mono', monospace;
        border-radius: 6px;
    }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #00ff88 0%, #00d4ff 100%);
        color: #0a0e1a;
        font-weight: 600;
        border: none;
        border-radius: 6px;
        padding: 0.5rem 1.5rem;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 20px rgba(0, 255, 136, 0.4);
    }

    /* Dataframes */
    .stDataFrame {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
    }

    /* Headers */
    h1, h2, h3 {
        color: var(--neon-green) !important;
        font-family: 'Inter', sans-serif;
    }

    /* Score badge */
    .score-safe      { color: #00ff88; font-weight: 700; }
    .score-moderate  { color: #ffa502; font-weight: 700; }
    .score-suspicious{ color: #ff8c00; font-weight: 700; }
    .score-dangerous { color: #ff4757; font-weight: 700; }
    .score-critical  { color: #ff0033; font-weight: 700; }

    /* Synthetic warning banner */
    .synthetic-banner {
        background: linear-gradient(135deg, #3d1a00, #5c2d00);
        border: 1px solid #ff8c00;
        border-radius: 8px;
        padding: 1rem 1.5rem;
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ── Initialize ────────────────────────────────────────────────────────────────
@st.cache_resource
def init_app():
    settings = get_settings()
    create_tables()
    load_model(settings.model_path)
    return settings


settings = init_app()


def score_color(score: int) -> str:
    if score <= 20:
        return "#00ff88"
    elif score <= 40:
        return "#ffa502"
    elif score <= 65:
        return "#ff8c00"
    elif score <= 80:
        return "#ff4757"
    return "#ff0033"


def score_emoji(score: int) -> str:
    if score <= 20:
        return "✅"
    elif score <= 40:
        return "🟡"
    elif score <= 65:
        return "🟠"
    elif score <= 80:
        return "🔴"
    return "🚨"


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔒 SecureLink AI")
    st.markdown("---")

    metadata = get_metadata()
    if metadata:
        version = metadata.get("version", "1.0.0")
        trained_at = metadata.get("trained_at", "Unknown")[:10]
        is_synth = metadata.get("is_synthetic", True)

        if is_synth:
            st.markdown(
                """<div class="synthetic-banner">
                ⚠️ <strong>Demo Model Active</strong><br>
                Trained on synthetic data. Not suitable for real threat detection.
                </div>""",
                unsafe_allow_html=True,
            )
        else:
            st.success(f"✅ Real model v{version}\nTrained: {trained_at}")
    else:
        st.warning("⚠️ No model loaded.\nRun: `python scripts/train_model.py`")

    st.markdown("---")
    st.markdown("**Navigation**")
    page = st.radio(
        "",
        [
            "🔍 URL Analyzer",
            "📋 Scan History",
            "📊 Model Statistics",
            "🧠 SHAP Summary",
            "👍 Feedback Review",
            "📈 Drift Monitor",
        ],
        label_visibility="collapsed",
    )

    st.markdown("---")
    stats = get_global_stats()
    st.metric("Total Scans", stats["total_scans"])
    st.metric("Avg Risk Score", f"{stats['avg_risk_score']}/100")
    st.metric("Dangerous URLs", stats["flagged_count"])


# ── Page: URL Analyzer ────────────────────────────────────────────────────────
if page == "🔍 URL Analyzer":
    st.title("🔍 URL Analyzer")
    st.markdown("Analyze any URL for phishing and malicious content.")

    col1, col2 = st.columns([4, 1])
    with col1:
        url_input = st.text_input(
            "Enter URL to analyze",
            placeholder="https://example.com",
            label_visibility="collapsed",
        )
    with col2:
        analyze_btn = st.button("🔒 Analyze", use_container_width=True)

    if analyze_btn and url_input:
        if not is_valid_url(url_input.strip()):
            st.error("❌ Invalid URL format. Please enter a valid http:// or https:// URL.")
        else:
            with st.spinner("Analyzing URL (fetching threat intel in parallel)..."):
                import asyncio

                async def _analyze():
                    from app.inference import analyze_url
                    return await analyze_url(url_input.strip(), user_id="dashboard")

                result = asyncio.run(_analyze())

            # ── Score gauge ───────────────────────────────────────────────────
            col_a, col_b, col_c, col_d = st.columns(4)
            col_a.metric("Risk Score", f"{result.risk_score}/100")
            col_b.metric("Verdict", result.prediction)
            col_c.metric("ML Confidence", f"{int(result.confidence * 100)}%")
            col_d.metric(
                "Threat Intel",
                "Active" if result.vt_available or result.sb_available else "Unavailable",
            )

            # ── Score bar ─────────────────────────────────────────────────────
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=result.risk_score,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": "Risk Score", "font": {"color": "#e8eaf6"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#7c8aaa"},
                    "bar": {"color": score_color(result.risk_score)},
                    "bgcolor": "#111827",
                    "steps": [
                        {"range": [0, 20], "color": "#001a0d"},
                        {"range": [20, 40], "color": "#1a1000"},
                        {"range": [40, 65], "color": "#1a0800"},
                        {"range": [65, 80], "color": "#1a0000"},
                        {"range": [80, 100], "color": "#200000"},
                    ],
                    "threshold": {
                        "line": {"color": "#ff4757", "width": 3},
                        "thickness": 0.75,
                        "value": 65,
                    },
                },
                number={"font": {"color": score_color(result.risk_score), "size": 48}},
            ))
            fig.update_layout(
                paper_bgcolor="#0a0e1a",
                font={"color": "#e8eaf6"},
                height=280,
                margin={"t": 40, "b": 20},
            )
            st.plotly_chart(fig, use_container_width=True)

            # ── Reasons ───────────────────────────────────────────────────────
            st.markdown("### 🚨 Risk Signals")
            if result.reasons:
                for reason in result.reasons:
                    st.markdown(f"**{reason}**")
            else:
                st.markdown("*No specific risk signals detected.*")

            # ── Recommendation ────────────────────────────────────────────────
            st.markdown("### 💡 Recommendation")
            st.info(result.recommendation_text)

            # ── API status ────────────────────────────────────────────────────
            with st.expander("🔧 API Status & Component Scores"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**ML Probability:** {result.ml_probability:.3f}")
                    st.write(f"**VT Detection Ratio:** {result.vt_detection_ratio:.3f}")
                    st.write(f"**Rule Score:** {result.rule_score:.3f}")
                    st.write(f"**Safe Browsing Flagged:** {result.sb_flagged}")
                with col2:
                    st.write(f"**VirusTotal:** {'✅' if result.vt_available else '❌'}")
                    st.write(f"**Safe Browsing:** {'✅' if result.sb_available else '❌'}")
                    st.write(f"**URLScan:** {'✅' if result.urlscan_available else '❌'}")


# ── Page: Scan History ────────────────────────────────────────────────────────
elif page == "📋 Scan History":
    st.title("📋 Scan History")

    scans = get_all_scans(limit=200)
    if not scans:
        st.info("No scans yet. Use the URL Analyzer or send a URL to the Telegram bot.")
    else:
        df = pd.DataFrame([
            {
                "ID": s.id,
                "URL": s.url[:60] + "..." if len(s.url) > 60 else s.url,
                "Verdict": s.prediction,
                "Risk Score": s.risk_score,
                "Confidence": f"{int(s.confidence * 100)}%",
                "User": s.user_id,
                "Timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M"),
            }
            for s in scans
        ])

        # ── Filters ───────────────────────────────────────────────────────────
        col1, col2 = st.columns(2)
        with col1:
            score_filter = st.slider("Min Risk Score", 0, 100, 0)
        with col2:
            verdict_options = ["All"] + sorted(df["Verdict"].unique().tolist())
            verdict_filter = st.selectbox("Filter by Verdict", verdict_options)

        filtered = df[df["Risk Score"] >= score_filter]
        if verdict_filter != "All":
            filtered = filtered[filtered["Verdict"] == verdict_filter]

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        # ── Risk distribution chart ───────────────────────────────────────────
        st.markdown("### Risk Distribution")
        col1, col2 = st.columns(2)

        with col1:
            verdict_counts = df["Verdict"].value_counts().reset_index()
            verdict_counts.columns = ["Verdict", "Count"]
            colors = {
                "Safe": "#00ff88",
                "Moderate Risk": "#ffa502",
                "Suspicious": "#ff8c00",
                "Dangerous": "#ff4757",
                "Critical": "#ff0033",
            }
            fig_pie = px.pie(
                verdict_counts,
                values="Count",
                names="Verdict",
                color="Verdict",
                color_discrete_map=colors,
                title="Verdicts Distribution",
            )
            fig_pie.update_layout(
                paper_bgcolor="#0a0e1a",
                plot_bgcolor="#0a0e1a",
                font={"color": "#e8eaf6"},
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with col2:
            fig_hist = px.histogram(
                df,
                x="Risk Score",
                nbins=20,
                title="Risk Score Distribution",
                color_discrete_sequence=["#00ff88"],
            )
            fig_hist.update_layout(
                paper_bgcolor="#0a0e1a",
                plot_bgcolor="#111827",
                font={"color": "#e8eaf6"},
                xaxis={"title": "Risk Score (0-100)"},
                yaxis={"title": "Count"},
            )
            st.plotly_chart(fig_hist, use_container_width=True)


# ── Page: Model Statistics ─────────────────────────────────────────────────────
elif page == "📊 Model Statistics":
    st.title("📊 Model Statistics")

    metadata = get_metadata()
    if not metadata:
        st.warning("No model metadata found. Run `python scripts/train_model.py` first.")
    else:
        is_synth = metadata.get("is_synthetic", True)
        if is_synth:
            st.error(
                "⚠️ **Synthetic model active** — metrics below are meaningless for real phishing detection. "
                "Download PhiUSIIL dataset from Kaggle and retrain."
            )

        metrics = metadata.get("metrics", {})

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Accuracy", f"{metrics.get('accuracy', 0) * 100:.1f}%")
        col2.metric("ROC-AUC", f"{metrics.get('roc_auc', 0):.3f}")
        col3.metric("F1 (Phishing)", f"{metrics.get('f1_phishing', 0):.3f}")
        col4.metric("Recall", f"{metrics.get('recall_phishing', 0) * 100:.1f}%")

        # ── Confusion matrix ──────────────────────────────────────────────────
        cm = metrics.get("confusion_matrix")
        if cm:
            st.markdown("### Confusion Matrix")
            cm_df = pd.DataFrame(
                cm,
                index=["Actual Legitimate", "Actual Phishing"],
                columns=["Pred Legitimate", "Pred Phishing"],
            )
            fig_cm = px.imshow(
                cm_df,
                text_auto=True,
                color_continuous_scale=["#0a0e1a", "#00ff88"],
                title="Confusion Matrix",
            )
            fig_cm.update_layout(
                paper_bgcolor="#0a0e1a",
                font={"color": "#e8eaf6"},
            )
            st.plotly_chart(fig_cm, use_container_width=True)

        # ── Model info ────────────────────────────────────────────────────────
        with st.expander("Model Details"):
            st.json(metadata)


# ── Page: SHAP Summary ────────────────────────────────────────────────────────
elif page == "🧠 SHAP Summary":
    st.title("🧠 SHAP Feature Importance")
    st.markdown(
        "SHAP (SHapley Additive exPlanations) quantifies how much each feature "
        "contributes to the model's predictions on average across all scans."
    )

    scans = get_all_scans(limit=100)
    if not scans:
        st.info("No scans yet — run some analyses first.")
    else:
        # Aggregate feature reasons from stored scans
        reason_counter: dict[str, int] = {}
        for scan in scans:
            try:
                reasons = json.loads(scan.shap_reasons)
                for reason in reasons:
                    # Normalize reason text to extract feature name
                    clean = reason.replace("• ", "").split("—")[0].strip()
                    reason_counter[clean] = reason_counter.get(clean, 0) + 1
            except Exception:
                continue

        if reason_counter:
            df_reasons = pd.DataFrame(
                sorted(reason_counter.items(), key=lambda x: x[1], reverse=True),
                columns=["Reason", "Frequency"],
            )

            fig = px.bar(
                df_reasons.head(15),
                x="Frequency",
                y="Reason",
                orientation="h",
                title="Top Risk Signals Across All Scans",
                color="Frequency",
                color_continuous_scale=["#003322", "#00ff88"],
            )
            fig.update_layout(
                paper_bgcolor="#0a0e1a",
                plot_bgcolor="#111827",
                font={"color": "#e8eaf6"},
                yaxis={"autorange": "reversed"},
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Not enough data for SHAP summary yet.")


# ── Page: Feedback Review ─────────────────────────────────────────────────────
elif page == "👍 Feedback Review":
    st.title("👍 Feedback Review")
    st.markdown("Predictions flagged as incorrect by users — useful for identifying model weaknesses.")

    feedback_rows = get_all_feedback()
    if not feedback_rows:
        st.info("No feedback received yet.")
    else:
        wrong = [f for f in feedback_rows if not f.was_correct]
        correct = [f for f in feedback_rows if f.was_correct]

        col1, col2 = st.columns(2)
        col1.metric("👎 Flagged as Wrong", len(wrong))
        col2.metric("👍 Confirmed Correct", len(correct))

        if wrong:
            st.markdown("### ⚠️ Potentially Misclassified Scans")
            wrong_df = pd.DataFrame([
                {
                    "Scan ID": f.scan_id,
                    "User": f.user_id,
                    "Flagged At": f.timestamp.strftime("%Y-%m-%d %H:%M"),
                }
                for f in wrong
            ])
            st.dataframe(wrong_df, use_container_width=True, hide_index=True)
            st.caption(
                "These scan IDs can be cross-referenced with the Scan History tab "
                "to identify patterns in misclassifications."
            )


# ── Page: Drift Monitor ───────────────────────────────────────────────────────
elif page == "📈 Drift Monitor":
    st.title("📈 Model Drift Monitor")
    st.markdown(
        "A sudden shift in average daily risk score can indicate the model is encountering "
        "a different distribution of URLs than it was trained on — a sign of concept drift."
    )

    scans = get_all_scans(limit=500)
    if len(scans) < 5:
        st.info("Need at least 5 scans to show the drift chart. Run some analyses first.")
    else:
        df = pd.DataFrame([
            {"date": s.timestamp.date(), "risk_score": s.risk_score}
            for s in scans
        ])
        daily = df.groupby("date")["risk_score"].agg(["mean", "count"]).reset_index()
        daily.columns = ["Date", "Avg Risk Score", "Scan Count"]

        fig = px.line(
            daily,
            x="Date",
            y="Avg Risk Score",
            title="Average Daily Risk Score",
            markers=True,
            color_discrete_sequence=["#00ff88"],
        )
        # Add reference line at 50
        fig.add_hline(
            y=50,
            line_dash="dash",
            line_color="#ff4757",
            annotation_text="Baseline (50)",
            annotation_position="right",
        )
        fig.update_layout(
            paper_bgcolor="#0a0e1a",
            plot_bgcolor="#111827",
            font={"color": "#e8eaf6"},
            xaxis={"title": "Date"},
            yaxis={"title": "Average Risk Score", "range": [0, 100]},
        )
        st.plotly_chart(fig, use_container_width=True)

        # ── Scan volume ───────────────────────────────────────────────────────
        fig2 = px.bar(
            daily,
            x="Date",
            y="Scan Count",
            title="Daily Scan Volume",
            color_discrete_sequence=["#00d4ff"],
        )
        fig2.update_layout(
            paper_bgcolor="#0a0e1a",
            plot_bgcolor="#111827",
            font={"color": "#e8eaf6"},
        )
        st.plotly_chart(fig2, use_container_width=True)

        st.caption(
            "📌 Sustained upward drift may indicate new phishing campaigns the model hasn't seen. "
            "Retrain on fresh data when drift persists for >3 days."
        )
