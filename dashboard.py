import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from datetime import datetime
from pathlib import Path

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Security Analytics Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* Dark security theme */
  [data-testid="stAppViewContainer"] {
    background-color: #0d1117;
    color: #e6edf3;
  }
  [data-testid="stSidebar"] {
    background-color: #161b22;
    border-right: 1px solid #30363d;
  }
  [data-testid="stSidebar"] * { color: #e6edf3 !important; }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px 16px;
  }
  [data-testid="metric-container"] label { color: #8b949e !important; font-size: 12px !important; }
  [data-testid="metric-container"] [data-testid="stMetricValue"] { color: #e6edf3 !important; font-size: 28px !important; }

  /* Alert badges */
  .badge-critical { background:#da3633; color:#fff; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; }
  .badge-high     { background:#d29922; color:#fff; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; }
  .badge-medium   { background:#388bfd; color:#fff; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; }
  .badge-low      { background:#3fb950; color:#fff; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; }

  /* Section headers */
  h1, h2, h3 { color: #e6edf3 !important; }
  .section-label {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.2px;
    color: #8b949e;
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  /* Table */
  [data-testid="stDataFrame"] { background: #161b22 !important; }
  .stDataFrame thead tr th { background: #21262d !important; color: #8b949e !important; }

  /* Divider */
  hr { border-color: #30363d; }
</style>
""", unsafe_allow_html=True)

# ── Color palettes (consistent) ───────────────────────────────────────────────
ALERT_COLORS = {"CRITICAL": "#da3633", "HIGH": "#d29922", "MEDIUM": "#388bfd", "LOW": "#3fb950"}
LABEL_COLORS = {
    "exfiltration_suspected": "#da3633",
    "compromised_account":    "#d29922",
    "privilege_abuse":        "#a371f7",
    "policy_violation":       "#388bfd",
    "normal":                 "#3fb950",
}
DEPT_PALETTE = px.colors.qualitative.Dark24

# ── Data loading ──────────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    base = Path("/mnt/user-data/uploads")
    events   = pd.read_csv(base / "event_alert_stream.csv", parse_dates=["event_time"])
    users    = pd.read_csv(base / "users.csv")
    assets   = pd.read_csv(base / "assets.csv")
    sample   = pd.read_csv(base / "sample_stream_events.csv", parse_dates=["event_time"])

    # Try loading jsonl for extra rows
    jsonl_path = base / "stream_events.jsonl"
    if jsonl_path.exists():
        rows = []
        with open(jsonl_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        stream_df = pd.DataFrame(rows)
        stream_df["event_time"] = pd.to_datetime(stream_df["event_time"])
    else:
        stream_df = pd.DataFrame()

    return events, users, assets, sample, stream_df

events, users, assets, sample, stream_df = load_data()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 Security Dashboard")
    st.markdown("---")

    st.markdown('<p class="section-label">Dataset</p>', unsafe_allow_html=True)
    dataset_choice = st.radio(
        "Sumber data",
        ["event_alert_stream", "sample_stream_events"],
        label_visibility="collapsed",
    )
    df_raw = events if dataset_choice == "event_alert_stream" else sample

    st.markdown("---")
    st.markdown('<p class="section-label">Filter</p>', unsafe_allow_html=True)

    depts = ["Semua"] + sorted(df_raw["dept"].unique().tolist())
    sel_dept = st.selectbox("Departemen", depts)

    alert_col = "alert_level" if "alert_level" in df_raw.columns else None
    if alert_col:
        levels = ["Semua"] + sorted(df_raw[alert_col].unique().tolist())
        sel_level = st.selectbox("Alert Level", levels)
    else:
        sel_level = "Semua"

    labels = ["Semua"] + sorted(df_raw["label"].unique().tolist())
    sel_label = st.selectbox("Label Insiden", labels)

    st.markdown("---")
    st.markdown('<p class="section-label">Info</p>', unsafe_allow_html=True)
    st.caption(f"**Events:** {len(df_raw):,}")
    st.caption(f"**Users:** {len(users):,}")
    st.caption(f"**Assets:** {len(assets):,}")

# ── Apply filters ─────────────────────────────────────────────────────────────
df = df_raw.copy()
if sel_dept != "Semua":
    df = df[df["dept"] == sel_dept]
if sel_level != "Semua" and alert_col:
    df = df[df[alert_col] == sel_level]
if sel_label != "Semua":
    df = df[df["label"] == sel_label]

# ── Title ─────────────────────────────────────────────────────────────────────
st.markdown("# Security Analytics Dashboard")
st.caption(f"Dataset: **{dataset_choice}** · {len(df):,} events ditampilkan · Terakhir diperbarui: {datetime.now().strftime('%d %b %Y %H:%M')}")
st.markdown("---")

# ── KPI Row ───────────────────────────────────────────────────────────────────
k1, k2, k3, k4, k5 = st.columns(5)

total_events = len(df)
anomaly_count = len(df[df["label"] != "normal"]) if "label" in df.columns else 0
high_risk = len(df[df["risk_score"] >= 70]) if "risk_score" in df.columns else 0
critical_count = len(df[df[alert_col] == "CRITICAL"]) if alert_col else 0
avg_risk = df["risk_score"].mean() if "risk_score" in df.columns else 0

k1.metric("Total Events", f"{total_events:,}")
k2.metric("Anomali Terdeteksi", f"{anomaly_count:,}")
k3.metric("High Risk (≥70)", f"{high_risk:,}")
k4.metric("CRITICAL Alerts", f"{critical_count:,}")
k5.metric("Avg Risk Score", f"{avg_risk:.1f}")

st.markdown("")

# ── Row 1: Label distribution + Alert level ───────────────────────────────────
col1, col2 = st.columns([1, 1])

with col1:
    st.markdown("#### Distribusi Label Insiden")
    label_counts = df["label"].value_counts().reset_index()
    label_counts.columns = ["label", "count"]
    fig = px.pie(
        label_counts, values="count", names="label",
        color="label", color_discrete_map=LABEL_COLORS,
        hole=0.55,
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf3", showlegend=True,
        legend=dict(font=dict(color="#8b949e")),
        margin=dict(t=10, b=10, l=10, r=10),
        height=300,
    )
    fig.update_traces(textinfo="percent+label", textfont_color="#e6edf3")
    st.plotly_chart(fig, use_container_width=True)

with col2:
    if alert_col:
        st.markdown("#### Alert Level Breakdown")
        al_counts = df[alert_col].value_counts().reindex(["CRITICAL","HIGH","MEDIUM","LOW"]).dropna().reset_index()
        al_counts.columns = ["level", "count"]
        fig2 = px.bar(
            al_counts, x="level", y="count", color="level",
            color_discrete_map=ALERT_COLORS, text="count",
        )
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e6edf3", showlegend=False,
            xaxis=dict(title="", color="#8b949e"),
            yaxis=dict(title="Jumlah", color="#8b949e", gridcolor="#21262d"),
            margin=dict(t=10, b=10, l=10, r=10),
            height=300,
        )
        fig2.update_traces(textposition="outside", textfont_color="#e6edf3")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.markdown("#### Risk Score Distribution")
        fig2 = px.histogram(
            df, x="risk_score", nbins=20,
            color_discrete_sequence=["#388bfd"],
        )
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e6edf3", showlegend=False,
            xaxis=dict(title="Risk Score", color="#8b949e"),
            yaxis=dict(title="Frekuensi", color="#8b949e", gridcolor="#21262d"),
            margin=dict(t=10, b=10, l=10, r=10),
            height=300,
        )
        st.plotly_chart(fig2, use_container_width=True)

# ── Row 2: Action + Dept ──────────────────────────────────────────────────────
col3, col4 = st.columns([1, 1])

with col3:
    st.markdown("#### Aktivitas per Aksi")
    action_counts = df["action"].value_counts().reset_index()
    action_counts.columns = ["action", "count"]
    fig3 = px.bar(
        action_counts.sort_values("count"), x="count", y="action",
        orientation="h", text="count",
        color="count", color_continuous_scale="Blues",
    )
    fig3.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf3", showlegend=False,
        coloraxis_showscale=False,
        xaxis=dict(title="Jumlah", color="#8b949e", gridcolor="#21262d"),
        yaxis=dict(title="", color="#8b949e"),
        margin=dict(t=10, b=10, l=10, r=10),
        height=320,
    )
    fig3.update_traces(textposition="outside", textfont_color="#e6edf3")
    st.plotly_chart(fig3, use_container_width=True)

with col4:
    st.markdown("#### Events per Departemen")
    dept_counts = df.groupby("dept").size().reset_index(name="count").sort_values("count", ascending=False)
    fig4 = px.bar(
        dept_counts, x="dept", y="count",
        text="count", color="dept",
        color_discrete_sequence=DEPT_PALETTE,
    )
    fig4.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf3", showlegend=False,
        xaxis=dict(title="", color="#8b949e", tickangle=-30),
        yaxis=dict(title="Jumlah", color="#8b949e", gridcolor="#21262d"),
        margin=dict(t=10, b=60, l=10, r=10),
        height=320,
    )
    fig4.update_traces(textposition="outside", textfont_color="#e6edf3")
    st.plotly_chart(fig4, use_container_width=True)

# ── Row 3: Risk scatter + bytes_out ──────────────────────────────────────────
st.markdown("---")
col5, col6 = st.columns([3, 2])

with col5:
    st.markdown("#### Risk Score vs Bytes Out (per Label)")
    fig5 = px.scatter(
        df, x="bytes_out", y="risk_score",
        color="label", color_discrete_map=LABEL_COLORS,
        hover_data=["user_id", "action", "asset_id"],
        opacity=0.7, size_max=10,
    )
    fig5.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf3",
        xaxis=dict(title="Bytes Out", color="#8b949e", gridcolor="#21262d"),
        yaxis=dict(title="Risk Score", color="#8b949e", gridcolor="#21262d"),
        legend=dict(font=dict(color="#8b949e")),
        margin=dict(t=10, b=10, l=10, r=10),
        height=340,
    )
    st.plotly_chart(fig5, use_container_width=True)

with col6:
    st.markdown("#### Top 10 User by Risk Score")
    user_risk = df.groupby("user_id")["risk_score"].mean().sort_values(ascending=False).head(10).reset_index()
    user_risk.columns = ["User", "Avg Risk"]
    user_risk["Avg Risk"] = user_risk["Avg Risk"].round(1)

    # Color rows by risk level
    def color_risk(val):
        if val >= 70: return "#da3633"
        elif val >= 50: return "#d29922"
        elif val >= 30: return "#388bfd"
        return "#3fb950"

    fig6 = px.bar(
        user_risk, x="Avg Risk", y="User", orientation="h",
        text="Avg Risk",
        color="Avg Risk", color_continuous_scale=["#3fb950","#388bfd","#d29922","#da3633"],
        range_color=[0, 100],
    )
    fig6.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf3", coloraxis_showscale=False,
        xaxis=dict(title="Avg Risk Score", color="#8b949e", gridcolor="#21262d"),
        yaxis=dict(title="", color="#8b949e", autorange="reversed"),
        margin=dict(t=10, b=10, l=10, r=10),
        height=340,
    )
    fig6.update_traces(textposition="outside", textfont_color="#e6edf3")
    st.plotly_chart(fig6, use_container_width=True)

# ── Row 4: Asset access + Clearance heatmap ──────────────────────────────────
st.markdown("---")
col7, col8 = st.columns([1, 1])

with col7:
    st.markdown("#### Akses per Asset")
    asset_count = df.groupby(["asset_id", "data_classification"]).size().reset_index(name="count")
    class_color = {"restricted": "#da3633", "confidential": "#d29922", "internal": "#388bfd", "public": "#3fb950"}
    fig7 = px.bar(
        asset_count, x="asset_id", y="count",
        color="data_classification", barmode="stack",
        color_discrete_map=class_color, text_auto=True,
    )
    fig7.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf3",
        xaxis=dict(title="", color="#8b949e"),
        yaxis=dict(title="Jumlah Akses", color="#8b949e", gridcolor="#21262d"),
        legend=dict(font=dict(color="#8b949e"), title_text="Klasifikasi"),
        margin=dict(t=10, b=10, l=10, r=10),
        height=320,
    )
    st.plotly_chart(fig7, use_container_width=True)

with col8:
    st.markdown("#### Heatmap: Dept × Aksi")
    heat_data = df.groupby(["dept", "action"]).size().unstack(fill_value=0)
    fig8 = px.imshow(
        heat_data,
        color_continuous_scale="Blues",
        aspect="auto",
        text_auto=True,
    )
    fig8.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf3",
        xaxis=dict(title="Aksi", color="#8b949e"),
        yaxis=dict(title="Dept", color="#8b949e"),
        coloraxis_showscale=False,
        margin=dict(t=10, b=10, l=10, r=10),
        height=320,
    )
    st.plotly_chart(fig8, use_container_width=True)

# ── Row 5: Timeline ───────────────────────────────────────────────────────────
if "event_time" in df.columns:
    st.markdown("---")
    st.markdown("#### Timeline Events")
    timeline = df.set_index("event_time").resample("5min").agg(
        total=("event_id", "count"),
        anomaly=("label", lambda x: (x != "normal").sum()),
    ).reset_index()

    fig9 = go.Figure()
    fig9.add_trace(go.Scatter(
        x=timeline["event_time"], y=timeline["total"],
        mode="lines", name="Total Events",
        line=dict(color="#388bfd", width=2),
        fill="tozeroy", fillcolor="rgba(56,139,253,0.1)",
    ))
    fig9.add_trace(go.Scatter(
        x=timeline["event_time"], y=timeline["anomaly"],
        mode="lines", name="Anomali",
        line=dict(color="#da3633", width=2),
        fill="tozeroy", fillcolor="rgba(218,54,51,0.15)",
    ))
    fig9.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf3",
        xaxis=dict(color="#8b949e", gridcolor="#21262d"),
        yaxis=dict(color="#8b949e", gridcolor="#21262d"),
        legend=dict(font=dict(color="#8b949e")),
        margin=dict(t=10, b=10, l=10, r=10),
        height=240,
    )
    st.plotly_chart(fig9, use_container_width=True)

# ── Raw data table ────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("#### Detail Event")
cols_show = ["event_id", "event_time", "user_id", "dept", "action",
             "asset_id", "data_classification", "risk_score", "label"]
if alert_col:
    cols_show.append(alert_col)
cols_show = [c for c in cols_show if c in df.columns]
st.dataframe(
    df[cols_show].sort_values("risk_score", ascending=False).head(50),
    use_container_width=True,
    height=300,
)

# ── Users & Assets tabs ───────────────────────────────────────────────────────
st.markdown("---")
tab1, tab2 = st.tabs(["👤 Data User", "🗄️ Data Asset"])

with tab1:
    st.dataframe(users, use_container_width=True, height=280)
    c1, c2 = st.columns(2)
    with c1:
        fig_u1 = px.pie(users, names="status", title="Status User",
                        color_discrete_sequence=["#3fb950","#da3633"])
        fig_u1.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e6edf3",
                              margin=dict(t=40, b=10), height=260)
        st.plotly_chart(fig_u1, use_container_width=True)
    with c2:
        fig_u2 = px.histogram(users, x="clearance", color="clearance",
                               color_discrete_map=class_color, title="Clearance Level")
        fig_u2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font_color="#e6edf3", showlegend=False,
                              xaxis=dict(color="#8b949e"), yaxis=dict(color="#8b949e", gridcolor="#21262d"),
                              margin=dict(t=40, b=10), height=260)
        st.plotly_chart(fig_u2, use_container_width=True)

with tab2:
    st.dataframe(assets, use_container_width=True, height=280)
    fig_a = px.bar(
        assets.groupby(["asset_type","data_classification"]).size().reset_index(name="count"),
        x="asset_type", y="count", color="data_classification",
        color_discrete_map=class_color, barmode="group",
        title="Asset Type by Classification",
    )
    fig_a.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#e6edf3",
                        xaxis=dict(color="#8b949e"), yaxis=dict(color="#8b949e", gridcolor="#21262d"),
                        legend=dict(font=dict(color="#8b949e")),
                        margin=dict(t=40, b=10), height=280)
    st.plotly_chart(fig_a, use_container_width=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.caption("UAS Praktik · Data Science · Universitas Bunda Mulia · 2026")