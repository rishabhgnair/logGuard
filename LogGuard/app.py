"""
app.py – LogGuard Streamlit Dashboard

Navigation pages:
  1. Overview
  2. Log Analysis
  3. Security Alerts
  4. Event Monitoring
  5. Reports
  6. Settings
  7. About LogGuard
"""

import sys
import os
from pathlib import Path

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# ---------------------------------------------------------------------------
# Path setup – ensure imports work from any working directory
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from log_processor  import load_csv_from_path, load_csv_from_upload, \
                           filter_logs, get_summary_stats
from analyzer       import run_all_rules
from alert_manager  import build_alerts_df, alert_summary, filter_alerts, \
                           export_alerts_csv, generate_report_summary, \
                           save_alerts_to_file, save_logs_to_file
from config         import (APP_TITLE, APP_VERSION, APP_TAGLINE,
                            COLOURS, SEVERITY_LEVELS,
                            FAILED_LOGIN_THRESHOLD, FAILED_LOGIN_WINDOW_SECONDS,
                            MULTI_ACCOUNT_DISTINCT_USERS, EVENT_FREQUENCY_THRESHOLD)

# ---------------------------------------------------------------------------
# Streamlit page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title=f"{APP_TITLE} – {APP_TAGLINE}",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Inject custom CSS
# ---------------------------------------------------------------------------
css_path = BASE_DIR / "assets" / "style.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

# Extra inline CSS for Plotly chart backgrounds
st.markdown("""
<style>
.js-plotly-plot .plotly, .plot-container { background: transparent !important; }
div[data-testid="metric-container"] {
    background: #1E293B; border: 1px solid #334155;
    border-radius: 10px; padding: 16px;
}
div[data-testid="metric-container"] label { color: #94A3B8 !important; }
div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
    color: #38BDF8 !important; font-size: 1.8rem !important;
}
div[data-testid="stSidebarContent"] { padding-top: 1rem; }
.stTabs [data-baseweb="tab"] { color: #94A3B8; }
.stTabs [data-baseweb="tab"][aria-selected="true"] { color: #38BDF8; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session-state helpers
# ---------------------------------------------------------------------------
if "logs_df"    not in st.session_state: st.session_state.logs_df    = None
if "alerts_df"  not in st.session_state: st.session_state.alerts_df  = None
if "proc_result" not in st.session_state: st.session_state.proc_result = None
if "data_source" not in st.session_state: st.session_state.data_source = None

# Settings (live-editable on the Settings page)
if "cfg_fail_threshold"  not in st.session_state:
    st.session_state.cfg_fail_threshold  = FAILED_LOGIN_THRESHOLD
if "cfg_fail_window"     not in st.session_state:
    st.session_state.cfg_fail_window     = FAILED_LOGIN_WINDOW_SECONDS // 60
if "cfg_multi_users"     not in st.session_state:
    st.session_state.cfg_multi_users     = MULTI_ACCOUNT_DISTINCT_USERS
if "cfg_freq_threshold"  not in st.session_state:
    st.session_state.cfg_freq_threshold  = EVENT_FREQUENCY_THRESHOLD
if "cfg_enable_time"     not in st.session_state:
    st.session_state.cfg_enable_time     = True


def _load_and_analyse(result: dict):
    """Store a processed result into session state and run detectors."""
    if not result["success"]:
        st.error(f"⚠️ {result['error']}")
        return False
    df = result["df"]
    st.session_state.proc_result = result
    st.session_state.logs_df     = df

    # Run detection with current settings
    import config as _cfg
    _cfg.FAILED_LOGIN_THRESHOLD    = st.session_state.cfg_fail_threshold
    _cfg.FAILED_LOGIN_WINDOW_SECONDS = st.session_state.cfg_fail_window * 60
    _cfg.MULTI_ACCOUNT_DISTINCT_USERS = st.session_state.cfg_multi_users
    _cfg.EVENT_FREQUENCY_THRESHOLD    = st.session_state.cfg_freq_threshold
    _cfg.ENABLE_TIME_BASED_DETECTION  = st.session_state.cfg_enable_time

    raw_alerts = run_all_rules(df)
    st.session_state.alerts_df = build_alerts_df(raw_alerts)
    return True


# ---------------------------------------------------------------------------
# Plotly theme helper
# ---------------------------------------------------------------------------
PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor ="rgba(0,0,0,0)",
    font=dict(color="#E2E8F0", family="Inter, Segoe UI, sans-serif"),
    margin=dict(l=10, r=10, t=36, b=10),
    legend=dict(bgcolor="rgba(0,0,0,0)"),
)
SEV_COLOURS = {
    "HIGH"  : COLOURS["HIGH"],
    "MEDIUM": COLOURS["MEDIUM"],
    "LOW"   : COLOURS["LOW"],
    "INFO"  : COLOURS["INFO"],
}


def _empty_state(icon="📂", title="No data loaded",
                 sub="Load the sample dataset or upload a CSV file from the Log Analysis page."):
    st.markdown(f"""
    <div class="empty-state">
      <div class="icon">{icon}</div>
      <h3>{title}</h3>
      <p>{sub}</p>
    </div>""", unsafe_allow_html=True)


# ===========================================================================
# SIDEBAR NAVIGATION
# ===========================================================================
with st.sidebar:
    st.markdown(f"""
    <div style="text-align:center;padding:16px 0 24px 0;">
      <div style="font-size:2.2rem;">🛡️</div>
      <div style="font-size:1.3rem;font-weight:700;color:#38BDF8;letter-spacing:0.04em;">
        {APP_TITLE}
      </div>
      <div style="font-size:0.68rem;color:#64748B;letter-spacing:0.08em;text-transform:uppercase;margin-top:4px;">
        v{APP_VERSION} · SOC Dashboard
      </div>
    </div>
    """, unsafe_allow_html=True)

    page = st.selectbox(
        "Navigate",
        ["🏠  Overview", "📋  Log Analysis", "🚨  Security Alerts",
         "📡  Event Monitoring", "📄  Reports", "⚙️  Settings", "ℹ️  About"],
        label_visibility="collapsed",
    )
    page_key = page.split()[-1]   # e.g. "Overview", "Analysis", …

    st.markdown("---")
    # Quick data-load shortcut in sidebar
    st.caption("Quick Load")
    if st.button("📂  Load Sample Dataset", use_container_width=True):
        with st.spinner("Loading sample data…"):
            result = load_csv_from_path(BASE_DIR / "data" / "sample_logs.csv")
            if _load_and_analyse(result):
                st.session_state.data_source = "Sample Dataset"
                st.success(f"✅ Loaded {len(st.session_state.logs_df)} records")

    st.markdown("---")
    # Status indicator
    if st.session_state.logs_df is not None:
        df = st.session_state.logs_df
        st.markdown(f"""
        <div style="font-size:0.75rem;color:#94A3B8;">
          <b style="color:#22C55E;">● ACTIVE</b> &nbsp;|&nbsp; {len(df)} records<br/>
          Source: {st.session_state.data_source or 'Unknown'}
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown('<div style="font-size:0.75rem;color:#94A3B8;">● No data loaded</div>',
                    unsafe_allow_html=True)


# ===========================================================================
# PAGE 1 – OVERVIEW
# ===========================================================================
def page_overview():
    st.markdown("## 🏠 Overview Dashboard")
    st.caption("Real-time summary of system log activity and security alerts.")

    logs_df   = st.session_state.logs_df
    alerts_df = st.session_state.alerts_df

    if logs_df is None or logs_df.empty:
        _empty_state()
        return

    stats    = get_summary_stats(logs_df)
    al_stats = alert_summary(alerts_df) if alerts_df is not None else {}

    # ── KPI Row ──────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("📊 Total Logs",        stats.get("total_logs", 0))
    c2.metric("✅ Successful Logins", stats.get("successful_logins", 0))
    c3.metric("❌ Failed Logins",     stats.get("failed_logins", 0))
    c4.metric("🚨 Total Alerts",      al_stats.get("total", 0))
    c5.metric("🔴 High Severity",     al_stats.get("HIGH", 0))
    c6.metric("⚠️ System Errors",     stats.get("system_errors", 0))

    st.markdown("<br/>", unsafe_allow_html=True)

    # ── Charts Row 1 ─────────────────────────────────────────────────────
    col_a, col_b = st.columns([2, 1])

    with col_a:
        # Login activity over time (hourly)
        login_df = logs_df[
            logs_df["event_type"].str.contains("login|auth|ssh",
                                               case=False, na=False)
        ].copy()
        if not login_df.empty:
            login_df["hour"] = login_df["timestamp"].dt.floor("h")
            timeline = (login_df.groupby(["hour", "status"])
                        .size().reset_index(name="count"))
            colour_map = {"success": COLOURS["INFO"], "failed": COLOURS["HIGH"],
                          "error": COLOURS["MEDIUM"]}
            fig = px.line(timeline, x="hour", y="count", color="status",
                          title="Login Activity Over Time",
                          color_discrete_map=colour_map,
                          markers=True)
            fig.update_layout(**PLOT_LAYOUT)
            fig.update_xaxes(gridcolor="#1E293B", showgrid=True)
            fig.update_yaxes(gridcolor="#1E293B", showgrid=True)
            st.plotly_chart(fig, use_container_width=True)

    with col_b:
        # Successful vs Failed donut
        s = stats.get("successful_logins", 0)
        f = stats.get("failed_logins", 0)
        if s + f > 0:
            fig2 = go.Figure(go.Pie(
                labels=["Successful", "Failed"],
                values=[s, f],
                hole=0.6,
                marker_colors=[COLOURS["INFO"], COLOURS["HIGH"]],
                textinfo="label+percent",
            ))
            fig2.update_layout(title="Login Outcomes", **PLOT_LAYOUT)
            st.plotly_chart(fig2, use_container_width=True)

    # ── Charts Row 2 ─────────────────────────────────────────────────────
    col_c, col_d = st.columns([1, 1])

    with col_c:
        # Event type distribution bar
        ec = stats.get("event_type_counts", {})
        if ec:
            etdf = pd.DataFrame(list(ec.items()),
                                columns=["Event Type", "Count"])
            etdf = etdf.sort_values("Count", ascending=False)
            fig3 = px.bar(etdf, x="Event Type", y="Count",
                          title="Event Distribution",
                          color="Count",
                          color_continuous_scale=["#1E3A5F", "#38BDF8"])
            fig3.update_layout(**PLOT_LAYOUT)
            fig3.update_xaxes(tickangle=-30, gridcolor="#1E293B")
            fig3.update_yaxes(gridcolor="#1E293B")
            st.plotly_chart(fig3, use_container_width=True)

    with col_d:
        # Alerts by severity donut
        if alerts_df is not None and not alerts_df.empty:
            sev_counts = alerts_df["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            fig4 = go.Figure(go.Pie(
                labels=sev_counts["Severity"],
                values=sev_counts["Count"],
                hole=0.55,
                marker_colors=[SEV_COLOURS.get(s, "#888")
                               for s in sev_counts["Severity"]],
                textinfo="label+value",
            ))
            fig4.update_layout(title="Alerts by Severity", **PLOT_LAYOUT)
            st.plotly_chart(fig4, use_container_width=True)
        else:
            st.info("No alerts to display.")

    # ── Recent Security Events table ──────────────────────────────────────
    st.markdown("### 🕐 Recent Security Events")
    if alerts_df is not None and not alerts_df.empty:
        recent = alerts_df.sort_values("timestamp", ascending=False).head(10)
        for _, row in recent.iterrows():
            sev   = row["severity"]
            color = SEV_COLOURS.get(sev, "#888")
            st.markdown(f"""
            <div style="
              background:#1E293B;border-left:4px solid {color};
              border-radius:0 8px 8px 0;padding:10px 16px;margin-bottom:8px;
              display:flex;align-items:center;gap:16px;
            ">
              <span class="badge badge-{sev}">{sev}</span>
              <span style="color:#94A3B8;font-size:0.8rem;min-width:160px;">
                {str(row["timestamp"])[:19]}
              </span>
              <span style="color:#38BDF8;font-weight:600;min-width:100px;">
                {row["username"]}
              </span>
              <span style="color:#E2E8F0;font-size:0.85rem;">{row["description"][:100]}…</span>
            </div>""", unsafe_allow_html=True)
    else:
        st.info("No security events detected.")


# ===========================================================================
# PAGE 2 – LOG ANALYSIS
# ===========================================================================
def page_log_analysis():
    st.markdown("## 📋 Log Analysis")
    st.caption("Upload a CSV log file or load the included sample dataset for analysis.")

    # ── Data source ───────────────────────────────────────────────────────
    tab_upload, tab_sample = st.tabs(["📤 Upload CSV", "📂 Sample Dataset"])

    with tab_upload:
        uploaded = st.file_uploader(
            "Choose a CSV log file",
            type=["csv"],
            help="Required columns: timestamp, host, event_type, username, status, message",
        )
        if uploaded:
            with st.spinner("Processing uploaded file…"):
                result = load_csv_from_upload(uploaded)
                if _load_and_analyse(result):
                    st.session_state.data_source = f"Upload: {uploaded.name}"
                    st.success(f"✅ Loaded {len(st.session_state.logs_df)} clean records "
                               f"from **{uploaded.name}**")

    with tab_sample:
        st.info("The sample dataset contains 143 synthetic log records designed to trigger "
                "each detection rule.  All data is fictional.")
        if st.button("Load Sample Dataset", key="load_sample_analysis"):
            with st.spinner("Loading sample data…"):
                result = load_csv_from_path(BASE_DIR / "data" / "sample_logs.csv")
                if _load_and_analyse(result):
                    st.session_state.data_source = "Sample Dataset"
                    st.success("✅ Sample dataset loaded.")

    if st.session_state.proc_result is None:
        _empty_state(icon="📋", title="No data loaded yet",
                     sub="Upload a CSV file or load the sample dataset above.")
        return

    result  = st.session_state.proc_result
    df      = st.session_state.logs_df
    summary = result["summary"]

    # ── Processing summary ────────────────────────────────────────────────
    st.markdown("### 📊 Processing Summary")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Rows",     summary["total_rows"])
    m2.metric("Clean Records",  summary["clean_rows"])
    m3.metric("Rejected Rows",  summary["rejected_rows"])
    m4.metric("Invalid Timestamps", summary["invalid_timestamps"])

    with st.expander("Dataset Details"):
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Columns:**", summary.get("columns", []))
            st.write("**Time range:**",
                     f"{summary.get('time_range_start', 'N/A')} → "
                     f"{summary.get('time_range_end', 'N/A')}")
        with col2:
            st.write("**Unique users:**", summary.get("unique_users", 0))
            st.write("**Unique hosts:**", summary.get("unique_hosts", 0))
            st.write("**Event types:**", summary.get("event_types", []))

        if not result["rejected"].empty:
            st.warning(f"⚠️ {len(result['rejected'])} rows were rejected during "
                       f"preprocessing (invalid timestamps or missing required fields).")
            with st.expander("View rejected rows"):
                st.dataframe(result["rejected"], use_container_width=True)

    # ── Filters ───────────────────────────────────────────────────────────
    st.markdown("### 🔍 Filter Logs")
    fc1, fc2, fc3 = st.columns(3)

    all_users  = sorted(df["username"].dropna().unique().tolist())
    all_etypes = sorted(df["event_type"].dropna().unique().tolist())
    all_status = sorted(df["status"].dropna().unique().tolist())

    sel_users  = fc1.multiselect("Username",   all_users,  placeholder="All users")
    sel_etypes = fc2.multiselect("Event Type", all_etypes, placeholder="All types")
    sel_status = fc3.multiselect("Status",     all_status, placeholder="All statuses")

    fd1, fd2 = st.columns(2)
    min_date = df["timestamp"].min().date()
    max_date = df["timestamp"].max().date()
    date_start = fd1.date_input("From", value=min_date,
                                min_value=min_date, max_value=max_date)
    date_end   = fd2.date_input("To",   value=max_date,
                                min_value=min_date, max_value=max_date)

    filtered = filter_logs(
        df,
        usernames   = sel_users   or None,
        event_types = sel_etypes  or None,
        statuses    = sel_status  or None,
        date_start  = date_start,
        date_end    = date_end,
    )

    st.markdown(f"**Showing {len(filtered)} of {len(df)} records**")
    st.dataframe(filtered, use_container_width=True, height=400)

    # Download filtered logs
    csv_bytes = filtered.to_csv(index=False).encode()
    st.download_button("⬇️  Download Filtered Logs (CSV)",
                       data=csv_bytes, file_name="filtered_logs.csv",
                       mime="text/csv")


# ===========================================================================
# PAGE 3 – SECURITY ALERTS
# ===========================================================================
def page_security_alerts():
    st.markdown("## 🚨 Security Alerts")
    st.caption("Detected anomalies and suspicious patterns. Each alert indicates "
               "something that warrants investigation — not proof of an attack.")

    if st.session_state.alerts_df is None:
        _empty_state(icon="🚨", title="No alerts yet",
                     sub="Load a dataset from the Log Analysis page to run detection.")
        return

    alerts_df = st.session_state.alerts_df

    if alerts_df.empty:
        st.success("✅ No suspicious activity detected in the loaded dataset.")
        return

    # ── Summary badges ────────────────────────────────────────────────────
    al = alert_summary(alerts_df)
    bc = st.columns(5)
    bc[0].metric("Total Alerts", al["total"])
    bc[1].metric("🔴 HIGH",      al.get("HIGH",   0))
    bc[2].metric("🟠 MEDIUM",    al.get("MEDIUM", 0))
    bc[3].metric("🟡 LOW",       al.get("LOW",    0))
    bc[4].metric("🟢 INFO",      al.get("INFO",   0))

    # ── Filters ───────────────────────────────────────────────────────────
    st.markdown("### 🔍 Filter Alerts")
    af1, af2, af3 = st.columns(3)
    sel_sev   = af1.multiselect("Severity",   SEVERITY_LEVELS[::-1], placeholder="All")
    sel_etype = af2.multiselect("Event Type",
                                sorted(alerts_df["event_type"].dropna().unique()),
                                placeholder="All")
    sel_usr   = af3.text_input("Username contains", placeholder="e.g. admin")

    afd1, afd2 = st.columns(2)
    ts_min = alerts_df["timestamp"].min()
    ts_max = alerts_df["timestamp"].max()
    if pd.isna(ts_min): ts_min = pd.Timestamp.now()
    if pd.isna(ts_max): ts_max = pd.Timestamp.now()

    ad_start = afd1.date_input("From", value=ts_min.date(), key="al_start")
    ad_end   = afd2.date_input("To",   value=ts_max.date(), key="al_end")

    sel_status = st.multiselect("Alert Status",
                                ["New", "Investigating", "Resolved"],
                                default=["New", "Investigating"],
                                placeholder="All statuses")

    filtered_alerts = filter_alerts(
        alerts_df,
        severities  = sel_sev    or None,
        event_types = sel_etype  or None,
        usernames   = [sel_usr]  if sel_usr else None,
        date_start  = ad_start,
        date_end    = ad_end,
        statuses    = sel_status or None,
    )

    st.markdown(f"**Showing {len(filtered_alerts)} alert(s)**")

    # ── Alert cards ───────────────────────────────────────────────────────
    for _, row in filtered_alerts.iterrows():
        sev   = row["severity"]
        color = SEV_COLOURS.get(sev, "#888")
        with st.expander(
            f"[{sev}] {row['alert_id']} | {str(row['timestamp'])[:19]} | "
            f"{row['username']} | {row['detection_rule']}"
        ):
            c1, c2, c3, c4 = st.columns(4)
            c1.markdown(f"**Alert ID:** `{row['alert_id']}`")
            c2.markdown(f"**Host:** `{row['host']}`")
            c3.markdown(f"**Occurrences:** {row['occurrences']}")
            c4.markdown(f"**Window:** {row['time_window_s']}s")
            st.markdown(f"**Description:** {row['description']}")
            st.markdown(f"**Detection Rule:** `{row['detection_rule']}`")
            st.markdown(
                f'<span class="badge badge-{sev}">{sev}</span>',
                unsafe_allow_html=True
            )

    # ── Export ────────────────────────────────────────────────────────────
    csv_bytes = export_alerts_csv(filtered_alerts)
    st.download_button("⬇️  Export Alerts CSV",
                       data=csv_bytes,
                       file_name="logguard_alerts.csv",
                       mime="text/csv")


# ===========================================================================
# PAGE 4 – EVENT MONITORING
# ===========================================================================
def page_event_monitoring():
    st.markdown("## 📡 Event Monitoring")
    st.caption("Visual breakdown of system events, users, and hosts.")

    df = st.session_state.logs_df
    if df is None or df.empty:
        _empty_state(icon="📡")
        return

    # ── Event timeline heatmap ────────────────────────────────────────────
    tmp = df.copy()
    tmp["hour"] = tmp["timestamp"].dt.floor("h")
    tmp["day"]  = tmp["timestamp"].dt.date.astype(str)

    hourly_counts = (tmp.groupby(["hour", "event_type"])
                     .size().reset_index(name="count"))

    fig = px.bar(hourly_counts, x="hour", y="count", color="event_type",
                 title="Event Activity Over Time (Hourly)",
                 barmode="stack")
    fig.update_layout(**PLOT_LAYOUT)
    fig.update_xaxes(gridcolor="#1E293B")
    fig.update_yaxes(gridcolor="#1E293B")
    st.plotly_chart(fig, use_container_width=True)

    col1, col2 = st.columns(2)

    with col1:
        # Top users by activity
        user_counts = df.groupby("username").size().reset_index(name="count")
        user_counts = user_counts.sort_values("count", ascending=True).tail(10)
        fig2 = px.bar(user_counts, x="count", y="username",
                      orientation="h",
                      title="Top 10 Users by Event Count",
                      color="count",
                      color_continuous_scale=["#1E3A5F","#38BDF8"])
        fig2.update_layout(**PLOT_LAYOUT)
        st.plotly_chart(fig2, use_container_width=True)

    with col2:
        # Top hosts by activity
        host_counts = df.groupby("host").size().reset_index(name="count")
        host_counts = host_counts.sort_values("count", ascending=True)
        fig3 = px.bar(host_counts, x="count", y="host",
                      orientation="h",
                      title="Events per Host",
                      color="count",
                      color_continuous_scale=["#1E3A5F","#38BDF8"])
        fig3.update_layout(**PLOT_LAYOUT)
        st.plotly_chart(fig3, use_container_width=True)

    # ── Status breakdown ──────────────────────────────────────────────────
    col3, col4 = st.columns(2)
    with col3:
        sc = df["status"].value_counts().reset_index()
        sc.columns = ["Status", "Count"]
        sc_colours = {
            "success": COLOURS["INFO"],
            "failed" : COLOURS["HIGH"],
            "error"  : COLOURS["MEDIUM"],
        }
        fig4 = px.bar(sc, x="Status", y="Count",
                      title="Events by Status",
                      color="Status",
                      color_discrete_map=sc_colours)
        fig4.update_layout(**PLOT_LAYOUT)
        st.plotly_chart(fig4, use_container_width=True)

    with col4:
        # Failed logins per user
        failed = df[df["status"] == "failed"].groupby("username").size() \
                   .reset_index(name="failures")
        failed = failed.sort_values("failures", ascending=False).head(10)
        fig5 = px.bar(failed, x="username", y="failures",
                      title="Top Users by Failure Count",
                      color="failures",
                      color_continuous_scale=["#2D1C1C","#EF4444"])
        fig5.update_layout(**PLOT_LAYOUT)
        fig5.update_xaxes(tickangle=-30)
        st.plotly_chart(fig5, use_container_width=True)

    # ── Raw filtered table ────────────────────────────────────────────────
    st.markdown("### 🔍 Browse Events")
    etype_opts = ["All"] + sorted(df["event_type"].dropna().unique().tolist())
    sel = st.selectbox("Filter by Event Type", etype_opts)
    view = df if sel == "All" else df[df["event_type"] == sel]
    st.dataframe(view, use_container_width=True, height=300)


# ===========================================================================
# PAGE 5 – REPORTS
# ===========================================================================
def page_reports():
    st.markdown("## 📄 Reports")
    st.caption("Generate and export analysis reports.")

    logs_df   = st.session_state.logs_df
    alerts_df = st.session_state.alerts_df

    if logs_df is None or logs_df.empty:
        _empty_state(icon="📄", title="No data to report",
                     sub="Load a dataset first.")
        return

    rpt = generate_report_summary(logs_df, alerts_df or pd.DataFrame())

    # ── Summary section ───────────────────────────────────────────────────
    st.markdown("### 📊 Analysis Summary")
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Total Logs",        rpt["total_logs"])
    r2.metric("Successful Logins", rpt["successful_logins"])
    r3.metric("Failed Logins",     rpt["failed_logins"])
    r4.metric("System Errors",     rpt["system_errors"])

    r5, r6, r7, r8 = st.columns(4)
    r5.metric("Total Alerts",   rpt["total_alerts"])
    r6.metric("HIGH Alerts",    rpt["high_alerts"])
    r7.metric("MEDIUM Alerts",  rpt["medium_alerts"])
    r8.metric("LOW Alerts",     rpt["low_alerts"])

    st.markdown(f"""
    <div class="info-box">
      <b>Analysis Period:</b> {rpt['time_start']} → {rpt['time_end']}<br/>
      <b>Unique Users:</b> {rpt['unique_users']} &nbsp;|&nbsp;
      <b>Unique Hosts:</b> {rpt['unique_hosts']}<br/>
      <b>Report Generated:</b> {rpt['generated_at']}
    </div>""", unsafe_allow_html=True)

    # ── Event breakdown table ─────────────────────────────────────────────
    st.markdown("### Event Type Breakdown")
    ec_df = pd.DataFrame(
        [(k, v) for k, v in rpt["event_type_breakdown"].items()],
        columns=["Event Type", "Count"]
    ).sort_values("Count", ascending=False)
    st.dataframe(ec_df, use_container_width=True)

    # ── Export buttons ────────────────────────────────────────────────────
    st.markdown("### ⬇️ Export")
    ec1, ec2 = st.columns(2)

    with ec1:
        if alerts_df is not None:
            csv_a = export_alerts_csv(alerts_df)
            st.download_button("📥  Download Alerts CSV",
                               data=csv_a,
                               file_name="logguard_alerts.csv",
                               mime="text/csv",
                               use_container_width=True)

    with ec2:
        csv_l = logs_df.to_csv(index=False).encode()
        st.download_button("📥  Download Processed Logs CSV",
                           data=csv_l,
                           file_name="processed_logs.csv",
                           mime="text/csv",
                           use_container_width=True)

    # Save to disk
    if st.button("💾  Save Reports to Disk", use_container_width=True):
        a_path = save_alerts_to_file(alerts_df or pd.DataFrame(),
                                     str(BASE_DIR / "reports"))
        l_path = save_logs_to_file(logs_df, str(BASE_DIR / "reports"))
        st.success(f"✅ Saved:\n- Alerts → `{a_path}`\n- Logs → `{l_path}`")


# ===========================================================================
# PAGE 6 – SETTINGS
# ===========================================================================
def page_settings():
    st.markdown("## ⚙️ Settings")
    st.caption("Adjust detection thresholds. Changes take effect the next time "
               "you load a dataset.")
    st.info("💡 After changing settings, reload your dataset from the Log Analysis "
            "page to re-run detection with the new values.")

    with st.form("settings_form"):
        st.markdown("### Rule 1 – Repeated Failed Logins")
        c1, c2 = st.columns(2)
        new_fail_thresh  = c1.number_input(
            "Minimum failures to alert",
            min_value=2, max_value=20,
            value=st.session_state.cfg_fail_threshold,
            help="Trigger a HIGH alert when a user fails this many times.")
        new_fail_window  = c2.number_input(
            "Rolling window (minutes)",
            min_value=1, max_value=60,
            value=st.session_state.cfg_fail_window,
            help="Time window in minutes for the rolling failure count.")

        st.markdown("### Rule 3 – Multiple Account Failures")
        new_multi_users = st.number_input(
            "Distinct accounts from one host",
            min_value=2, max_value=20,
            value=st.session_state.cfg_multi_users,
            help="Alert when this many distinct accounts fail from one host.")

        st.markdown("### Rule 6 – Unusual Event Frequency")
        new_freq_thresh = st.number_input(
            "Event frequency threshold (per hour)",
            min_value=5, max_value=200,
            value=st.session_state.cfg_freq_threshold,
            help="Alert when any event type exceeds this count per hour.")

        st.markdown("### Rule 2b – Off-Hours Login Detection")
        new_enable_time = st.toggle(
            "Enable off-hours login detection",
            value=st.session_state.cfg_enable_time)

        submitted = st.form_submit_button("💾  Save Settings",
                                          use_container_width=True)
        if submitted:
            st.session_state.cfg_fail_threshold = int(new_fail_thresh)
            st.session_state.cfg_fail_window    = int(new_fail_window)
            st.session_state.cfg_multi_users    = int(new_multi_users)
            st.session_state.cfg_freq_threshold = int(new_freq_thresh)
            st.session_state.cfg_enable_time    = new_enable_time
            st.success("✅ Settings saved. Reload your dataset to apply.")

    # Reset button
    if st.button("🔄 Reset to Defaults"):
        st.session_state.cfg_fail_threshold  = FAILED_LOGIN_THRESHOLD
        st.session_state.cfg_fail_window     = FAILED_LOGIN_WINDOW_SECONDS // 60
        st.session_state.cfg_multi_users     = MULTI_ACCOUNT_DISTINCT_USERS
        st.session_state.cfg_freq_threshold  = EVENT_FREQUENCY_THRESHOLD
        st.session_state.cfg_enable_time     = True
        st.success("✅ Settings reset to defaults.")


# ===========================================================================
# PAGE 7 – ABOUT
# ===========================================================================
def page_about():
    st.markdown("## ℹ️ About LogGuard")
    st.markdown(f"""
    <div class="info-box">
      <b>LogGuard v{APP_VERSION}</b> – {APP_TAGLINE}<br/>
      A B.Tech Computer Science cybersecurity project demonstrating
      defensive log monitoring and anomaly detection.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    ### 🎯 Purpose
    LogGuard is an educational defensive cybersecurity tool that analyses system
    log files to identify potentially suspicious activity.  It is designed for:
    - College B.Tech / BCA cybersecurity coursework
    - Understanding Security Operations Centre (SOC) workflows
    - Learning how SIEM (Security Information and Event Management) tools work

    > **Important:** Alerts generated by LogGuard are *indicators for investigation*,
    > not proof of a cyberattack.  Always verify before acting.

    ---

    ### 🔍 Detection Rules

    | Rule | Description | Severity |
    |------|-------------|----------|
    | 1 | Repeated Failed Login Attempts (rolling 10-min window) | HIGH |
    | 2a | Failure burst followed by successful login | HIGH |
    | 2b | Successful login outside configured normal hours | LOW |
    | 3 | Multiple account failures from one host (password spray) | HIGH |
    | 4 | Unexpected service stop | MEDIUM / HIGH |
    | 5 | System error detection (individual + repeated) | LOW / MEDIUM |
    | 6 | Unusual event frequency per hour | MEDIUM |

    ---

    ### 🛠️ Technology Stack
    | Layer | Technology |
    |-------|-----------|
    | Backend | Python 3, pandas, NumPy |
    | Frontend | Streamlit |
    | Charts | Plotly |
    | Data | CSV files |
    | Tests | pytest |

    ---

    ### 📂 Project Structure
    ```
    LogGuard/
    ├── app.py              # Streamlit dashboard
    ├── main.py             # CLI entry point
    ├── analyzer.py         # Detection rules
    ├── log_processor.py    # CSV loading & preprocessing
    ├── alert_manager.py    # Alert management & export
    ├── config.py           # Configurable thresholds
    ├── data/               # Sample dataset
    ├── reports/            # Generated reports
    ├── assets/             # CSS styling
    └── tests/              # pytest unit tests
    ```

    ---

    ### ⚠️ Disclaimer
    All sample data in this project is **completely synthetic and fictional**.
    No real usernames, hostnames, or IP addresses are present.

    This tool is for **authorised educational and defensive monitoring only**.
    Do not use it on systems you do not own or have explicit permission to monitor.
    """)


# ===========================================================================
# ROUTER
# ===========================================================================
page_map = {
    "Overview"   : page_overview,
    "Analysis"   : page_log_analysis,
    "Alerts"     : page_security_alerts,
    "Monitoring" : page_event_monitoring,
    "Reports"    : page_reports,
    "Settings"   : page_settings,
    "About"      : page_about,
}

page_map.get(page_key, page_overview)()
