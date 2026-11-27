"""
alert_manager.py – LogGuard

Converts raw alert dicts (produced by analyzer.py) into a pandas DataFrame,
adds status tracking, and provides CSV export helpers.

Alert status lifecycle:  New → Investigating → Resolved
"""

import io
from datetime import datetime
from pathlib import Path

import pandas as pd

from config import SEVERITY_LEVELS, COLOURS

# Column order for the alerts DataFrame / export
ALERT_COLUMNS = [
    "alert_id", "timestamp", "username", "host", "event_type",
    "severity", "occurrences", "description", "detection_rule",
    "time_window_s", "status",
]


# ---------------------------------------------------------------------------
# Build alerts DataFrame
# ---------------------------------------------------------------------------

def build_alerts_df(raw_alerts: list) -> pd.DataFrame:
    """
    Convert the list of alert dicts returned by run_all_rules() into a clean
    DataFrame with a 'status' column defaulting to 'New'.
    """
    if not raw_alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    df = pd.DataFrame(raw_alerts)

    # Ensure all expected columns exist
    for col in ALERT_COLUMNS:
        if col not in df.columns:
            df[col] = None

    df["status"] = "New"
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df[ALERT_COLUMNS].copy()


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def alert_summary(alerts_df: pd.DataFrame) -> dict:
    """
    Return high-level alert KPIs for the overview dashboard.
    """
    if alerts_df.empty:
        return {sev: 0 for sev in SEVERITY_LEVELS} | {"total": 0}

    counts = alerts_df["severity"].value_counts().to_dict()
    total  = len(alerts_df)

    summary = {"total": total}
    for sev in SEVERITY_LEVELS:
        summary[sev] = counts.get(sev, 0)

    return summary


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def filter_alerts(
    df: pd.DataFrame,
    severities: list   = None,
    event_types: list  = None,
    usernames: list    = None,
    date_start=None,
    date_end=None,
    statuses: list     = None,
) -> pd.DataFrame:
    """
    Apply optional filters to the alerts DataFrame.
    """
    out = df.copy()

    if severities:
        out = out[out["severity"].isin(severities)]
    if event_types:
        out = out[out["event_type"].isin(event_types)]
    if usernames:
        out = out[out["username"].str.contains("|".join(usernames),
                                               case=False, na=False)]
    if date_start is not None:
        out = out[out["timestamp"] >= pd.Timestamp(date_start)]
    if date_end is not None:
        out = out[out["timestamp"] <= pd.Timestamp(date_end)
                  + pd.Timedelta(days=1)]
    if statuses:
        out = out[out["status"].isin(statuses)]

    return out.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_alerts_csv(alerts_df: pd.DataFrame) -> bytes:
    """
    Return alert DataFrame as UTF-8 CSV bytes (for Streamlit download button).
    """
    buf = io.BytesIO()
    alerts_df.to_csv(buf, index=False)
    return buf.getvalue()


def save_alerts_to_file(alerts_df: pd.DataFrame,
                        reports_dir: str = "reports") -> str:
    """
    Save alerts CSV to the reports directory and return the file path.
    """
    Path(reports_dir).mkdir(exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(reports_dir) / f"alerts_{ts}.csv"
    alerts_df.to_csv(out_path, index=False)
    return str(out_path)


def save_logs_to_file(logs_df: pd.DataFrame,
                      reports_dir: str = "reports") -> str:
    """
    Save processed logs CSV to the reports directory and return the file path.
    """
    Path(reports_dir).mkdir(exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(reports_dir) / f"processed_logs_{ts}.csv"
    logs_df.to_csv(out_path, index=False)
    return str(out_path)


def generate_report_summary(logs_df: pd.DataFrame,
                             alerts_df: pd.DataFrame) -> dict:
    """
    Compile a text-friendly summary dict for the Reports page.
    """
    if logs_df.empty:
        return {}

    sev_counts = {}
    if not alerts_df.empty:
        sev_counts = alerts_df["severity"].value_counts().to_dict()

    return {
        "generated_at"       : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_logs"         : len(logs_df),
        "successful_logins"  : int((logs_df["status"] == "success").sum()),
        "failed_logins"      : int((logs_df["status"] == "failed").sum()),
        "system_errors"      : int((logs_df["event_type"] == "system_error").sum()),
        "total_alerts"       : len(alerts_df),
        "high_alerts"        : sev_counts.get("HIGH", 0),
        "medium_alerts"      : sev_counts.get("MEDIUM", 0),
        "low_alerts"         : sev_counts.get("LOW", 0),
        "info_alerts"        : sev_counts.get("INFO", 0),
        "time_start"         : str(logs_df["timestamp"].min()),
        "time_end"           : str(logs_df["timestamp"].max()),
        "unique_users"       : int(logs_df["username"].nunique()),
        "unique_hosts"       : int(logs_df["host"].nunique()),
        "event_type_breakdown": logs_df["event_type"].value_counts().to_dict(),
    }
