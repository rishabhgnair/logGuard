"""
analyzer.py – LogGuard Anomaly Detection Engine

Each public function implements one detection rule and returns a list of
alert dictionaries.  The alert schema is:

    {
        "alert_id"       : str   – unique identifier
        "timestamp"      : str   – when the pattern was first observed
        "username"       : str
        "host"           : str
        "event_type"     : str   – the triggering event_type
        "severity"       : str   – HIGH / MEDIUM / LOW / INFO
        "occurrences"    : int   – how many events triggered this alert
        "description"    : str   – human-readable explanation
        "detection_rule" : str   – which rule fired
        "time_window_s"  : int   – the rolling window used (seconds)
    }

Design decisions
----------------
• Every rule is a pure function that accepts a DataFrame and config params.
• No global state – run_all_rules() composes them and de-duplicates results.
• Duplicate prevention: an alert is considered a duplicate if the same
  (username, host, detection_rule, truncated-window-start) already exists.
"""

import hashlib
import uuid
from datetime import timedelta

import pandas as pd

import config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert_id(prefix: str, *parts) -> str:
    """Generate a short, deterministic alert ID from meaningful components."""
    raw = "|".join(str(p) for p in parts)
    h   = hashlib.md5(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h}".upper()


def _window_start_key(ts: pd.Timestamp, window_seconds: int) -> str:
    """
    Bucket a timestamp into a window so that two alerts in the same window
    get the same key (used for duplicate prevention).
    """
    epoch_s   = int(ts.timestamp())
    bucket    = epoch_s - (epoch_s % window_seconds)
    return str(bucket)


# ---------------------------------------------------------------------------
# RULE 1 – Repeated Failed Login Attempts
# ---------------------------------------------------------------------------

def detect_repeated_failed_logins(
    df: pd.DataFrame,
    threshold: int = config.FAILED_LOGIN_THRESHOLD,
    window_seconds: int = config.FAILED_LOGIN_WINDOW_SECONDS,
) -> list:
    """
    For every username, slide a time window over their failed login events.
    If the count of failures within any window reaches `threshold`, emit an
    alert.

    How the sliding window works
    ----------------------------
    We iterate over each failure event for a user (sorted by time).
    We keep a deque of events within [current_event_time - window, current].
    When the deque size hits the threshold we record an alert at the window
    start, then advance past that alert to avoid counting the same events
    twice (non-overlapping alerts per detection pass).
    """
    alerts = []
    seen   = set()   # dedup keys

    # Guard: nothing to do on an empty DataFrame
    if df.empty or "status" not in df.columns or "event_type" not in df.columns:
        return alerts

    # Keep only failed login events
    failed = df[
        (df["status"] == "failed") &
        (df["event_type"].str.contains("login|auth|logon|ssh|rdp",
                                       case=False, na=False))
    ].copy()

    if failed.empty:
        return alerts

    for username, group in failed.groupby("username"):
        events = group.sort_values("timestamp")["timestamp"].tolist()
        i = 0
        while i < len(events):
            # Collect all events within [events[i], events[i] + window]
            window_end = events[i] + timedelta(seconds=window_seconds)
            burst = [t for t in events[i:] if t <= window_end]

            if len(burst) >= threshold:
                window_start = burst[0]
                dedup_key = _make_alert_id(
                    "RFL", username,
                    _window_start_key(window_start, window_seconds)
                )
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    # Identify the host(s) involved
                    host_series = group[
                        (group["timestamp"] >= window_start) &
                        (group["timestamp"] <= window_end)
                    ]["host"]
                    host = host_series.mode()[0] if not host_series.empty else "unknown"

                    alerts.append({
                        "alert_id"      : dedup_key,
                        "timestamp"     : str(window_start),
                        "username"      : username,
                        "host"          : host,
                        "event_type"    : "login_failure",
                        "severity"      : "HIGH",
                        "occurrences"   : len(burst),
                        "description"   : (
                            f"User '{username}' had {len(burst)} failed login "
                            f"attempt(s) within a {window_seconds // 60}-minute "
                            f"window starting at {window_start}."
                        ),
                        "detection_rule": "Repeated Failed Login Attempts",
                        "time_window_s" : window_seconds,
                    })
                # Advance past the burst to avoid re-counting same events
                i += len(burst)
            else:
                i += 1

    return alerts


# ---------------------------------------------------------------------------
# RULE 2 – Suspicious Login Activity
# ---------------------------------------------------------------------------

def detect_suspicious_login_activity(
    df: pd.DataFrame,
    failure_count: int = config.SUSPICIOUS_LOGIN_FAILURE_COUNT,
    normal_start: int  = config.NORMAL_HOURS_START,
    normal_end: int    = config.NORMAL_HOURS_END,
    enable_time: bool  = config.ENABLE_TIME_BASED_DETECTION,
    window_seconds: int = config.FAILED_LOGIN_WINDOW_SECONDS,
) -> list:
    """
    Two sub-checks:

    2a. Failure burst then success (credential stuffing / brute-force success)
        – Same username, N failures within the window, then a success.

    2b. Off-hours successful login (configurable, disabled by default trigger
        only when enable_time=True).
    """
    alerts = []
    seen   = set()

    # --- 2a. Failures followed by success ---
    login_events = df[
        df["event_type"].str.contains("login|auth|logon|ssh|rdp",
                                      case=False, na=False)
    ].copy()

    for username, group in login_events.groupby("username"):
        events = group.sort_values("timestamp")
        timestamps = events["timestamp"].tolist()
        statuses   = events["status"].tolist()

        for idx, (ts, st) in enumerate(zip(timestamps, statuses)):
            if st == "success":
                # Count failures in the window ending just before this success
                win_start = ts - timedelta(seconds=window_seconds)
                prev_failures = [
                    t for t, s in zip(timestamps[:idx], statuses[:idx])
                    if s == "failed" and t >= win_start
                ]
                if len(prev_failures) >= failure_count:
                    dedup_key = _make_alert_id(
                        "SLA", username,
                        _window_start_key(ts, window_seconds)
                    )
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        host = events[events["timestamp"] == ts]["host"].iloc[0] \
                               if not events[events["timestamp"] == ts].empty \
                               else "unknown"
                        alerts.append({
                            "alert_id"      : dedup_key,
                            "timestamp"     : str(ts),
                            "username"      : username,
                            "host"          : host,
                            "event_type"    : "suspicious_login",
                            "severity"      : "HIGH",
                            "occurrences"   : len(prev_failures) + 1,
                            "description"   : (
                                f"User '{username}' had {len(prev_failures)} "
                                f"failed login(s) followed by a successful login "
                                f"at {ts}. This may indicate a successful brute-"
                                f"force or credential-stuffing attempt."
                            ),
                            "detection_rule": "Suspicious Login Activity (burst+success)",
                            "time_window_s" : window_seconds,
                        })

    # --- 2b. Off-hours successful login ---
    if enable_time:
        success_logins = login_events[login_events["status"] == "success"].copy()
        success_logins["hour"] = success_logins["timestamp"].dt.hour
        off_hours = success_logins[
            ~success_logins["hour"].between(normal_start, normal_end - 1)
        ]
        for _, row in off_hours.iterrows():
            dedup_key = _make_alert_id(
                "OHL", row["username"], str(row["timestamp"])
            )
            if dedup_key not in seen:
                seen.add(dedup_key)
                alerts.append({
                    "alert_id"      : dedup_key,
                    "timestamp"     : str(row["timestamp"]),
                    "username"      : row["username"],
                    "host"          : row["host"],
                    "event_type"    : "off_hours_login",
                    "severity"      : "LOW",
                    "occurrences"   : 1,
                    "description"   : (
                        f"User '{row['username']}' logged in successfully at "
                        f"{row['timestamp']} – outside configured normal hours "
                        f"({normal_start:02d}:00–{normal_end:02d}:00). "
                        f"Investigate if unexpected."
                    ),
                    "detection_rule": "Suspicious Login Activity (off-hours)",
                    "time_window_s" : 0,
                })

    return alerts


# ---------------------------------------------------------------------------
# RULE 3 – Multiple Account Failures from the Same Host
# ---------------------------------------------------------------------------

def detect_multi_account_failures(
    df: pd.DataFrame,
    distinct_users: int   = config.MULTI_ACCOUNT_DISTINCT_USERS,
    window_seconds: int   = config.MULTI_ACCOUNT_WINDOW_SECONDS,
) -> list:
    """
    If a single host produces failed logins for N distinct usernames within
    the rolling window, raise a HIGH alert.

    This can indicate password-spraying or automated credential scanning.
    """
    alerts = []
    seen   = set()

    failed_logins = df[
        (df["status"] == "failed") &
        (df["event_type"].str.contains("login|auth|logon|ssh|rdp",
                                       case=False, na=False))
    ].copy()

    if failed_logins.empty:
        return alerts

    for host, group in failed_logins.groupby("host"):
        events = group.sort_values("timestamp")
        ts_list   = events["timestamp"].tolist()
        user_list = events["username"].tolist()

        i = 0
        while i < len(ts_list):
            win_end    = ts_list[i] + timedelta(seconds=window_seconds)
            burst_mask = [t <= win_end for t in ts_list[i:]]
            burst_ts   = [t for t, m in zip(ts_list[i:], burst_mask) if m]
            burst_usr  = [u for u, m in zip(user_list[i:], burst_mask) if m]

            unique_users = set(burst_usr)
            if len(unique_users) >= distinct_users:
                dedup_key = _make_alert_id(
                    "MAF", host,
                    _window_start_key(ts_list[i], window_seconds)
                )
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    alerts.append({
                        "alert_id"      : dedup_key,
                        "timestamp"     : str(ts_list[i]),
                        "username"      : ", ".join(sorted(unique_users)[:5]),
                        "host"          : host,
                        "event_type"    : "multi_account_failure",
                        "severity"      : "HIGH",
                        "occurrences"   : len(burst_ts),
                        "description"   : (
                            f"Host '{host}' generated login failures for "
                            f"{len(unique_users)} distinct accounts "
                            f"({', '.join(sorted(unique_users)[:5])}) "
                            f"within a {window_seconds // 60}-minute window. "
                            f"This may indicate password spraying."
                        ),
                        "detection_rule": "Multiple Account Failures",
                        "time_window_s" : window_seconds,
                    })
                i += len(burst_ts)
            else:
                i += 1

    return alerts


# ---------------------------------------------------------------------------
# RULE 4 – Unexpected Service Stop
# ---------------------------------------------------------------------------

def detect_unexpected_service_stop(
    df: pd.DataFrame,
    high_keywords: list = config.SERVICE_STOP_HIGH_KEYWORDS,
) -> list:
    """
    Every service_stopped event is at least MEDIUM severity.
    If the message contains a keyword from high_keywords it becomes HIGH.
    """
    alerts = []
    seen   = set()

    svc_stopped = df[df["event_type"] == "service_stopped"].copy()

    for _, row in svc_stopped.iterrows():
        message  = str(row.get("message", "")).lower()
        severity = "HIGH" if any(kw in message for kw in high_keywords) \
                   else "MEDIUM"

        dedup_key = _make_alert_id(
            "USS", row["username"], row["host"], str(row["timestamp"])
        )
        if dedup_key not in seen:
            seen.add(dedup_key)
            alerts.append({
                "alert_id"      : dedup_key,
                "timestamp"     : str(row["timestamp"]),
                "username"      : row["username"],
                "host"          : row["host"],
                "event_type"    : "service_stopped",
                "severity"      : severity,
                "occurrences"   : 1,
                "description"   : (
                    f"Service stop event detected on host '{row['host']}'. "
                    f"Message: {row.get('message', 'N/A')}."
                ),
                "detection_rule": "Unexpected Service Stop",
                "time_window_s" : 0,
            })

    return alerts


# ---------------------------------------------------------------------------
# RULE 5 – System Error Detection
# ---------------------------------------------------------------------------

def detect_system_errors(
    df: pd.DataFrame,
    repeat_threshold: int = config.SYSTEM_ERROR_REPEAT_THRESHOLD,
    window_seconds: int   = config.SYSTEM_ERROR_WINDOW_SECONDS,
) -> list:
    """
    Two sub-checks:

    5a. Any single system_error event → LOW alert.
    5b. If a host generates repeat_threshold or more system_error events
        within window_seconds → MEDIUM alert (replaces individual LOW alerts
        for that burst).
    """
    alerts = []
    seen   = set()

    sys_errors = df[df["event_type"] == "system_error"].copy()

    if sys_errors.empty:
        return alerts

    # --- 5b. Repeated errors per host ---
    for host, group in sys_errors.groupby("host"):
        events = group.sort_values("timestamp")
        ts_list = events["timestamp"].tolist()

        i = 0
        while i < len(ts_list):
            win_end  = ts_list[i] + timedelta(seconds=window_seconds)
            burst    = [t for t in ts_list[i:] if t <= win_end]

            if len(burst) >= repeat_threshold:
                dedup_key = _make_alert_id(
                    "RSE", host,
                    _window_start_key(ts_list[i], window_seconds)
                )
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    alerts.append({
                        "alert_id"      : dedup_key,
                        "timestamp"     : str(ts_list[i]),
                        "username"      : "system",
                        "host"          : host,
                        "event_type"    : "system_error",
                        "severity"      : "MEDIUM",
                        "occurrences"   : len(burst),
                        "description"   : (
                            f"Host '{host}' logged {len(burst)} system error(s) "
                            f"within a {window_seconds // 60}-minute window."
                        ),
                        "detection_rule": "System Error Detection (repeated)",
                        "time_window_s" : window_seconds,
                    })
                # Mark these events so we don't also emit LOW alerts for them
                for t in burst:
                    seen.add(_make_alert_id("SSE", host, str(t)))
                i += len(burst)
            else:
                i += 1

    # --- 5a. Individual system_error events (not already in a burst) ---
    for _, row in sys_errors.iterrows():
        dedup_key = _make_alert_id("SSE", row["host"], str(row["timestamp"]))
        if dedup_key not in seen:
            seen.add(dedup_key)
            alerts.append({
                "alert_id"      : dedup_key,
                "timestamp"     : str(row["timestamp"]),
                "username"      : row.get("username", "system"),
                "host"          : row["host"],
                "event_type"    : "system_error",
                "severity"      : "LOW",
                "occurrences"   : 1,
                "description"   : (
                    f"System error on host '{row['host']}': "
                    f"{row.get('message', 'N/A')}"
                ),
                "detection_rule": "System Error Detection",
                "time_window_s" : 0,
            })

    return alerts


# ---------------------------------------------------------------------------
# RULE 6 – Unusual Event Frequency
# ---------------------------------------------------------------------------

def detect_unusual_event_frequency(
    df: pd.DataFrame,
    threshold: int = config.EVENT_FREQUENCY_THRESHOLD,
) -> list:
    """
    For each hour in the dataset, count events per event_type.
    If any type exceeds `threshold` occurrences in an hour, emit a MEDIUM
    alert.

    The threshold is intentionally transparent: the alert message explains
    exactly how many events were observed and what the threshold is.
    """
    alerts = []
    seen   = set()

    if df.empty:
        return alerts

    tmp = df.copy()
    tmp["hour_bucket"] = tmp["timestamp"].dt.floor("h")

    hourly = (
        tmp.groupby(["hour_bucket", "event_type"])
           .size()
           .reset_index(name="count")
    )

    high_freq = hourly[hourly["count"] > threshold]

    for _, row in high_freq.iterrows():
        dedup_key = _make_alert_id(
            "UEF", row["event_type"], str(row["hour_bucket"])
        )
        if dedup_key not in seen:
            seen.add(dedup_key)
            alerts.append({
                "alert_id"      : dedup_key,
                "timestamp"     : str(row["hour_bucket"]),
                "username"      : "N/A",
                "host"          : "N/A",
                "event_type"    : row["event_type"],
                "severity"      : "MEDIUM",
                "occurrences"   : int(row["count"]),
                "description"   : (
                    f"Event type '{row['event_type']}' occurred "
                    f"{int(row['count'])} time(s) in the hour starting "
                    f"{row['hour_bucket']} – exceeds the threshold of "
                    f"{threshold} per hour."
                ),
                "detection_rule": "Unusual Event Frequency",
                "time_window_s" : 3600,
            })

    return alerts


# ---------------------------------------------------------------------------
# Composite runner
# ---------------------------------------------------------------------------

def run_all_rules(df: pd.DataFrame) -> list:
    """
    Run every detection rule against the clean DataFrame and return a merged,
    deduplicated list of alerts sorted by severity (HIGH first) then timestamp.
    """
    if df.empty:
        return []

    all_alerts: list = []
    all_alerts.extend(detect_repeated_failed_logins(df))
    all_alerts.extend(detect_suspicious_login_activity(df))
    all_alerts.extend(detect_multi_account_failures(df))
    all_alerts.extend(detect_unexpected_service_stop(df))
    all_alerts.extend(detect_system_errors(df))
    all_alerts.extend(detect_unusual_event_frequency(df))

    # Global dedup by alert_id (each rule already dedupes internally, but
    # just in case rules share edge-case keys).
    seen_ids = set()
    unique   = []
    for a in all_alerts:
        if a["alert_id"] not in seen_ids:
            seen_ids.add(a["alert_id"])
            unique.append(a)

    # Sort: severity order then timestamp
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    unique.sort(key=lambda a: (sev_order.get(a["severity"], 9), a["timestamp"]))

    return unique
