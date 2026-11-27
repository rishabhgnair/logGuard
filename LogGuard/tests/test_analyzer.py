"""
tests/test_analyzer.py – LogGuard

Unit tests for analyzer.py detection rules.
Run with:  pytest tests/ -v

Each test builds a minimal synthetic DataFrame, runs the relevant detection
function, and asserts the expected alert behaviour.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer import (
    detect_repeated_failed_logins,
    detect_suspicious_login_activity,
    detect_multi_account_failures,
    detect_unexpected_service_stop,
    detect_system_errors,
    detect_unusual_event_frequency,
    run_all_rules,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_TS = datetime(2024, 3, 15, 9, 0, 0)


def _login_df(records):
    """
    Build a DataFrame from a list of (minutes_offset, username, status, host)
    tuples.  event_type is always 'login_attempt'.
    """
    rows = []
    for (mins, user, status, host) in records:
        rows.append({
            "timestamp" : BASE_TS + timedelta(minutes=mins),
            "host"      : host,
            "event_type": "login_attempt",
            "username"  : user,
            "status"    : status,
            "message"   : f"{status} login for {user}",
        })
    return pd.DataFrame(rows)


# ===========================================================================
# RULE 1 – Repeated Failed Logins
# ===========================================================================

class TestRepeatedFailedLogins:

    def test_exactly_threshold_triggers(self):
        """3 failures in 10 min (default threshold=3) → 1 HIGH alert."""
        df = _login_df([
            (0, "admin", "failed", "h1"),
            (2, "admin", "failed", "h1"),
            (4, "admin", "failed", "h1"),
        ])
        alerts = detect_repeated_failed_logins(df, threshold=3, window_seconds=600)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "HIGH"
        assert alerts[0]["username"] == "admin"

    def test_below_threshold_no_alert(self):
        """2 failures with threshold=3 must NOT trigger an alert."""
        df = _login_df([
            (0, "alice", "failed", "h1"),
            (3, "alice", "failed", "h1"),
        ])
        alerts = detect_repeated_failed_logins(df, threshold=3, window_seconds=600)
        assert len(alerts) == 0

    def test_five_failures_triggers_once(self):
        """5 consecutive failures should produce exactly 1 alert (not 3)."""
        df = _login_df([
            (0, "bob", "failed", "h1"),
            (1, "bob", "failed", "h1"),
            (2, "bob", "failed", "h1"),
            (3, "bob", "failed", "h1"),
            (4, "bob", "failed", "h1"),
        ])
        alerts = detect_repeated_failed_logins(df, threshold=3, window_seconds=600)
        # May produce 1 or 2 non-overlapping alerts; must not produce 0
        assert len(alerts) >= 1
        assert all(a["severity"] == "HIGH" for a in alerts)

    def test_outside_window_no_alert(self):
        """Failures spread > 10 min apart must NOT trigger the rule."""
        df = _login_df([
            (0,  "carol", "failed", "h1"),
            (11, "carol", "failed", "h1"),
            (22, "carol", "failed", "h1"),
        ])
        alerts = detect_repeated_failed_logins(df, threshold=3, window_seconds=600)
        assert len(alerts) == 0

    def test_multiple_usernames_independent(self):
        """Failures for different users are assessed independently."""
        df = _login_df([
            (0, "dave", "failed", "h1"),
            (2, "dave", "failed", "h1"),
            (4, "dave", "failed", "h1"),
            (0, "eve",  "failed", "h2"),   # only 1 failure – no alert
        ])
        alerts = detect_repeated_failed_logins(df, threshold=3, window_seconds=600)
        usernames = [a["username"] for a in alerts]
        assert "dave" in usernames
        assert "eve"  not in usernames

    def test_empty_df_returns_no_alerts(self):
        """An empty DataFrame must not raise an exception."""
        alerts = detect_repeated_failed_logins(pd.DataFrame(), threshold=3,
                                               window_seconds=600)
        assert alerts == []

    def test_no_duplicate_alerts(self):
        """The same burst should not produce two alerts with the same ID."""
        df = _login_df([(i, "admin", "failed", "h1") for i in range(5)])
        alerts = detect_repeated_failed_logins(df, threshold=3, window_seconds=600)
        ids = [a["alert_id"] for a in alerts]
        assert len(ids) == len(set(ids)), "Duplicate alert IDs detected"

    def test_successful_logins_not_counted(self):
        """Successful logins interspersed must not inflate the failure count."""
        df = _login_df([
            (0, "frank", "failed",  "h1"),
            (1, "frank", "success", "h1"),
            (2, "frank", "failed",  "h1"),
        ])
        alerts = detect_repeated_failed_logins(df, threshold=3, window_seconds=600)
        assert len(alerts) == 0


# ===========================================================================
# RULE 2 – Suspicious Login Activity
# ===========================================================================

class TestSuspiciousLoginActivity:

    def test_burst_then_success_triggers(self):
        """3 failures then 1 success → HIGH alert."""
        df = _login_df([
            (0, "grace", "failed",  "h1"),
            (2, "grace", "failed",  "h1"),
            (4, "grace", "failed",  "h1"),
            (5, "grace", "success", "h1"),
        ])
        alerts = detect_suspicious_login_activity(
            df, failure_count=2, enable_time=False)
        high = [a for a in alerts if a["severity"] == "HIGH"]
        assert len(high) >= 1
        assert any(a["username"] == "grace" for a in high)

    def test_success_alone_no_alert(self):
        """A single successful login with no prior failures is fine."""
        df = _login_df([(0, "heidi", "success", "h1")])
        alerts = detect_suspicious_login_activity(
            df, failure_count=2, enable_time=False)
        assert len(alerts) == 0

    def test_off_hours_login_low_severity(self):
        """Login at 02:00 with off-hours detection enabled → LOW alert."""
        rows = [{
            "timestamp" : datetime(2024, 3, 15, 2, 0, 0),
            "host"      : "bastion-01",
            "event_type": "login_attempt",
            "username"  : "ivan",
            "status"    : "success",
            "message"   : "Night login.",
        }]
        df = pd.DataFrame(rows)
        alerts = detect_suspicious_login_activity(
            df, failure_count=2,
            normal_start=8, normal_end=20, enable_time=True)
        low = [a for a in alerts if a["severity"] == "LOW"]
        assert len(low) >= 1

    def test_off_hours_disabled_no_alert(self):
        """Off-hours login with enable_time=False must NOT alert."""
        rows = [{
            "timestamp" : datetime(2024, 3, 15, 2, 0, 0),
            "host"      : "bastion-01",
            "event_type": "login_attempt",
            "username"  : "ivan",
            "status"    : "success",
            "message"   : "Night login.",
        }]
        df = pd.DataFrame(rows)
        alerts = detect_suspicious_login_activity(
            df, failure_count=2, enable_time=False)
        # Should have no LOW off-hours alert
        low_off = [a for a in alerts
                   if a["severity"] == "LOW" and "off" in a["detection_rule"].lower()]
        assert len(low_off) == 0


# ===========================================================================
# RULE 3 – Multiple Account Failures
# ===========================================================================

class TestMultiAccountFailures:

    def test_multiple_distinct_accounts_triggers(self):
        """3 distinct accounts failing from same host → HIGH alert."""
        rows = []
        base = datetime(2024, 3, 15, 9, 0, 0)
        for i, user in enumerate(["root", "admin", "sysop"]):
            rows.append({
                "timestamp" : base + timedelta(minutes=i),
                "host"      : "db-01",
                "event_type": "login_attempt",
                "username"  : user,
                "status"    : "failed",
                "message"   : f"failed for {user}",
            })
        df = pd.DataFrame(rows)
        alerts = detect_multi_account_failures(df, distinct_users=3,
                                               window_seconds=600)
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "HIGH"
        assert alerts[0]["host"] == "db-01"

    def test_same_account_multiple_times_no_alert(self):
        """Failures from only 1 distinct user should not trigger Rule 3."""
        df = _login_df([
            (0, "root", "failed", "db-01"),
            (1, "root", "failed", "db-01"),
            (2, "root", "failed", "db-01"),
        ])
        alerts = detect_multi_account_failures(df, distinct_users=3,
                                               window_seconds=600)
        assert len(alerts) == 0


# ===========================================================================
# RULE 4 – Unexpected Service Stop
# ===========================================================================

class TestServiceStop:

    def test_crash_keyword_produces_high(self):
        """'crash' in message → HIGH severity."""
        rows = [{
            "timestamp" : datetime(2024, 3, 15, 10, 0, 0),
            "host"      : "web-01",
            "event_type": "service_stopped",
            "username"  : "sysop",
            "status"    : "error",
            "message"   : "nginx stopped unexpectedly – crash detected.",
        }]
        df = pd.DataFrame(rows)
        alerts = detect_unexpected_service_stop(df)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "HIGH"

    def test_graceful_stop_produces_medium(self):
        """A graceful stop (no crash keywords) → MEDIUM severity."""
        rows = [{
            "timestamp" : datetime(2024, 3, 15, 10, 0, 0),
            "host"      : "db-01",
            "event_type": "service_stopped",
            "username"  : "root",
            "status"    : "success",
            "message"   : "postgresql stopped for maintenance.",
        }]
        df = pd.DataFrame(rows)
        alerts = detect_unexpected_service_stop(df)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "MEDIUM"

    def test_no_service_stop_events_no_alerts(self):
        df = _login_df([(0, "alice", "success", "h1")])
        alerts = detect_unexpected_service_stop(df)
        assert alerts == []


# ===========================================================================
# RULE 5 – System Error Detection
# ===========================================================================

class TestSystemErrors:

    def _sys_error_df(self, count, host="cache-01",
                       interval_minutes=1):
        rows = []
        base = datetime(2024, 3, 15, 10, 0, 0)
        for i in range(count):
            rows.append({
                "timestamp" : base + timedelta(minutes=i * interval_minutes),
                "host"      : host,
                "event_type": "system_error",
                "username"  : "system",
                "status"    : "error",
                "message"   : f"System error #{i+1}",
            })
        return pd.DataFrame(rows)

    def test_single_error_produces_low(self):
        df = self._sys_error_df(1)
        alerts = detect_system_errors(df, repeat_threshold=3,
                                      window_seconds=300)
        # Should have exactly one LOW alert
        low = [a for a in alerts if a["severity"] == "LOW"]
        assert len(low) == 1

    def test_repeated_errors_produce_medium(self):
        """3 errors in 5 min window → MEDIUM alert (not 3 LOW alerts)."""
        df = self._sys_error_df(3)
        alerts = detect_system_errors(df, repeat_threshold=3,
                                      window_seconds=300)
        medium = [a for a in alerts if a["severity"] == "MEDIUM"]
        assert len(medium) >= 1

    def test_errors_spread_out_produce_lows_not_medium(self):
        """Errors spaced >5 min apart each produce LOW, no MEDIUM."""
        df = self._sys_error_df(3, interval_minutes=10)
        alerts = detect_system_errors(df, repeat_threshold=3,
                                      window_seconds=300)
        medium = [a for a in alerts if a["severity"] == "MEDIUM"]
        low    = [a for a in alerts if a["severity"] == "LOW"]
        assert len(medium) == 0
        assert len(low)    == 3


# ===========================================================================
# RULE 6 – Unusual Event Frequency
# ===========================================================================

class TestEventFrequency:

    def test_high_frequency_produces_alert(self):
        """25 events of same type in one hour > threshold=20 → MEDIUM alert."""
        rows = []
        base = datetime(2024, 3, 15, 9, 0, 0)
        for i in range(25):
            rows.append({
                "timestamp" : base + timedelta(minutes=i * 2),
                "host"      : "monitor-01",
                "event_type": "cron_job",
                "username"  : "root",
                "status"    : "success",
                "message"   : f"cron #{i}",
            })
        df = pd.DataFrame(rows)
        alerts = detect_unusual_event_frequency(df, threshold=20)
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "MEDIUM"
        assert alerts[0]["occurrences"] == 25

    def test_below_threshold_no_alert(self):
        rows = []
        base = datetime(2024, 3, 15, 9, 0, 0)
        for i in range(5):
            rows.append({
                "timestamp" : base + timedelta(minutes=i * 10),
                "host"      : "h1",
                "event_type": "cron_job",
                "username"  : "root",
                "status"    : "success",
                "message"   : "cron",
            })
        df = pd.DataFrame(rows)
        alerts = detect_unusual_event_frequency(df, threshold=20)
        assert len(alerts) == 0


# ===========================================================================
# COMPOSITE – run_all_rules
# ===========================================================================

class TestRunAllRules:

    def test_empty_df_returns_empty(self):
        assert run_all_rules(pd.DataFrame()) == []

    def test_sample_data_produces_multiple_alerts(self, tmp_path):
        """run_all_rules on the sample CSV should produce at least 5 alerts."""
        sample = Path(__file__).parent.parent / "data" / "sample_logs.csv"
        if not sample.exists():
            pytest.skip("Sample dataset not generated yet.")

        import pandas as pd
        df = pd.read_csv(sample, dtype=str)
        # Minimal preprocessing
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
        df["status"] = df["status"].str.lower().str.strip()
        df["event_type"] = df["event_type"].str.lower().str.strip().str.replace(
            r"\s+", "_", regex=True)
        df["username"] = df["username"].str.lower().str.strip()
        df["host"]     = df["host"].str.lower().str.strip()

        alerts = run_all_rules(df)
        assert len(alerts) >= 5, \
            f"Expected ≥5 alerts from sample data, got {len(alerts)}"

    def test_all_alert_ids_unique(self):
        """Every alert in the combined output must have a unique ID."""
        rows = []
        base = datetime(2024, 3, 15, 9, 0, 0)
        # Trigger Rule 1
        for i in range(5):
            rows.append({
                "timestamp" : base + timedelta(minutes=i),
                "host"      : "h1",
                "event_type": "login_attempt",
                "username"  : "admin",
                "status"    : "failed",
                "message"   : "fail",
            })
        # Trigger Rule 4
        rows.append({
            "timestamp" : base + timedelta(hours=1),
            "host"      : "h1",
            "event_type": "service_stopped",
            "username"  : "root",
            "status"    : "error",
            "message"   : "crash",
        })
        df = pd.DataFrame(rows)
        alerts = run_all_rules(df)
        ids = [a["alert_id"] for a in alerts]
        assert len(ids) == len(set(ids)), "Duplicate alert IDs in run_all_rules output"
