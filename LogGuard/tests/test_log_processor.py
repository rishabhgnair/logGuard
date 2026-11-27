"""
tests/test_log_processor.py – LogGuard

Unit tests for log_processor.py.
Run with:  pytest tests/ -v
"""

import io
import sys
from pathlib import Path
from datetime import datetime

import pandas as pd
import pytest

# Allow imports from the parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from log_processor import (
    load_csv_from_path,
    load_csv_from_upload,
    filter_logs,
    get_summary_stats,
    _process,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_df(**overrides):
    """
    Build a minimal valid log DataFrame with one row.
    Override any column via keyword arguments.
    """
    defaults = {
        "timestamp" : ["2024-03-15 09:00:00"],
        "host"      : ["web-01"],
        "event_type": ["login_attempt"],
        "username"  : ["alice"],
        "status"    : ["success"],
        "message"   : ["User alice logged in."],
    }
    defaults.update({k: [v] if not isinstance(v, list) else v
                     for k, v in overrides.items()})
    return pd.DataFrame(defaults)


def _csv_bytes(df: pd.DataFrame) -> bytes:
    buf = io.BytesIO()
    df.to_csv(buf, index=False)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# TEST GROUP 1 – CSV Loading
# ---------------------------------------------------------------------------

class TestCsvLoading:

    def test_valid_sample_csv_loads(self, tmp_path):
        """A well-formed CSV with all required columns should succeed."""
        df  = _make_df()
        csv = tmp_path / "valid.csv"
        df.to_csv(csv, index=False)

        result = load_csv_from_path(csv)
        assert result["success"] is True
        assert len(result["df"]) == 1
        assert result["error"] == ""

    def test_nonexistent_file_fails(self, tmp_path):
        """A path that does not exist should return failure."""
        result = load_csv_from_path(tmp_path / "ghost.csv")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_missing_required_column_fails(self, tmp_path):
        """A CSV missing a required column should fail with a helpful message."""
        df = _make_df()
        df = df.drop(columns=["status"])
        csv = tmp_path / "missing_col.csv"
        df.to_csv(csv, index=False)

        result = load_csv_from_path(csv)
        assert result["success"] is False
        assert "status" in result["error"]

    def test_multiple_missing_columns_reported(self, tmp_path):
        """All missing columns should be mentioned in the error message."""
        df = pd.DataFrame({"timestamp": ["2024-01-01"], "host": ["h1"]})
        csv = tmp_path / "broken.csv"
        df.to_csv(csv, index=False)

        result = load_csv_from_path(csv)
        assert result["success"] is False
        # At least one of the missing columns should be named
        assert any(c in result["error"]
                   for c in ["event_type", "username", "status", "message"])

    def test_empty_file_handled(self, tmp_path):
        """An empty CSV (header only) should load with 0 rows, not crash."""
        csv = tmp_path / "empty.csv"
        csv.write_text("timestamp,host,event_type,username,status,message\n")
        result = load_csv_from_path(csv)
        assert result["success"] is True
        assert len(result["df"]) == 0


# ---------------------------------------------------------------------------
# TEST GROUP 2 – Timestamp Handling
# ---------------------------------------------------------------------------

class TestTimestampHandling:

    def test_invalid_timestamp_row_rejected(self):
        """Rows with unparseable timestamps must be excluded from clean_df."""
        rows = [
            ("NOT_A_DATE",    "h1", "login_attempt", "alice", "success", "ok"),
            ("2024-03-15 09:00", "h1", "login_attempt", "bob",   "success", "ok"),
        ]
        df = pd.DataFrame(rows, columns=["timestamp","host","event_type",
                                         "username","status","message"])
        result = _process(df)
        assert result["success"] is True
        assert len(result["df"]) == 1
        assert result["df"]["username"].iloc[0] == "bob"
        assert result["summary"]["invalid_timestamps"] == 1

    def test_all_invalid_timestamps_produces_empty_df(self):
        """When every row has a bad timestamp, clean_df should be empty."""
        df = _make_df(timestamp=["BADDATE"])
        result = _process(df)
        assert result["success"] is True
        assert result["df"].empty

    def test_mixed_timestamp_formats_parsed(self):
        """pandas should parse multiple sensible datetime formats."""
        rows = [
            ("2024-03-15 09:00:00", "h1","login_attempt","alice","success","m1"),
            ("2024-03-15T10:30:00", "h1","login_attempt","bob",  "success","m2"),
        ]
        df = pd.DataFrame(rows, columns=["timestamp","host","event_type",
                                         "username","status","message"])
        result = _process(df)
        assert result["success"] is True
        assert len(result["df"]) == 2


# ---------------------------------------------------------------------------
# TEST GROUP 3 – Status Normalisation
# ---------------------------------------------------------------------------

class TestStatusNormalisation:

    def test_status_variants_normalised(self):
        """'fail', 'failure', 'Fail' should all become 'failed'."""
        variants = ["fail", "failure", "Fail", "FAIL"]
        for v in variants:
            df = _make_df(status=[v])
            result = _process(df)
            assert result["df"]["status"].iloc[0] == "failed", \
                f"'{v}' was not normalised to 'failed'"

    def test_success_variants_normalised(self):
        """'succeed', 'ok', 'OK' should become 'success'."""
        for v in ["succeed", "ok", "OK"]:
            df = _make_df(status=[v])
            result = _process(df)
            assert result["df"]["status"].iloc[0] == "success", \
                f"'{v}' was not normalised to 'success'"


# ---------------------------------------------------------------------------
# TEST GROUP 4 – Filtering
# ---------------------------------------------------------------------------

class TestFilterLogs:

    @pytest.fixture
    def sample_df(self):
        rows = [
            ("2024-03-15 08:00", "web-01","login_attempt","alice","success","m1"),
            ("2024-03-15 08:10", "web-01","login_attempt","alice","failed", "m2"),
            ("2024-03-15 09:00", "db-01", "system_error", "bob",  "error",  "m3"),
        ]
        df = pd.DataFrame(rows, columns=["timestamp","host","event_type",
                                         "username","status","message"])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def test_filter_by_username(self, sample_df):
        out = filter_logs(sample_df, usernames=["alice"])
        assert len(out) == 2
        assert all(out["username"] == "alice")

    def test_filter_by_status(self, sample_df):
        out = filter_logs(sample_df, statuses=["failed"])
        assert len(out) == 1
        assert out.iloc[0]["username"] == "alice"

    def test_filter_by_event_type(self, sample_df):
        out = filter_logs(sample_df, event_types=["system_error"])
        assert len(out) == 1
        assert out.iloc[0]["username"] == "bob"

    def test_no_filter_returns_all(self, sample_df):
        out = filter_logs(sample_df)
        assert len(out) == len(sample_df)


# ---------------------------------------------------------------------------
# TEST GROUP 5 – get_summary_stats
# ---------------------------------------------------------------------------

class TestSummaryStats:

    def test_empty_df_returns_empty_dict(self):
        assert get_summary_stats(pd.DataFrame()) == {}

    def test_counts_correct(self):
        rows = [
            ("2024-03-15 09:00","h1","login_attempt","alice","success","m1"),
            ("2024-03-15 09:01","h1","login_attempt","alice","failed", "m2"),
            ("2024-03-15 09:02","h1","system_error", "system","error","m3"),
        ]
        df = pd.DataFrame(rows, columns=["timestamp","host","event_type",
                                         "username","status","message"])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        stats = get_summary_stats(df)
        assert stats["total_logs"]        == 3
        assert stats["successful_logins"] == 1
        assert stats["failed_logins"]     == 1
        assert stats["system_errors"]     == 1
