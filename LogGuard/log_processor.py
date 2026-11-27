"""
log_processor.py – LogGuard

Responsible for:
  • Loading CSV files from disk or an uploaded file object.
  • Validating that required columns are present.
  • Parsing and normalising timestamps.
  • Normalising status and event_type text.
  • Collecting and reporting rows that could not be cleaned.
  • Returning a clean DataFrame ready for the detection engine.

All public functions return plain Python dicts or pandas DataFrames so the
rest of the application never needs to import this module's internals.
"""

import io
import logging
from pathlib import Path
from typing import Union

import pandas as pd

from config import REQUIRED_COLUMNS, MAX_UPLOAD_SIZE_MB

# ---------------------------------------------------------------------------
# Module logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def load_csv_from_path(file_path: Union[str, Path]) -> dict:
    """
    Load a CSV from a file-system path and return a processing result dict.

    Returns
    -------
    dict with keys:
        success     – bool
        df          – cleaned DataFrame (or empty DataFrame on failure)
        raw_df      – original DataFrame before cleaning
        rejected    – DataFrame of rows that were dropped
        summary     – human-readable dict of stats
        error       – error message string ('' on success)
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return _failure(f"File not found: {file_path}")

    size_mb = file_path.stat().st_size / (1024 * 1024)
    if size_mb > MAX_UPLOAD_SIZE_MB:
        return _failure(
            f"File is {size_mb:.1f} MB – exceeds the {MAX_UPLOAD_SIZE_MB} MB limit."
        )

    try:
        raw_df = pd.read_csv(file_path, dtype=str)
    except Exception as exc:
        return _failure(f"Could not read CSV: {exc}")

    return _process(raw_df)


def load_csv_from_upload(uploaded_file) -> dict:
    """
    Load a CSV from a Streamlit UploadedFile object and return a processing
    result dict.  Same schema as :func:`load_csv_from_path`.
    """
    # Guard against huge uploads.
    # Streamlit exposes .size in bytes.
    try:
        size_mb = uploaded_file.size / (1024 * 1024)
        if size_mb > MAX_UPLOAD_SIZE_MB:
            return _failure(
                f"Uploaded file is {size_mb:.1f} MB – exceeds the "
                f"{MAX_UPLOAD_SIZE_MB} MB limit."
            )
    except AttributeError:
        pass   # .size not always available; skip the check

    try:
        # Read bytes first so we can reset if needed.
        raw_bytes = uploaded_file.read()
        raw_df = pd.read_csv(io.BytesIO(raw_bytes), dtype=str)
    except Exception as exc:
        return _failure(f"Could not parse uploaded file: {exc}")

    return _process(raw_df)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _process(raw_df: pd.DataFrame) -> dict:
    """
    Validate, clean and normalise a raw DataFrame.
    """
    # --- 1. Column validation ---
    raw_df.columns = [c.strip().lower() for c in raw_df.columns]
    missing_cols = [c for c in REQUIRED_COLUMNS if c not in raw_df.columns]
    if missing_cols:
        return _failure(
            f"Missing required column(s): {', '.join(missing_cols)}. "
            f"Expected: {', '.join(REQUIRED_COLUMNS)}"
        )

    df = raw_df.copy()
    rejected_mask = pd.Series(False, index=df.index)

    # --- 2. Strip whitespace from string columns ---
    for col in df.select_dtypes(include=["object", "string"]).columns:
        df[col] = df[col].str.strip()

    # --- 3. Parse timestamps ---
    # Try multiple common formats; unparseable rows are flagged as rejected.
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    bad_ts = df["timestamp"].isna()
    if bad_ts.any():
        logger.warning("%d rows have unparseable timestamps and will be dropped.",
                       bad_ts.sum())
        rejected_mask |= bad_ts

    # --- 4. Normalise text fields ---
    # status: lowercase, strip, map common variants
    df["status"] = df["status"].str.lower().str.strip()
    status_map = {
        "fail": "failed", "failure": "failed", "false": "failed",
        "success": "success", "succeed": "success", "ok": "success",
        "true": "success",
        "error": "error",
    }
    df["status"] = df["status"].map(lambda v: status_map.get(v, v)
                                    if isinstance(v, str) else v)

    # event_type: lowercase, strip, replace spaces with underscores
    df["event_type"] = (
        df["event_type"]
        .str.lower()
        .str.strip()
        .str.replace(r"\s+", "_", regex=True)
    )

    # username / host: lowercase, strip
    df["username"] = df["username"].str.lower().str.strip()
    df["host"]     = df["host"].str.lower().str.strip()

    # --- 5. Handle missing values in critical columns ---
    critical_cols = ["username", "host", "event_type", "status"]
    for col in critical_cols:
        missing = df[col].isna() | (df[col] == "")
        if missing.any():
            logger.warning(
                "%d rows have missing '%s' and will be dropped.", missing.sum(), col
            )
            rejected_mask |= missing

    # --- 6. Split into clean and rejected ---
    rejected_df = raw_df[rejected_mask].copy()
    clean_df    = df[~rejected_mask].copy()
    clean_df    = clean_df.sort_values("timestamp").reset_index(drop=True)

    # --- 7. Build summary ---
    total      = len(raw_df)
    n_clean    = len(clean_df)
    n_rejected = len(rejected_df)
    n_missing_ts = bad_ts.sum()

    time_range_start = None
    time_range_end   = None
    if not clean_df.empty:
        time_range_start = str(clean_df["timestamp"].min())
        time_range_end   = str(clean_df["timestamp"].max())

    summary = {
        "total_rows"       : total,
        "clean_rows"       : n_clean,
        "rejected_rows"    : n_rejected,
        "invalid_timestamps": int(n_missing_ts),
        "columns"          : list(clean_df.columns),
        "time_range_start" : time_range_start,
        "time_range_end"   : time_range_end,
        "event_types"      : sorted(clean_df["event_type"].dropna().unique().tolist())
                             if not clean_df.empty else [],
        "unique_users"     : int(clean_df["username"].nunique())
                             if not clean_df.empty else 0,
        "unique_hosts"     : int(clean_df["host"].nunique())
                             if not clean_df.empty else 0,
    }

    return {
        "success" : True,
        "df"      : clean_df,
        "raw_df"  : raw_df,
        "rejected": rejected_df,
        "summary" : summary,
        "error"   : "",
    }


def _failure(message: str) -> dict:
    """Return a standard failure result dict."""
    logger.error(message)
    return {
        "success" : False,
        "df"      : pd.DataFrame(),
        "raw_df"  : pd.DataFrame(),
        "rejected": pd.DataFrame(),
        "summary" : {},
        "error"   : message,
    }


# ---------------------------------------------------------------------------
# Convenience query helpers (used by app.py filters)
# ---------------------------------------------------------------------------

def filter_logs(df: pd.DataFrame,
                usernames: list = None,
                event_types: list = None,
                statuses: list = None,
                date_start=None,
                date_end=None) -> pd.DataFrame:
    """
    Apply optional filter criteria to a clean log DataFrame.

    All parameters are optional; pass None / empty list to skip that filter.
    date_start / date_end can be datetime.date or datetime.datetime objects.
    """
    out = df.copy()

    if usernames:
        out = out[out["username"].isin(usernames)]

    if event_types:
        out = out[out["event_type"].isin(event_types)]

    if statuses:
        out = out[out["status"].isin(statuses)]

    if date_start is not None:
        out = out[out["timestamp"] >= pd.Timestamp(date_start)]

    if date_end is not None:
        # Include the whole end day
        out = out[out["timestamp"] <= pd.Timestamp(date_end) + pd.Timedelta(days=1)]

    return out.reset_index(drop=True)


def get_summary_stats(df: pd.DataFrame) -> dict:
    """
    Compute high-level KPI statistics from a clean log DataFrame.
    Returns an empty dict for an empty DataFrame.
    """
    if df.empty:
        return {}

    total      = len(df)
    successes  = int((df["status"] == "success").sum())
    failures   = int((df["status"] == "failed").sum())
    errors     = int((df["status"] == "error").sum())
    sys_errors = int((df["event_type"] == "system_error").sum())

    return {
        "total_logs"      : total,
        "successful_logins": successes,
        "failed_logins"   : failures,
        "system_errors"   : sys_errors,
        "other_events"    : total - successes - failures - errors,
        "unique_users"    : int(df["username"].nunique()),
        "unique_hosts"    : int(df["host"].nunique()),
        "event_type_counts": df["event_type"].value_counts().to_dict(),
        "status_counts"   : df["status"].value_counts().to_dict(),
    }
