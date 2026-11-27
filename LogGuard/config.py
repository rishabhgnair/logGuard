"""
config.py – LogGuard Configuration

All detection thresholds and application settings live here.
Changing a value here affects the whole application – no need
to touch the detection algorithms themselves.
"""

# ---------------------------------------------------------------------------
# RULE 1: Repeated Failed Login Attempts
# ---------------------------------------------------------------------------
# If a single username produces this many failures within the rolling
# window (seconds), generate a HIGH-severity alert.
FAILED_LOGIN_THRESHOLD = 3          # minimum number of failures to flag
FAILED_LOGIN_WINDOW_SECONDS = 600   # 10-minute rolling window

# ---------------------------------------------------------------------------
# RULE 2: Suspicious Login (failure burst then success)
# ---------------------------------------------------------------------------
# Flag when a username has this many failures BEFORE a successful login.
SUSPICIOUS_LOGIN_FAILURE_COUNT = 2

# Optional: list of hours considered "normal office hours" (24-h clock).
# Leave empty to disable time-based suspicious-login checks.
NORMAL_HOURS_START = 8    # 08:00
NORMAL_HOURS_END   = 20   # 20:00
ENABLE_TIME_BASED_DETECTION = True   # set False to ignore off-hours logins

# ---------------------------------------------------------------------------
# RULE 3: Multiple Account Failures from the Same Host
# ---------------------------------------------------------------------------
# Flag when this many *distinct* usernames fail from one host within the
# rolling window below.
MULTI_ACCOUNT_DISTINCT_USERS = 3
MULTI_ACCOUNT_WINDOW_SECONDS = 600   # 10-minute rolling window

# ---------------------------------------------------------------------------
# RULE 4: Unexpected Service Stop
# ---------------------------------------------------------------------------
# Keywords that, when found in the message field of a service_stopped event,
# raise the severity to HIGH instead of MEDIUM.
SERVICE_STOP_HIGH_KEYWORDS = ["crash", "killed", "oom", "out of memory",
                               "segfault", "unexpected", "abort"]

# ---------------------------------------------------------------------------
# RULE 5: System Error Detection
# ---------------------------------------------------------------------------
# How many system_error events within the window trigger a repeated-error
# alert?
SYSTEM_ERROR_REPEAT_THRESHOLD = 3
SYSTEM_ERROR_WINDOW_SECONDS   = 300  # 5-minute window

# ---------------------------------------------------------------------------
# RULE 6: Unusual Event Frequency
# ---------------------------------------------------------------------------
# If any event_type appears more than this many times per hour, flag it.
EVENT_FREQUENCY_THRESHOLD = 20

# ---------------------------------------------------------------------------
# GENERAL SETTINGS
# ---------------------------------------------------------------------------
APP_TITLE   = "LogGuard"
APP_VERSION = "1.0.0"
APP_TAGLINE = "System Log Monitoring & Anomaly Detection Platform"

# Maximum CSV upload size in megabytes.
MAX_UPLOAD_SIZE_MB = 50

# Required columns (lowercase) that every log CSV must contain.
REQUIRED_COLUMNS = ["timestamp", "host", "event_type", "username",
                    "status", "message"]

# Severity levels (ordered lowest → highest).
SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH"]

# Colour palette used by the Streamlit frontend.
COLOURS = {
    "HIGH"   : "#EF4444",   # red
    "MEDIUM" : "#F97316",   # orange
    "LOW"    : "#EAB308",   # yellow
    "INFO"   : "#22C55E",   # green
    "bg"     : "#0F172A",   # dark navy
    "card"   : "#1E293B",   # charcoal
    "accent" : "#38BDF8",   # cyan
}
