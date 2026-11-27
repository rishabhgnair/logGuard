# 🛡️ LogGuard – System Log Monitoring and Anomaly Detection Platform

> **B.Tech Computer Science Cybersecurity Project**  
> A defensive security tool that analyses system log files and detects potentially suspicious activity.

---

## 📋 Table of Contents
1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Objectives](#objectives)
4. [Features](#features)
5. [Technology Stack](#technology-stack)
6. [Architecture](#architecture)
7. [Project Structure](#project-structure)
8. [Installation](#installation)
9. [How to Run](#how-to-run)
10. [How to Upload Logs](#how-to-upload-logs)
11. [Detection Rules](#detection-rules)
12. [Limitations](#limitations)
13. [Future Enhancements](#future-enhancements)
14. [Disclaimer](#disclaimer)

---

## Overview

**LogGuard** is a Python-based Security Information and Event Management (SIEM)-style tool designed to:

- Ingest system log files in CSV format
- Validate, clean, and preprocess log records
- Detect suspicious patterns using rule-based anomaly detection
- Classify security alerts by severity (HIGH / MEDIUM / LOW / INFO)
- Visualise activity through an interactive Streamlit dashboard
- Export alerts and reports as CSV files

The tool is intended for **educational demonstrations** and **authorised defensive security monitoring**.

---

## Problem Statement

System administrators and security analysts deal with hundreds of log events every day. Manually reviewing each log entry is time-consuming and error-prone. Automated log monitoring tools can flag suspicious patterns quickly, allowing analysts to focus on real threats.

LogGuard demonstrates how such a tool works from first principles — without relying on expensive enterprise SIEM products.

---

## Objectives

- Read system logs from CSV files with real preprocessing and validation.
- Identify repeated failed login attempts using a rolling time-window algorithm.
- Detect suspicious patterns such as credential stuffing (failure burst then success).
- Identify multi-account attack patterns (password spraying) from a single host.
- Detect unexpected service stops and system errors.
- Flag unusually high event frequencies.
- Classify all alerts by severity.
- Display everything in a professional, dark-themed SOC-style dashboard.
- Allow users to upload their own log CSV files.
- Export results for further analysis.

---

## Features

| Feature | Status |
|---------|--------|
| CSV log upload & preprocessing | ✅ |
| Sample synthetic dataset (143 records) | ✅ |
| Rule 1 – Repeated failed logins | ✅ |
| Rule 2a – Failure burst then success | ✅ |
| Rule 2b – Off-hours successful login | ✅ |
| Rule 3 – Multi-account failures (spraying) | ✅ |
| Rule 4 – Unexpected service stop | ✅ |
| Rule 5 – System error detection (single + repeated) | ✅ |
| Rule 6 – Unusual event frequency | ✅ |
| Severity classification (HIGH/MEDIUM/LOW/INFO) | ✅ |
| Interactive Plotly charts | ✅ |
| Duplicate alert prevention | ✅ |
| Alert filtering by severity / type / user / date | ✅ |
| CSV alert export | ✅ |
| CSV log export | ✅ |
| Configurable thresholds (Settings page) | ✅ |
| Command-line interface (`main.py`) | ✅ |
| Automated pytest unit tests (38+ tests) | ✅ |
| Professional dark SOC-style dashboard | ✅ |

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| Data Processing | pandas, NumPy |
| Dashboard | Streamlit |
| Charts | Plotly |
| Styling | Custom CSS |
| Testing | pytest |
| Data Format | CSV |

---

## Architecture

```
CSV Log File
     │
     ▼
log_processor.py ──► Validate columns
                 ──► Parse timestamps
                 ──► Normalise status/event_type
                 ──► Return clean DataFrame
     │
     ▼
analyzer.py ──► Rule 1: Repeated failed logins
            ──► Rule 2: Suspicious login activity
            ──► Rule 3: Multi-account failures
            ──► Rule 4: Service stop detection
            ──► Rule 5: System error detection
            ──► Rule 6: Unusual event frequency
     │
     ▼
alert_manager.py ──► Build alerts DataFrame
                 ──► Severity classification
                 ──► Filter / export
     │
     ▼
app.py (Streamlit) ──► Overview dashboard
                   ──► Log Analysis page
                   ──► Security Alerts page
                   ──► Event Monitoring page
                   ──► Reports page
                   ──► Settings page
                   ──► About page
```

---

## Project Structure

```
LogGuard/
│
├── app.py                  # Streamlit dashboard (all 7 pages)
├── main.py                 # Command-line entry point
├── analyzer.py             # Anomaly detection rules
├── log_processor.py        # CSV loading, validation, preprocessing
├── alert_manager.py        # Alert creation, filtering, export
├── config.py               # All configurable thresholds
├── generate_sample_data.py # Script to regenerate sample_logs.csv
│
├── data/
│   └── sample_logs.csv     # 143-row synthetic dataset
│
├── reports/                # Auto-generated CSV reports saved here
│
├── assets/
│   └── style.css           # Professional dark SOC theme
│
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py    # 25+ tests for detection rules
│   └── test_log_processor.py # 15+ tests for preprocessing
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Installation

### Prerequisites
- Ubuntu Linux (or any Linux/macOS)
- Python 3.10 or later
- `pip` and `venv`

### Step 1 – Clone or Download

```bash
# If using git
git clone <your-repo-url> LogGuard
cd LogGuard

# Or navigate to the project folder
cd /path/to/LogGuard
```

### Step 2 – Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3 – Install Dependencies

```bash
pip install -r requirements.txt
```

---

## How to Run

### Dashboard (Streamlit)

```bash
# Make sure your venv is active
source .venv/bin/activate

# Start the dashboard
streamlit run app.py
```

The dashboard will open at **http://localhost:8501** in your browser.

### Command-Line Interface

```bash
# Analyse the sample dataset
python3 main.py

# Analyse a custom CSV file
python3 main.py --file path/to/your_logs.csv

# Analyse without saving reports
python3 main.py --no-save

# Help
python3 main.py --help
```

### Run Tests

```bash
pytest tests/ -v
```

---

## How to Upload Logs

1. Open the dashboard at http://localhost:8501
2. Click **"📋 Log Analysis"** in the sidebar
3. Select **"📤 Upload CSV"** tab
4. Click **"Browse files"** and select your CSV

### Required CSV Columns

Your CSV file must have these exact column names (case-insensitive):

| Column | Description | Example |
|--------|-------------|---------|
| `timestamp` | Date and time of the event | `2024-03-15 09:00:00` |
| `host` | Machine hostname | `web-01` |
| `event_type` | Type of event | `login_attempt` |
| `username` | Account involved | `alice` |
| `status` | Outcome | `success`, `failed`, `error` |
| `message` | Human-readable description | `User alice authenticated.` |

### Common Event Types Recognised

- `login_attempt`, `ssh_login`, `auth`
- `service_stopped`, `service_started`
- `system_error`
- `logout`, `password_change`, `sudo_command`
- `file_access`, `cron_job`

---

## Detection Rules

### Rule 1 – Repeated Failed Login Attempts (HIGH)

**What:** Detects when the same username fails to log in 3 or more times within a 10-minute rolling window.

**Why it matters:** This is the classic signature of a brute-force attack.

**Example trigger:** `admin` fails at 09:02, 09:03, 09:04, 09:05, 09:06.

**Configurable:** Threshold and window in Settings page or `config.py`.

---

### Rule 2a – Burst Then Success (HIGH)

**What:** Detects when a user has 2+ failed logins immediately followed by a successful login within the same window.

**Why it matters:** This may indicate a successful credential-stuffing or brute-force attack.

---

### Rule 2b – Off-Hours Successful Login (LOW)

**What:** Flags a successful login that occurs outside configured "normal hours" (default: 08:00–20:00).

**Why it matters:** Legitimate users rarely log in at 03:00; this warrants investigation.

**Configurable:** Can be disabled in Settings. Hours configurable in `config.py`.

---

### Rule 3 – Multiple Account Failures from One Host (HIGH)

**What:** Detects when 3 or more distinct usernames fail to authenticate from the same host within 10 minutes.

**Why it matters:** Classic password-spraying pattern — an attacker tries common passwords against many accounts to avoid lockouts.

---

### Rule 4 – Unexpected Service Stop (MEDIUM / HIGH)

**What:** Flags every `service_stopped` event. If the message contains crash-related keywords (`crash`, `segfault`, `oom`, etc.) the severity is HIGH; otherwise MEDIUM.

---

### Rule 5 – System Error Detection (LOW / MEDIUM)

**What:**
- Individual `system_error` events → LOW alert
- 3+ system errors from the same host within 5 minutes → MEDIUM alert (the individual LOW alerts are suppressed for that burst)

---

### Rule 6 – Unusual Event Frequency (MEDIUM)

**What:** Flags any event type that occurs more than 20 times within a single hour.

**Why it matters:** Sudden spikes in cron jobs, login attempts, or file accesses can indicate automation scripts or attacks.

**Configurable:** Threshold configurable in Settings or `config.py`.

---

## Limitations

- **Rule-based only.** LogGuard uses hand-crafted detection rules, not machine learning. It cannot detect novel attack patterns it was not programmed for.
- **CSV input only.** Real SIEM tools ingest live log streams. LogGuard reads static CSV snapshots.
- **No authentication.** The dashboard has no login. Do not expose it on a public network.
- **No persistent storage.** Alert statuses reset when the app restarts.
- **Educational, not production.** Do not rely on this tool for real security monitoring.

---

## Future Enhancements

| Enhancement | Description |
|-------------|-------------|
| Machine learning detection | Use Isolation Forest or LSTM for anomaly detection |
| Live log streaming | Tail log files in real time |
| Email / Slack alerts | Push notifications for HIGH-severity alerts |
| User authentication | Add login to protect the dashboard |
| Database backend | Store alerts and statuses in SQLite / PostgreSQL |
| GeoIP lookup | Map login sources by country |
| Alert correlation | Link related alerts into incidents |
| Docker packaging | One-command deployment |

---

## Disclaimer

> All sample data in this project is **completely synthetic and fictional**.  
> No real usernames, hostnames, IP addresses, or organisation data are present.  
>
> LogGuard is intended for **educational purposes** and **authorised defensive monitoring only**.  
> Do not use it on systems you do not own or have explicit written permission to monitor.  
> Generated alerts are **indicators for investigation**, not proof of a cyberattack.

---

*LogGuard v1.0.0 · B.Tech CSE Cybersecurity Project*
