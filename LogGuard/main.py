"""
main.py – LogGuard Command-Line Entry Point

Run from the terminal to perform a quick analysis of a log CSV without
opening the Streamlit dashboard:

    python3 main.py                          # uses data/sample_logs.csv
    python3 main.py --file path/to/logs.csv  # custom file
    python3 main.py --help
"""

import argparse
import sys
from pathlib import Path

from log_processor import load_csv_from_path, get_summary_stats
from analyzer import run_all_rules
from alert_manager import build_alerts_df, generate_report_summary, \
    save_alerts_to_file, save_logs_to_file
from config import APP_TITLE, APP_VERSION, APP_TAGLINE


def banner():
    print(f"""
╔══════════════════════════════════════════════════════╗
║          {APP_TITLE} v{APP_VERSION}                           ║
║          {APP_TAGLINE}  ║
╚══════════════════════════════════════════════════════╝
""")


def run(file_path: str, save_reports: bool = True):
    banner()

    result = load_csv_from_path(file_path)
    if not result["success"]:
        print(f"[ERROR] {result['error']}")
        sys.exit(1)

    df      = result["df"]
    summary = result["summary"]

    print(f"[INFO] Loaded {summary['total_rows']} rows | "
          f"{summary['clean_rows']} clean | "
          f"{summary['rejected_rows']} rejected")
    print(f"[INFO] Time range: {summary['time_range_start']} → "
          f"{summary['time_range_end']}")
    print(f"[INFO] Unique users: {summary['unique_users']} | "
          f"Unique hosts: {summary['unique_hosts']}\n")

    # Run detection
    print("[INFO] Running anomaly detection rules …")
    raw_alerts = run_all_rules(df)
    alerts_df  = build_alerts_df(raw_alerts)

    # Print alert table
    if alerts_df.empty:
        print("[OK] No alerts generated.")
    else:
        print(f"[ALERT] {len(alerts_df)} alert(s) generated:\n")
        for _, row in alerts_df.iterrows():
            print(f"  [{row['severity']:6s}] {row['alert_id']} | "
                  f"{row['timestamp']} | {row['username']} | "
                  f"{row['detection_rule']}")
            print(f"           {row['description']}\n")

    # Stats
    stats = get_summary_stats(df)
    print("\n── Summary ─────────────────────────────────────────")
    print(f"  Total logs        : {stats.get('total_logs', 0)}")
    print(f"  Successful logins : {stats.get('successful_logins', 0)}")
    print(f"  Failed logins     : {stats.get('failed_logins', 0)}")
    print(f"  System errors     : {stats.get('system_errors', 0)}")
    print(f"  Total alerts      : {len(alerts_df)}")
    if not alerts_df.empty:
        sev = alerts_df["severity"].value_counts()
        for s in ["HIGH", "MEDIUM", "LOW", "INFO"]:
            if s in sev:
                print(f"    {s:8s}: {sev[s]}")
    print("────────────────────────────────────────────────────\n")

    # Save reports
    if save_reports:
        a_path = save_alerts_to_file(alerts_df)
        l_path = save_logs_to_file(df)
        print(f"[INFO] Alerts saved to  : {a_path}")
        print(f"[INFO] Logs saved to    : {l_path}")


def main():
    parser = argparse.ArgumentParser(
        description=f"{APP_TITLE} – Command-line log analyser"
    )
    parser.add_argument(
        "--file", "-f",
        default="data/sample_logs.csv",
        help="Path to the CSV log file (default: data/sample_logs.csv)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save report files",
    )
    args = parser.parse_args()
    run(args.file, save_reports=not args.no_save)


if __name__ == "__main__":
    main()
