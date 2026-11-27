"""
generate_sample_data.py – run once to regenerate data/sample_logs.csv
(Not part of the main app; kept for reproducibility.)

All usernames, hostnames, and IP-like identifiers in this dataset are
completely fictional and synthetic.  No real user data is present.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

USERS   = ["alice", "bob", "carol", "dave", "eve", "frank", "grace",
           "heidi", "ivan", "judy", "root", "admin", "sysop", "deployer"]
HOSTS   = ["web-01", "web-02", "db-01", "db-02", "app-srv-01",
           "app-srv-02", "cache-01", "monitor-01", "bastion-01"]
SERVICES = ["nginx", "postgresql", "redis", "sshd", "logrotate",
            "cron", "appserver", "memcached"]

EVENT_TEMPLATES = {
    "login_attempt": {
        "success": "User {user} authenticated successfully via {proto}.",
        "failed" : "Authentication failed for user {user} via {proto}.",
    },
    "ssh_login": {
        "success": "Accepted password for {user} from 10.0.{a}.{b} port {port}.",
        "failed" : "Failed password for {user} from 10.0.{a}.{b} port {port}.",
    },
    "service_started": {
        "success": "Service {svc} started successfully (PID {pid}).",
    },
    "service_stopped": {
        "success": "Service {svc} stopped gracefully.",
        "error"  : "Service {svc} stopped unexpectedly – check logs (crash detected).",
    },
    "system_error": {
        "error"  : "Kernel: I/O error on device sda1, sector {sec}.",
        "failed" : "Process {pid} terminated with signal 11 (segfault).",
    },
    "logout": {
        "success": "User {user} logged out. Session duration {dur}s.",
    },
    "password_change": {
        "success": "Password changed successfully for {user}.",
        "failed" : "Password change failed for {user}: policy violation.",
    },
    "sudo_command": {
        "success": "sudo: {user} ran command /usr/bin/{cmd} as root.",
        "failed" : "sudo: {user} denied – not in sudoers file.",
    },
    "file_access": {
        "success": "File /var/log/{file} accessed by {user}.",
    },
    "cron_job": {
        "success": "Cron job '{job}' completed successfully.",
        "error"  : "Cron job '{job}' failed with exit code 1.",
    },
}

PROTOS = ["SSH", "PAM", "LDAP"]
CMDS   = ["apt", "systemctl", "passwd", "useradd", "visudo"]
FILES  = ["syslog", "auth.log", "nginx/access.log", "cron"]
JOBS   = ["backup_db", "rotate_logs", "sync_config", "health_check"]


def rnd_msg(event_type, status, user, host):
    templates = EVENT_TEMPLATES.get(event_type, {})
    tmpl = templates.get(status, templates.get(list(templates.keys())[0], "Event: {event}."))
    return tmpl.format(
        user=user, host=host, proto=random.choice(PROTOS),
        a=random.randint(1, 10), b=random.randint(1, 254),
        port=random.randint(1024, 65535), svc=random.choice(SERVICES),
        pid=random.randint(100, 32000), sec=random.randint(1000, 99999),
        dur=random.randint(10, 3600), cmd=random.choice(CMDS),
        file=random.choice(FILES), job=random.choice(JOBS),
        event=event_type,
    )


rows = []
base = datetime(2024, 3, 15, 8, 0, 0)


def add(dt, host, event_type, user, status, msg=None):
    rows.append({
        "timestamp" : dt.strftime("%Y-%m-%d %H:%M:%S"),
        "host"      : host,
        "event_type": event_type,
        "username"  : user,
        "status"    : status,
        "message"   : msg or rnd_msg(event_type, status, user, host),
    })


# ── NORMAL MORNING ACTIVITY ──────────────────────────────────────────────
t = base
for user in ["alice", "bob", "carol", "dave", "grace"]:
    t += timedelta(minutes=random.randint(1, 5))
    add(t, random.choice(HOSTS[:3]), "login_attempt", user, "success")
    t += timedelta(minutes=random.randint(5, 20))
    add(t, random.choice(HOSTS[:3]), "file_access", user, "success")

# ── RULE 1: REPEATED FAILED LOGINS (admin, 5 failures, 3 min window) ─────
t = base + timedelta(hours=1)
for i in range(5):
    t += timedelta(minutes=1)
    add(t, "bastion-01", "login_attempt", "admin",
        "failed", f"Authentication failed for admin – attempt {i+1}.")

# ── RULE 2a: BURST THEN SUCCESS (eve, 3 failures then success) ───────────
t = base + timedelta(hours=1, minutes=20)
for _ in range(3):
    t += timedelta(minutes=2)
    add(t, "app-srv-01", "ssh_login", "eve", "failed")
t += timedelta(minutes=1)
add(t, "app-srv-01", "ssh_login", "eve", "success",
    "Accepted password for eve after retry.")

# ── RULE 3: MULTI-ACCOUNT FAILURES (from db-01) ──────────────────────────
t = base + timedelta(hours=2)
spray_users = ["root", "admin", "sysop", "deployer", "frank"]
for u in spray_users:
    t += timedelta(minutes=1)
    add(t, "db-01", "ssh_login", u, "failed",
        f"Failed password for {u} from 192.168.1.42 – possible spray.")

# ── RULE 4: SERVICE STOPS ─────────────────────────────────────────────────
t = base + timedelta(hours=3)
add(t, "web-01", "service_stopped", "sysop", "error",
    "Service nginx stopped unexpectedly – crash detected (segfault).")
t += timedelta(minutes=30)
add(t, "db-02", "service_stopped", "root", "success",
    "Service postgresql stopped gracefully for maintenance.")

# ── RULE 5: REPEATED SYSTEM ERRORS (cache-01, 4 errors in 4 min) ─────────
t = base + timedelta(hours=3, minutes=45)
for _ in range(4):
    t += timedelta(minutes=1)
    add(t, "cache-01", "system_error", "system", "error",
        "Redis OOM – killed process to free memory.")

# Single system errors on other hosts
add(base + timedelta(hours=4, minutes=10),
    "monitor-01", "system_error", "system", "error",
    "Disk I/O error detected on /dev/sdb1.")

# ── RULE 2b: OFF-HOURS LOGIN (ivan at 02:30) ──────────────────────────────
off_time = base + timedelta(hours=18, minutes=30)   # 02:30 next day
add(off_time, "bastion-01", "login_attempt", "ivan", "success",
    "User ivan logged in successfully at 02:30 from 10.0.9.55.")

# ── NORMAL AFTERNOON ACTIVITY ────────────────────────────────────────────
t = base + timedelta(hours=4, minutes=30)
for _ in range(30):
    t += timedelta(minutes=random.randint(1, 8))
    user  = random.choice(USERS[:8])
    host  = random.choice(HOSTS)
    etype = random.choice(["login_attempt", "logout", "file_access",
                           "sudo_command", "cron_job", "ssh_login"])
    # Mostly successes, occasional failures
    status = "success" if random.random() > 0.15 else "failed"
    add(t, host, etype, user, status)

# ── RULE 1 (second burst): heidi fails 4 times ───────────────────────────
t = base + timedelta(hours=6)
for _ in range(4):
    t += timedelta(minutes=1, seconds=30)
    add(t, "app-srv-02", "login_attempt", "heidi", "failed",
        "Authentication failed for heidi (incorrect password).")

# ── SERVICE STARTED / NORMAL OPS ─────────────────────────────────────────
t = base + timedelta(hours=6, minutes=30)
for svc in SERVICES[:4]:
    t += timedelta(minutes=5)
    add(t, random.choice(HOSTS), "service_started", "root", "success",
        f"Service {svc} started successfully.")

# ── PASSWORD CHANGES ──────────────────────────────────────────────────────
t = base + timedelta(hours=7)
for user in ["alice", "carol", "dave"]:
    t += timedelta(minutes=10)
    add(t, "web-01", "password_change", user, "success")

# ── RULE 6: HIGH FREQUENCY EVENT (25 cron events in one hour) ────────────
t = base + timedelta(hours=8)
for i in range(25):
    t += timedelta(minutes=2)
    add(t, "monitor-01", "cron_job", "root",
        "success" if i % 5 != 0 else "error",
        f"Cron job 'health_check' iteration {i+1}.")

# ── MORE NORMAL EVENTS ────────────────────────────────────────────────────
t = base + timedelta(hours=9)
for _ in range(40):
    t += timedelta(minutes=random.randint(1, 5))
    user  = random.choice(USERS)
    host  = random.choice(HOSTS)
    etype = random.choice(list(EVENT_TEMPLATES.keys()))
    status_opts = list(EVENT_TEMPLATES[etype].keys())
    status = random.choice(status_opts)
    add(t, host, etype, user, status)

# ── ANOTHER MULTI-ACCOUNT SPRAY (from app-srv-02) ─────────────────────────
t = base + timedelta(hours=10)
for u in ["judy", "heidi", "ivan", "grace", "frank"]:
    t += timedelta(seconds=90)
    add(t, "app-srv-02", "login_attempt", u, "failed",
        f"Failed login for {u} – automated sweep suspected.")

# Sort and write
rows.sort(key=lambda r: r["timestamp"])

Path("data").mkdir(exist_ok=True)
out = Path("data/sample_logs.csv")
with out.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["timestamp","host","event_type",
                                            "username","status","message"])
    writer.writeheader()
    writer.writerows(rows)

print(f"Written {len(rows)} rows to {out}")
