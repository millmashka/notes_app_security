# siem_monitor.py
import time
import re
import os
from collections import deque, defaultdict
from datetime import datetime, timedelta

LOG_PATH = "flask_app.log"
ALERT_LOG = "security_alerts.log"
REPORT_FILE = "daily_security_report.txt"

# шаблоны SQL-инъекций
SQL_PATTERNS = [
    re.compile(r"(\bOR\b\s+1=1)", re.IGNORECASE),
    re.compile(r"UNION\s+SELECT", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE)
]

# защищённые пути
PROTECTED_PATHS = ["/admin", "/api/delete"]

# окно для подсчёта попыток входа (в секундах)
FAILED_LOGIN_WINDOW = 60
FAILED_LOGIN_THRESHOLD = 5

# хранение неудачных логинов: ip -> deque of timestamps
failed_logins = defaultdict(deque)

# метрики для отчёта
metrics = {
    "processed_lines": 0,
    "incidents": []
}

def tail_follow(file):
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def write_alert(record):
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(record + "\n")

def color_print_red(msg):
    # простая окраска для Windows поддерживаемые escape последовательности
    print(f"\033[31m{msg}\033[0m")

def color_print_yellow(msg):
    print(f"\033[33m{msg}\033[0m")

def process_line(line):
    metrics["processed_lines"] += 1
    now = datetime.utcnow()

    lower = line.lower()
    # 1) LOGIN_FAILED detection (по нашему формату логов "LOGIN_FAILED ip=...")
    if "login_failed" in lower:
        m = re.search(r"ip=([\d\.]+)", line)
        ip = m.group(1) if m else "unknown"
        failed_logins[ip].append(now)
        # очистка старых записей
        while failed_logins[ip] and (now - failed_logins[ip][0]).total_seconds() > FAILED_LOGIN_WINDOW:
            failed_logins[ip].popleft()
        if len(failed_logins[ip]) >= FAILED_LOGIN_THRESHOLD:
            alert = f"{datetime.utcnow().isoformat()} ALERT MULTI_FAILED_LOGIN ip={ip} count={len(failed_logins[ip])}"
            write_alert(alert)
            color_print_red(alert)
            metrics["incidents"].append({"time": now.isoformat(), "type": "MULTI_FAILED_LOGIN", "ip": ip})
            # очистим чтобы не дублировать
            failed_logins[ip].clear()
        return

    # 2) SQL patterns in NOTE_CREATE or raw content
    if "note_create" in lower or "content=" in lower:
        for p in SQL_PATTERNS:
            if p.search(line):
                alert = f"{datetime.utcnow().isoformat()} ALERT SQL_INJECTION_PATTERN detected line={line.strip()[:300]}"
                write_alert(alert)
                color_print_red(alert)
                metrics["incidents"].append({"time": now.isoformat(), "type": "SQL_PATTERN", "line": line.strip()[:300]})
                return

    # 3) Protected endpoint access (we look for GET/POST lines or our custom logs)
    # Example of WSGI log line contains "GET /admin HTTP/1.1" or our custom logs contain path
    for path in PROTECTED_PATHS:
        if f" {path} " in line or f" {path}?" in line:
            alert = f"{datetime.utcnow().isoformat()} ALERT PROTECTED_PATH_ACCESSED path={path} line={line.strip()[:200]}"
            write_alert(alert)
            color_print_yellow(alert)
            metrics["incidents"].append({"time": now.isoformat(), "type": "PROTECTED_PATH", "path": path})
            return

def generate_daily_report():
    lines = []
    lines.append(f"Daily security report generated at {datetime.utcnow().isoformat()}")
    lines.append(f"Processed log lines: {metrics['processed_lines']}")
    lines.append(f"Total incidents detected: {len(metrics['incidents'])}")
    lines.append("")
    lines.append("Incidents detail:")
    for it in metrics["incidents"]:
        lines.append(str(it))
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Daily report written to {REPORT_FILE}")

def main():
    if not os.path.exists(LOG_PATH):
        print(f"Log file {LOG_PATH} not found. Start your app first.")
        return

    print("Starting SIEM monitor, following", LOG_PATH)
    with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        follower = tail_follow(f)
        try:
            for line in follower:
                process_line(line)
        except KeyboardInterrupt:
            print("Interrupted. Generating daily report...")
            generate_daily_report()

if __name__ == "__main__":
    main()
