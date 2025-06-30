# modules/location_ext.py

import threading
import requests
import os
import json
import time
import socket
from modules.logger import log_event

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
DEFAULT_INTERVAL = 300
GEOLOG_PATH = os.path.join(os.path.expanduser("~"), "ip_geolocations.json")

# ──────────────────────────────────────────────────────────────────────────────

def is_internet_available(host="8.8.8.8", port=53, timeout=3) -> bool:
    """
    Quick check to see if we can reach the internet (default: Google DNS).
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except Exception:
        return False

def geolocate_ip_ipinfo(ip: str = None) -> dict:
    """
    Query ipinfo.io for geolocation. Returns parsed JSON or {} on failure.
    """
    url = "https://ipinfo.io"
    if ip:
        url += f"/{ip}"
    url += "/json"
    headers = {}
    if IPINFO_TOKEN:
        headers["Authorization"] = f"Bearer {IPINFO_TOKEN}"
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        data = resp.json()
        if "bogon" in data or data.get("error"):
            return {}
        return data
    except Exception as e:
        log_event({"type": "geolocate_ipinfo_failed", "error": str(e)})
        return {}

def geolocate_ip_ipapi(ip: str = None) -> dict:
    """
    Fallback to ip-api.com (free, no token). Rate-limited to 45 req/min.
    Returns parsed JSON or {} on failure.
    """
    target = ip if ip else ""
    url = f"http://ip-api.com/json/{target}"
    try:
        resp = requests.get(url, timeout=5)
        data = resp.json()
        if data.get("status") != "success":
            return {}
        return data
    except Exception as e:
        log_event({"type": "geolocate_ipapi_failed", "error": str(e)})
        return {}

def geolocate_ip(ip: str = None) -> dict:
    """
    Try ipinfo.io first; if it fails or returns empty, fallback to ip-api.com.
    """
    if not is_internet_available():
        return {}
    data = geolocate_ip_ipinfo(ip)
    if data:
        return data
    return geolocate_ip_ipapi(ip)

def save_geolocation(data: dict):
    """
    Append a timestamped geolocation entry to GEOLOG_PATH.
    """
    entry = {
        "timestamp": int(time.time()),
        "data": data
    }
    os.makedirs(os.path.dirname(GEOLOG_PATH), exist_ok=True)
    try:
        if os.path.exists(GEOLOG_PATH):
            with open(GEOLOG_PATH, "r+", encoding="utf-8") as f:
                arr = json.load(f)
                arr.append(entry)
                f.seek(0)
                json.dump(arr, f, indent=2)
        else:
            with open(GEOLOG_PATH, "w", encoding="utf-8") as f:
                json.dump([entry], f, indent=2)
        log_event({"type": "geolocate_success", "ip": data.get("ip", "")})
    except Exception as e:
        # Overwrite if file is malformed
        with open(GEOLOG_PATH, "w", encoding="utf-8") as f:
            json.dump([entry], f, indent=2)
        log_event({"type": "geolocate_success", "ip": data.get("ip", "")})

def continuous_geolocate(interval: int = DEFAULT_INTERVAL):
    """
    Every 'interval' seconds, fetch the public IP’s geolocation and save it.
    """
    while True:
        data = geolocate_ip(None)
        if data:
            save_geolocation(data)
        time.sleep(interval)

def start_location_tracker(interval: int = DEFAULT_INTERVAL):
    """
    Start a daemon thread that logs geolocation every 'interval' seconds.
    Returns the Thread object.
    """
    t = threading.Thread(target=continuous_geolocate, args=(interval,), daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    print(f"[+] Geolocating public IP …")
    info = geolocate_ip(None)
    if info:
        print(json.dumps(info, indent=2))
    else:
        print("[!] Geolocation failed (no internet or API error).")
