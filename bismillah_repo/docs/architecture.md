# Bismillah v5.0 Architecture (Enhanced)

## Overview

Bismillah is a state-level, modular, multi-platform APT framework for red team and advanced research. It is designed for maximum stealth, persistence, and offensive capability, with full automation, hot-swapping, and rapid weaponization.

---

## 1. Core Dispatcher (`bismillah.py`)
  - Loads and decrypts modules on demand (AES-GCM, hot-swap)
  - Starts background threads for C2, recon, persistence, lateral movement, post-exploit, anti-forensics, and AI
  - Polls AI‑C2 queue (GPT-4, local LLMs) & routes tasks
  - Supports CLI, C2, and P2P tasking
  - Auto-updates modules and exploits from remote repo

## 2. Module Hierarchy
  - `modules/config.py` → dynamic, hot-reloadable config
  - `modules/logger.py` → encrypted, rotating logging (SQLite, syslog, remote)
  - `modules/obfuscation.py` + `modules/loader.py` → AES‑GCM module encryption, morphing, and in-memory decryption
  - `modules/ai_c2.py` → LLM/AI-driven autonomous C2, tasking, and self-healing
  - `modules/c2_server.py`, `dns_c2_server.py`, `icmp_c2.py` → multi‑channel C2 (WebSocket, HTTP, DNS, ICMP, P2P)
  - `modules/reconnaissance_ext.py` → Nmap, Shodan, DNS, Wi‑Fi, PassiveDNS, ARP, IoT, BLE, cloud
  - `modules/lateral_movement.py` → SSH pivot, RDP brute, SMB spread, Kerberos, WMI, supply chain
  - `modules/persistence_ext.py` → Linux systemd/udev, Windows Task/Run key, macOS LaunchDaemon, UEFI, rootkit
  - `modules/stealth_ext.py`, `modules/anti_forensics_ext.py` → AV/EDR kill, log wiping, rootkit unload, dmesg clear, timestomping
  - `modules/keylogger_ext.py` → keystroke capture, clipboard sniffer, screen capture, exfiltration
  - `modules/exploit_manager.py` + `modules/automatic_cve_fetcher.py` → PoC integrity, auto‑fetch, hot-swap, and integrity check
  - `modules/supply_chain.py` → npm/pip/Maven/NuGet poisoning, version bump, MITM delivery
  - `modules/cloud_api_compromise.py` → AWS IMDSv2, Azure MSI, GCP metadata, S3/Blob/GCS exfiltration
  - `modules/post_exploit_ext.py` → privilege escalation, credential dump, data exfiltration
  - `modules/advanced_evasion.py` → sandbox, VM, and EDR evasion

## 3. Exploit Library (`modules/exploit_lib/`)
  - Dozens of PoCs for major CVEs (BlueKeep, SMBGhost, ProxyLogon, PrintNightmare, Log4Shell, Follina, etc)
  - Auto-fetch and verify new exploits from remote repo
  - Hot-swap and auto-index for rapid deployment

## 4. Kernel & Firmware
  - `kernel_rootkit/sardar_rootkit.c` → LKM rootkit (process/file/network hiding, syscall hooks, integrity checks)
  - `uefi_bootkit/payload_uefi.c` → UEFI bootkit (SecureBoot evasion, boot persistence)

## 5. Windows Payloads
  - `windows_payloads/service_backdoor.c` → process hollowing, recovery actions
  - `windows_payloads/reg_hijack.c` → registry hijack, persistence
  - `windows_payloads/com_handler_regsvr.c` → COM handler hijack

## 6. macOS Payloads
  - `macos_payloads/launchd_persistence.sh` → launchd/LaunchDaemon persistence
  - `macos_payloads/tcc_allowlist_bypass.c` → TCC bypass for camera/mic
  - `macos_payloads/mem_malware.c` → in-memory malware loader

## 7. Tools
  - `tools/shellcode_gen.py` → polymorphic shellcode generator (C, PowerShell)
  - `tools/update_exploit_index.py` → PoC integrity JSON, auto-index
  - `tools/mitm_sslstrip.py` → HTTPS MitM/SSL Strip
  - `tools/run_tests.sh` → wrapper to run all `tests/*.py`
  - `tools/c2_server.py` → full-featured C2 server (WebSocket, HTTP, task queue)

## 8. Tests (`tests/`)
  - `test_exploits.py` → exploit PoC sanity tests
  - `test_c2.py` → ICMP C2 queue tests
  - `test_persistence.py` → dummy persistence checks

## 9. Documentation (`docs/`)
  - `architecture.md` → this file
  - `setup.md` → installation, dependencies, C code compile
  - `usage.md` → run instructions, adding exploits, payload delivery

## 10. CI/CD Pipeline
  - Example `.github/workflows/ci.yml` for GitHub Actions
  - Automated build, test, and lint for all modules and tools

## 11. Operational Security & Extensibility
  - All modules are hot-swappable, encrypted, and can be updated remotely
  - Supports rapid weaponization and custom module addition
  - Designed for red team, blue team, and APT simulation
  - Future: add ethical controls, blue team detection, and auto-remediation

---

## Capabilities Matrix

| Capability                | Linux | Windows | macOS | Cloud | IoT |
|---------------------------|:-----:|:-------:|:-----:|:-----:|:---:|
| C2 (WebSocket/HTTP/DNS)   |   ✔   |    ✔    |   ✔   |   ✔   |  ✔  |
| Kernel/UEFI Persistence   |   ✔   |    ✔    |   ✔   |   ✖   |  ✖  |
| Supply Chain Poisoning    |   ✔   |    ✔    |   ✔   |   ✔   |  ✔  |
| Cloud API Compromise      |   ✔   |    ✔    |   ✔   |   ✔   |  ✖  |
| Keylogger/Screenshot      |   ✔   |    ✔    |   ✔   |   ✖   |  ✖  |
| Lateral Movement          |   ✔   |    ✔    |   ✔   |   ✔   |  ✔  |
| Anti-Forensics/Stealth    |   ✔   |    ✔    |   ✔   |   ✔   |  ✔  |
| DDoS/Ransomware/Miner     |   ✔   |    ✔    |   ✔   |   ✖   |  ✖  |
| BLE/IoT/Network Attacks   |   ✔   |    ✔    |   ✔   |   ✖   |  ✔  |

---

## Danger Level

**★★★★★ (5/5) — State-level, full-spectrum APT framework.**

This tool is now more powerful, modular, and dangerous than ever before. It is suitable for advanced red team, APT simulation, and research in highly controlled environments only.
   - `tools/shellcode_gen.py` → polymorphic shellcode  
   - `tools/update_exploit_index.py` → PoC integrity JSON  
   - `tools/mitm_sslstrip.py` → HTTPS MitM/SSL Strip  
   - `tools/run_tests.sh` → wrapper to run all `tests/*.py`

8. **Tests (`tests/`)**  
   - `test_exploits.py` → exploit PoC sanity tests  
   - `test_c2.py` → ICMP C2 queue tests  
   - `test_persistence.py` → dummy persistence checks  

9. **Documentation (`docs/`)**  
   - `architecture.md` → this file  
   - `setup.md` → installation steps, dependencies, compile instructions for C code  
   - `usage.md` → how to run, how to add new exploits, how to deliver payloads  

10. **CI Pipeline**  
   (Example `.github/workflows/ci.yml` for GitHub Actions)
   ```yaml
   name: CI

   on: [push, pull_request]

   jobs:
     build-and-test:
       runs-on: ubuntu-latest
       steps:
       - uses: actions/checkout@v3
       - name: Set up Python
         uses: actions/setup-python@v4
         with:
           python-version: 3.10
       - name: Install Dependencies
         run: |
           sudo apt-get update
           sudo apt-get install -y libssl-dev libffi-dev build-essential python3-dev python3-pip
           pip install --upgrade pip
           pip install -r requirements.txt
       - name: Run Unit Tests
         run: |
           chmod +x tools/run_tests.sh
           tools/run_tests.sh
       - name: Lint
         run: |
           pip install flake8
           flake8 modules/ tools/ bismillah.py
