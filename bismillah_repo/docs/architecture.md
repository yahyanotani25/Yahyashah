# Bismillah v4.0 Architecture

This document describes the overall design:

1. **Core Dispatcher (`bismillah.py`)**  
   - Loads encrypted modules  
   - Starts background loops  
   - Polls AI‑C2 queue & routes tasks  

2. **Module Hierarchy**  
   - `modules/config.py` → dynamic config  
   - `modules/logger.py` → encrypted logging  
   - `modules/obfuscation.py` + `modules/loader.py` → AES‑GCM module encryption/hot‑load  
   - `modules/ai_c2.py` → LLM tasking  
   - `modules/c2_server.py`, `dns_c2_server.py`, `icmp_c2.py` → multi‑channel C2  
   - `modules/reconnaissance_ext.py` → Nmap/Shodan/DNS/Wi‑Fi/PassiveDNS/ARP  
   - `modules/lateral_movement.py` → SSH pivot, RDP brute, SMB spread, Kerberos, WMI  
   - `modules/persistence_ext.py` → Linux systemd/udev, Windows Task/Run key, macOS LaunchDaemon  
   - `modules/stealth_ext.py`, `modules/anti_forensics_ext.py` → AV kill, log wiping, rootkit unload, dmesg clear  
   - `modules/keylogger_ext.py` → keystroke capture, clipboard sniffer, screen capture  
   - `modules/exploit_manager.py` + `modules/automatic_cve_fetcher.py` → PoC integrity & auto‑fetch  
   - `modules/supply_chain.py` → npm/pip/Maven poisoning  
   - `modules/cloud_api_compromise.py` → AWS IMDSv2, Azure MSI, GCP metadata  

3. **Exploit Library (`modules/exploit_lib/`)**  
   - `cve_2019_0708_bluekeep.py`, `bluekeep_poc.py`  
   - `cve_2020_0796.py`, `smbghost_poc.py`  
   - `cve_2021_26855_proxylogon.py`  
   - `cve_2021_21985_vmware_vcenter.py`  
   - `cve_2021_34527_printnightmare.py`, `printnightmare_poc.py`  
   - `cve_2021_44228_log4j.py`  
   - `cve_2022_30190_follina.py`  

4. **Kernel & Firmware**  
   - `kernel_rootkit/sardar_rootkit.c` → LKM rootkit with integrity checks  
   - `uefi_bootkit/payload_uefi.c` → UEFI bootkit with SecureBoot evasion  

5. **Windows Payloads**  
   - `windows_payloads/service_backdoor.c`  
   - `windows_payloads/reg_hijack.c`  
   - `windows_payloads/com_handler_regsvr.c`  

6. **macOS Payloads**  
   - `macos_payloads/launchd_persistence.sh`  
   - `macos_payloads/tcc_allowlist_bypass.c`  
   - `macos_payloads/mem_malware.c`  

7. **Tools**  
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
