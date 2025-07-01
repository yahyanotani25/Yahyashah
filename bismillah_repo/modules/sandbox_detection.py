import logging
import os
import platform
import subprocess
import psutil
import time
import ctypes
from typing import Dict, List, Tuple

class SandboxDetectionEngine:
    """
    Comprehensive sandbox and VM detection engine.
    Detects various analysis environments, virtual machines, and sandboxes.
    """
    def __init__(self):
        self.logger = logging.getLogger("SandboxDetectionEngine")
        self.detection_results = {}
        self.sandbox_indicators = []

    def detect_sandbox(self) -> bool:
        """
        Comprehensive sandbox detection using multiple techniques.
        Returns True if sandbox/VM is detected.
        """
        self.logger.info("[Sandbox] Starting comprehensive sandbox detection...")
        
        # Reset results
        self.detection_results = {}
        self.sandbox_indicators = []
        
        # Run all detection methods
        detection_methods = [
            self._check_vm_artifacts,
            self._check_vm_processes,
            self._check_vm_registry,
            self._check_vm_drivers,
            self._check_vm_services,
            self._check_vm_files,
            self._check_vm_network,
            self._check_vm_hardware,
            self._check_sandbox_artifacts,
            self._check_analysis_tools,
            self._check_debugger_presence,
            self._check_timing_anomalies,
            self._check_user_interaction,
            self._check_system_characteristics
        ]
        
        for method in detection_methods:
            try:
                result = method()
                if result:
                    self.sandbox_indicators.append(result)
            except Exception as e:
                self.logger.debug(f"[Sandbox] Detection method {method.__name__} failed: {e}")
        
        # Calculate detection score
        detection_score = len(self.sandbox_indicators)
        is_sandbox = detection_score >= 3  # Threshold for sandbox detection
        
        self.logger.info(f"[Sandbox] Detection complete. Score: {detection_score}/14, Sandbox detected: {is_sandbox}")
        if self.sandbox_indicators:
            self.logger.warning(f"[Sandbox] Indicators found: {', '.join(self.sandbox_indicators)}")
        
        return is_sandbox

    def _check_vm_artifacts(self) -> str:
        """Check for VM-specific artifacts and files"""
        vm_artifacts = {
            "Linux": [
                "/.dockerenv", "/.containerenv", "/proc/scsi/scsi",
                "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/chassis_vendor",
                "/proc/cpuinfo", "/proc/meminfo", "/proc/version"
            ],
            "Windows": [
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f5630a-b6bf-11d0-94f2-00a0c91efb8b}"
            ],
            "Darwin": [
                "/System/Library/Extensions/IOUSBHostFamily.kext",
                "/System/Library/Extensions/IOUSBMassStorageClass.kext"
            ]
        }
        
        system = platform.system()
        artifacts = vm_artifacts.get(system, [])
        
        for artifact in artifacts:
            if system == "Linux" and os.path.exists(artifact):
                try:
                    if artifact == "/sys/class/dmi/id/product_name":
                        with open(artifact, 'r') as f:
                            content = f.read().lower()
                            vm_indicators = ["virtualbox", "vmware", "qemu", "kvm", "hyperv", "parallels", "xen", "bochs"]
                            if any(indicator in content for indicator in vm_indicators):
                                return f"VM product detected: {content.strip()}"
                    elif artifact == "/proc/cpuinfo":
                        with open(artifact, 'r') as f:
                            content = f.read().lower()
                            if "hypervisor" in content or "vmware" in content or "virtualbox" in content:
                                return "VM hypervisor detected in CPU info"
                    else:
                        return f"VM artifact found: {artifact}"
                except Exception:
                    continue
            elif system == "Windows":
                try:
                    import winreg
                    key_path = artifact.replace("HKLM\\", "")
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                    winreg.CloseKey(key)
                    return f"VM registry key found: {artifact}"
                except Exception:
                    continue
        
        return None

    def _check_vm_processes(self) -> str:
        """Check for VM-related processes"""
        vm_processes = {
            "vmtoolsd", "vboxservice", "vboxtray", "vmusr", "vmscsi", "vmscsi.sys",
            "vboxguest", "vboxsf", "vboxvideo", "vboxmouse", "vboxaudio",
            "vmwaretray", "vmwareuser", "vmware-authd", "vmware-vmx",
            "qemu-ga", "qemu-guest-agent", "spice-vdagentd",
            "hv_vmbus", "hv_balloon", "hv_netvsc", "hv_storvsc",
            "xenbus", "xenconsoled", "xenstored", "xenwatch"
        }
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() in vm_processes:
                    return f"VM process detected: {proc.info['name']} (PID: {proc.info['pid']})"
        except Exception as e:
            self.logger.debug(f"[Sandbox] Process check failed: {e}")
        
        return None

    def _check_vm_registry(self) -> str:
        """Check Windows registry for VM indicators"""
        if platform.system() != "Windows":
            return None
            
        try:
            import winreg
            
            vm_registry_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000", "ProviderName"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000", "UserModeDriverGUID"),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier"),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\SystemBiosVersion", ""),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\VideoBiosVersion", "")
            ]
            
            for hkey, subkey, value_name in vm_registry_keys:
                try:
                    key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                    if value_name:
                        value, _ = winreg.QueryValueEx(key, value_name)
                        vm_indicators = ["vmware", "virtualbox", "qemu", "vbox", "hv_vmbus"]
                        if any(indicator.lower() in str(value).lower() for indicator in vm_indicators):
                            winreg.CloseKey(key)
                            return f"VM registry value detected: {value}"
                    winreg.CloseKey(key)
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"[Sandbox] Registry check failed: {e}")
        
        return None

    def _check_vm_drivers(self) -> str:
        """Check for VM-specific drivers"""
        if platform.system() != "Windows":
            return None
            
        vm_drivers = [
            "vboxguest.sys", "vboxmouse.sys", "vboxsf.sys", "vboxvideo.sys",
            "vmci.sys", "vmhgfs.sys", "vmmouse.sys", "vmscsi.sys", "vmusb.sys",
            "hv_vmbus.sys", "hv_balloon.sys", "hv_netvsc.sys", "hv_storvsc.sys",
            "xenbus.sys", "xennet.sys", "xenvbd.sys"
        ]
        
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", 0, winreg.KEY_READ)
            
            for driver in vm_drivers:
                try:
                    driver_key = winreg.OpenKey(key, driver.replace('.sys', ''), 0, winreg.KEY_READ)
                    winreg.CloseKey(driver_key)
                    return f"VM driver detected: {driver}"
                except Exception:
                    continue
                    
            winreg.CloseKey(key)
        except Exception as e:
            self.logger.debug(f"[Sandbox] Driver check failed: {e}")
        
        return None

    def _check_vm_services(self) -> str:
        """Check for VM-related services"""
        vm_services = [
            "VBoxGuest", "VBoxMouse", "VBoxService", "VBoxSF", "VBoxVideo",
            "VMwareGuest", "VMwareMouse", "VMwareService", "VMwareSF", "VMwareVideo",
            "hv_vmbus", "hv_balloon", "hv_netvsc", "hv_storvsc",
            "xenbus", "xennet", "xenvbd"
        ]
        
        try:
            for service in vm_services:
                try:
                    if platform.system() == "Windows":
                        import winreg
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Services\\{service}", 0, winreg.KEY_READ)
                        winreg.CloseKey(key)
                        return f"VM service detected: {service}"
                    else:
                        # Check if service exists in systemd
                        result = subprocess.run(['systemctl', 'list-unit-files', f'{service}.service'], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0 and service in result.stdout:
                            return f"VM service detected: {service}"
                except Exception:
                    continue
        except Exception as e:
            self.logger.debug(f"[Sandbox] Service check failed: {e}")
        
        return None

    def _check_vm_files(self) -> str:
        """Check for VM-specific files and directories"""
        vm_files = {
            "Linux": [
                "/usr/bin/VBoxClient", "/usr/bin/VBoxControl", "/usr/bin/vmware-toolbox-cmd",
                "/usr/bin/vmware-user-suid-wrapper", "/usr/bin/vmware-user",
                "/usr/lib/vmware-tools", "/usr/lib/vmware-tools-common",
                "/opt/vmware-tools", "/etc/vmware-tools",
                "/proc/driver/vboxguest", "/proc/driver/vboxsf",
                "/sys/bus/vmbus", "/sys/bus/vmbus/devices"
            ],
            "Windows": [
                "C:\\Program Files\\VMware\\VMware Tools",
                "C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
                "C:\\Program Files\\Common Files\\VMware\\Drivers",
                "C:\\Windows\\System32\\drivers\\vboxguest.sys",
                "C:\\Windows\\System32\\drivers\\vboxmouse.sys",
                "C:\\Windows\\System32\\drivers\\vboxsf.sys",
                "C:\\Windows\\System32\\drivers\\vboxvideo.sys"
            ],
            "Darwin": [
                "/Library/Application Support/VMware Tools",
                "/Library/Application Support/Oracle/VirtualBox Guest Additions",
                "/usr/bin/vmware-toolbox-cmd",
                "/usr/bin/vmware-user-suid-wrapper"
            ]
        }
        
        system = platform.system()
        files = vm_files.get(system, [])
        
        for file_path in files:
            if os.path.exists(file_path):
                return f"VM file detected: {file_path}"
        
        return None

    def _check_vm_network(self) -> str:
        """Check for VM-specific network configurations"""
        try:
            # Check for VM-specific MAC address ranges
            vm_mac_prefixes = [
                "00:05:69", "00:0c:29", "00:1c:14", "00:50:56",  # VMware
                "08:00:27", "08:00:28", "08:00:29", "08:00:2a",  # VirtualBox
                "00:15:5d", "00:16:3e", "00:17:fa", "00:18:db",  # Hyper-V
                "52:54:00", "52:55:00", "52:56:00"               # QEMU/KVM
            ]
            
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:  # MAC address
                        mac = addr.address.lower()
                        for prefix in vm_mac_prefixes:
                            if mac.startswith(prefix.lower().replace(':', '')):
                                return f"VM MAC address detected: {mac} (prefix: {prefix})"
        except Exception as e:
            self.logger.debug(f"[Sandbox] Network check failed: {e}")
        
        return None

    def _check_vm_hardware(self) -> str:
        """Check for VM-specific hardware characteristics"""
        try:
            # Check CPU cores (VMs often have few cores)
            cpu_count = psutil.cpu_count()
            if cpu_count <= 2:
                return f"Low CPU count detected: {cpu_count} cores"
            
            # Check memory (VMs often have limited RAM)
            memory = psutil.virtual_memory()
            memory_gb = memory.total / (1024**3)
            if memory_gb <= 2:
                return f"Low memory detected: {memory_gb:.1f} GB"
            
            # Check disk space (VMs often have small disks)
            disk = psutil.disk_usage('/')
            disk_gb = disk.total / (1024**3)
            if disk_gb <= 20:
                return f"Small disk detected: {disk_gb:.1f} GB"
                
        except Exception as e:
            self.logger.debug(f"[Sandbox] Hardware check failed: {e}")
        
        return None

    def _check_sandbox_artifacts(self) -> str:
        """Check for sandbox-specific artifacts"""
        sandbox_artifacts = [
            "/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb",
            "/usr/bin/valgrind", "/usr/bin/dtruss", "/usr/bin/dtrace",
            "/proc/self/status", "/proc/self/maps", "/proc/self/environ",
            "/tmp/sandbox", "/var/tmp/sandbox", "/opt/sandbox",
            "C:\\sandbox", "C:\\analysis", "C:\\malware",
            "/Applications/Analysis", "/Applications/Sandbox"
        ]
        
        for artifact in sandbox_artifacts:
            if os.path.exists(artifact):
                return f"Sandbox artifact detected: {artifact}"
        
        return None

    def _check_analysis_tools(self) -> str:
        """Check for analysis and debugging tools"""
        analysis_tools = [
            "wireshark", "tcpdump", "strace", "ltrace", "gdb", "lldb",
            "ollydbg", "x64dbg", "windbg", "ida", "ghidra", "radare2",
            "processhacker", "processexplorer", "procexp", "procexp64",
            "fiddler", "burp", "charles", "mitmproxy", "wireshark",
            "tcpview", "netstat", "netcat", "nc", "ncat"
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                proc_name = proc.info['name'].lower()
                for tool in analysis_tools:
                    if tool in proc_name:
                        return f"Analysis tool detected: {proc.info['name']} (PID: {proc.info['pid']})"
        except Exception as e:
            self.logger.debug(f"[Sandbox] Analysis tools check failed: {e}")
        
        return None

    def _check_debugger_presence(self) -> str:
        """Check for debugger presence"""
        try:
            if platform.system() == "Windows":
                # Windows API check
                is_debugger = ctypes.windll.kernel32.IsDebuggerPresent() != 0
                if is_debugger:
                    return "Debugger detected via Windows API"
                
                # Check for debugger in PEB
                try:
                    import ctypes.wintypes
                    kernel32 = ctypes.windll.kernel32
                    GetCurrentProcess = kernel32.GetCurrentProcess
                    GetCurrentProcess.restype = ctypes.wintypes.HANDLE
                    
                    ntdll = ctypes.windll.ntdll
                    NtQueryInformationProcess = ntdll.NtQueryInformationProcess
                    NtQueryInformationProcess.restype = ctypes.c_ulong
                    
                    process = GetCurrentProcess()
                    debug_port = ctypes.c_ulong()
                    size = ctypes.c_ulong(ctypes.sizeof(debug_port))
                    
                    status = NtQueryInformationProcess(process, 7, ctypes.byref(debug_port), size, None)
                    if status == 0 and debug_port.value != 0:
                        return "Debugger detected via NtQueryInformationProcess"
                except Exception:
                    pass
                    
            else:
                # Linux/macOS: check TracerPid
                try:
                    with open("/proc/self/status", "r") as f:
                        for line in f:
                            if line.startswith("TracerPid:"):
                                tracer_pid = int(line.split()[1])
                                if tracer_pid > 0:
                                    return f"Debugger detected via TracerPid: {tracer_pid}"
                except Exception:
                    pass
                    
        except Exception as e:
            self.logger.debug(f"[Sandbox] Debugger check failed: {e}")
        
        return None

    def _check_timing_anomalies(self) -> str:
        """Check for timing anomalies that indicate sandbox analysis"""
        try:
            # Check if system time is recent (sandboxes often reset time)
            current_time = time.time()
            if current_time < 1609459200:  # Before 2021
                return f"System time anomaly detected: {current_time}"
            
            # Check for rapid execution (sandboxes often run code quickly)
            start_time = time.time()
            time.sleep(0.1)  # Sleep for 100ms
            actual_sleep = time.time() - start_time
            
            if actual_sleep < 0.05:  # If sleep was too fast
                return f"Timing anomaly detected: expected 0.1s, got {actual_sleep:.3f}s"
                
        except Exception as e:
            self.logger.debug(f"[Sandbox] Timing check failed: {e}")
        
        return None

    def _check_user_interaction(self) -> str:
        """Check for lack of user interaction (common in sandboxes)"""
        try:
            if platform.system() == "Windows":
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, winreg.KEY_READ)
                try:
                    screensave_active, _ = winreg.QueryValueEx(key, "ScreenSaveActive")
                    if screensave_active == "0":
                        return "Screen saver disabled (common in sandboxes)"
                except Exception:
                    pass
                winreg.CloseKey(key)
                
            # Check for mouse movement (sandboxes often have no mouse activity)
            # This is a simplified check - in practice you'd track mouse events
            if platform.system() == "Linux":
                try:
                    result = subprocess.run(['xset', 'q'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and "Screen Saver" in result.stdout:
                        return "X11 screen saver detected (possible sandbox)"
                except Exception:
                    pass
                    
        except Exception as e:
            self.logger.debug(f"[Sandbox] User interaction check failed: {e}")
        
        return None

    def _check_system_characteristics(self) -> str:
        """Check for system characteristics that indicate sandbox"""
        try:
            # Check hostname (sandboxes often have generic names)
            hostname = platform.node().lower()
            sandbox_hostnames = ["sandbox", "analysis", "malware", "test", "vm", "virtual"]
            if any(name in hostname for name in sandbox_hostnames):
                return f"Suspicious hostname detected: {hostname}"
            
            # Check username (sandboxes often use generic usernames)
            username = os.getenv('USER', os.getenv('USERNAME', '')).lower()
            sandbox_usernames = ["sandbox", "analysis", "malware", "test", "user", "admin"]
            if any(name in username for name in sandbox_usernames):
                return f"Suspicious username detected: {username}"
            
            # Check for too many processes (sandboxes often have minimal processes)
            process_count = len(list(psutil.process_iter()))
            if process_count < 50:
                return f"Low process count detected: {process_count} processes"
                
        except Exception as e:
            self.logger.debug(f"[Sandbox] System characteristics check failed: {e}")
        
        return None

    def get_detection_summary(self) -> Dict[str, any]:
        """Get a summary of all detection results"""
        return {
            "sandbox_detected": len(self.sandbox_indicators) >= 3,
            "detection_score": len(self.sandbox_indicators),
            "indicators": self.sandbox_indicators,
            "total_checks": 14
        } 