# modules/usb_monitor_ext.py

import os
import platform
import threading
import time
import datetime
import subprocess
from pathlib import Path
from modules.logger import log_event
from modules.config import load_config

# OS‐specific imports
if platform.system() == "Linux":
    try:
        from pyudev import Context, Monitor, MonitorObserver
    except ImportError:
        MonitorObserver = None
elif platform.system() == "Windows":
    try:
        import win32con
        import win32file
        import win32api
        import win32event
        import win32gui
        import ctypes
    except ImportError:
        win32file = None
else:
    # macOS: no easy hook; will poll diskutil list
    pass

USB_LOG_PATH = os.path.join(os.path.expanduser("~"), "usb_events.log")

cfg = load_config()
USB_MONITOR_INTERVAL = cfg.get("usb_monitor", {}).get("interval", 5)

def log_usb_event(action: str, device: dict):
    """
    Append a USB event (insert/remove) to the log and encrypted event log.
    """
    try:
        event_data = {
            "timestamp": time.time(),
            "action": action,
            "device": device
        }
        log_event("usb_monitor", f"USB {action}: {device}".encode())
    except Exception as e:
        log_event("usb_monitor", f"USB event logging error: {e}".encode())

### Linux Implementation
def linux_usb_monitor():
    """Monitor USB devices on Linux"""
    try:
        # Use udev to monitor USB events
        cmd = ["udevadm", "monitor", "--property", "--subsystem-match=usb"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in process.stdout:
            if "ID_VENDOR_ID" in line or "ID_MODEL_ID" in line:
                device_info = {
                    "vendor_id": line.split("=")[1].strip() if "ID_VENDOR_ID" in line else "",
                    "model_id": line.split("=")[1].strip() if "ID_MODEL_ID" in line else ""
                }
                log_usb_event("detected", device_info)
                
    except Exception as e:
        log_event("usb_monitor", f"Linux USB monitor error: {e}".encode())

def linux_usb_callback(action, device):
    """Callback for Linux USB events"""
    try:
        device_info = {
            "action": action,
            "device_path": device.get("DEVNAME", ""),
            "vendor": device.get("ID_VENDOR_ID", ""),
            "model": device.get("ID_MODEL_ID", "")
        }
        log_usb_event(action, device_info)
    except Exception as e:
        log_event("usb_monitor", f"Linux USB callback error: {e}".encode())

### Windows Implementation
def windows_usb_monitor():
    """Monitor USB devices on Windows"""
    try:
        # Use PowerShell to monitor USB devices
        cmd = [
            "powershell", 
            "Get-WmiObject -Class Win32_USBHub | Select-Object DeviceID, Name, Status"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')[3:]  # Skip header
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        device_info = {
                            "device_id": parts[0],
                            "name": " ".join(parts[1:-1]),
                            "status": parts[-1]
                        }
                        log_usb_event("detected", device_info)
                        
    except Exception as e:
        log_event("usb_monitor", f"Windows USB monitor error: {e}".encode())

### macOS Implementation
def macos_usb_monitor():
    """Monitor USB devices on macOS"""
    try:
        # Use system_profiler to get USB device info
        cmd = ["system_profiler", "SPUSBDataType"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            current_device = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith("Product ID:"):
                    current_device["product_id"] = line.split(":")[1].strip()
                elif line.startswith("Vendor ID:"):
                    current_device["vendor_id"] = line.split(":")[1].strip()
                elif line.startswith("Manufacturer:"):
                    current_device["manufacturer"] = line.split(":")[1].strip()
                elif line.startswith("Product Name:"):
                    current_device["product_name"] = line.split(":")[1].strip()
                    if current_device:
                        log_usb_event("detected", current_device.copy())
                        current_device = {}
                        
    except Exception as e:
        log_event("usb_monitor", f"macOS USB monitor error: {e}".encode())

def start_usb_monitor():
    """Start USB monitoring based on platform"""
    def monitor_loop():
        while True:
            try:
                system = platform.system()
                if system == "Linux":
                    linux_usb_monitor()
                elif system == "Windows":
                    windows_usb_monitor()
                elif system == "Darwin":
                    macos_usb_monitor()
                else:
                    log_event("usb_monitor", f"Unsupported platform: {system}".encode())
                    
            except Exception as e:
                log_event("usb_monitor", f"USB monitor loop error: {e}".encode())
            
            time.sleep(USB_MONITOR_INTERVAL)
    
    # Start monitoring in background thread
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    log_event("usb_monitor", "USB monitoring started".encode())

if __name__ == "__main__":
    print("[+] Starting USB monitoring …")
    start_usb_monitor()
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        pass
