# File: modules/obfuscation.py

"""
Enhanced obfuscation:  
• Switch from simple XOR to AES‑GCM encrypting each module on disk with a daily key.  
• Daily key derived from master key + date, rotated at midnight.  
• Modules stored as .morph (encrypted), loader decrypts them in memory.  
• Prevents static analysis by any tool that reads .morph directly without key.
"""

import os
import json
import time
import hashlib
import threading
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Master key (256‑bit) stored securely or derived from environment
MASTER_KEY = bytes.fromhex(os.getenv("OBF_MASTER_KEY", "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"))
OBF_DIR = Path(__file__).parent / "morph_cache"
INDEX_FILE = Path(__file__).parent / "morph_index.json"

# Ensure cache directory exists
OBF_DIR.mkdir(exist_ok=True)

# Lock for index
index_lock = threading.Lock()

def _daily_key():
    """Derive a daily 256-bit key: AES‑GCM(master, date_string)."""
    date_str = time.strftime("%Y-%m-%d")
    digest = hashlib.sha256(MASTER_KEY + date_str.encode()).digest()
    return digest  # 32 bytes

def encrypt_module(src_path: Path):
    """
    Encrypt src_path using AES‑GCM with daily key.
    Output: OBF_DIR/<modname>.morph
    """
    try:
        key = _daily_key()
        aesgcm = AESGCM(key)
        iv = os.urandom(12)
        plaintext = src_path.read_bytes()
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        target = OBF_DIR / (src_path.stem + ".morph")
        with open(target, "wb") as f:
            f.write(iv + ciphertext)  # prepend IV
        # Update index with timestamp and hash
        h = hashlib.sha256(ciphertext).hexdigest()
        with index_lock:
            idx = {}
            if INDEX_FILE.exists():
                idx = json.load(open(INDEX_FILE))
            idx[src_path.name] = {"hash": h, "last_modified": time.time()}
            json.dump(idx, open(INDEX_FILE, "w"), indent=2)
        src_path.unlink()  # remove plaintext
    except Exception as e:
        print(f"Obfuscation failed for {src_path}: {e}")

def decrypt_module(name: str) -> str:
    """
    Decrypt OBF_DIR/<name>.morph using daily key. Returns path to temporary .py file.
    """
    try:
        morph = OBF_DIR / (name + ".morph")
        data = morph.read_bytes()
        iv = data[:12]
        ciphertext = data[12:]
        key = _daily_key()
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        tmp_py = Path("/tmp") / f"{name}.py"
        tmp_py.write_bytes(plaintext)
        return str(tmp_py)
    except Exception as e:
        print(f"Decryption failed for {name}: {e}")
        return ""

# File‑watcher to re‑encrypt changed .py files every midnight
def watch_and_encrypt():
    """
    Scans modules/ directory every minute; if a .py’s timestamp > recorded, encrypts it.
    Rotates on date change (daily key), re‑encrypts all .morph files to new key.
    """
    last_date = time.strftime("%Y-%m-%d")
    while True:
        time.sleep(60)
        current_date = time.strftime("%Y-%m-%d")
        # If date changed, re‑encrypt all .morph with new key
        if current_date != last_date:
            for morph in OBF_DIR.glob("*.morph"):
                name = morph.stem
                pt = decrypt_module(name)
                if pt:
                    encrypt_module(Path(pt))
            last_date = current_date

        # Encrypt any new/modified .py files in modules/
        mod_dir = Path(__file__).parent  # adjust if needed
        for py in mod_dir.glob("*.py"):
            idx = {}
            if INDEX_FILE.exists():
                idx = json.load(open(INDEX_FILE))
            record = idx.get(py.name, {})
            if py.stat().st_mtime > record.get("last_modified", 0):
                encrypt_module(py)
