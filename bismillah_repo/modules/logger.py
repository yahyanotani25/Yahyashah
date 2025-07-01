import logging
import logging.handlers
import os
import sqlite3
import threading
import time
import shutil
from base64 import b64encode, b64decode
from pathlib import Path
import gzip
from datetime import datetime
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from modules.config import load_config

cfg = load_config().get("logging", {})
DB_PATH = cfg.get("sqlite_db", "/opt/bismillah_repo/bismillah.db")
ROTATE = cfg.get("rotate", {})
SYSLOG = cfg.get("remote_syslog", {})
RAMDISK = cfg.get("ramdisk_path", "/dev/shm/bismillah_logs")
RETENTION_DAYS = cfg.get("log_retention_days", 7)

# AES key for log encryption (32 bytes = 256 bits)
AES_KEY = bytes.fromhex(cfg.get("aes_key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
AES_NONCE = bytes.fromhex(cfg.get("aes_iv", "0123456789abcdef0123456789abcdef"))[:12]

_LOCK = threading.Lock()

# Set up Python logger
logger = logging.getLogger("bismillah")
logger.setLevel(logging.DEBUG)

# Write to console at INFO level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# Ensure RAM disk for logs
try:
    Path(RAMDISK).mkdir(parents=True, exist_ok=True)
    log_file_path = Path(RAMDISK) / "bismillah.log"
except Exception:
    # Fallback to /tmp if RAMDISK unavailable
    log_file_path = Path("/tmp") / "bismillah.log"

# Rotating file handler with on‐disk encryption
if ROTATE:
    fh = logging.handlers.RotatingFileHandler(
        filename=str(log_file_path),
        maxBytes=ROTATE.get("max_size_mb", 50) * 1024 * 1024,
        backupCount=ROTATE.get("backup_count", 10)
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    def encrypt_old_logs():
        """
        Every 5 min, compress & encrypt old log backups with ChaCha20_Poly1305.
        """
        for i in range(1, ROTATE.get("backup_count", 10) + 1):
            fn = log_file_path.with_name(f"bismillah.log.{i}")
            if fn.exists() and not str(fn).endswith(".enc"):
                try:
                    # Compress
                    gz_path = fn.with_suffix(fn.suffix + ".gz")
                    with open(fn, "rb") as f_in, gzip.open(str(gz_path), "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                    os.remove(fn)

                    # Encrypt with ChaCha20Poly1305
                    with open(str(gz_path), "rb") as f_plain:
                        plaintext = f_plain.read()
                    nonce = secrets.token_bytes(12)
                    cipher = ChaCha20Poly1305(AES_KEY[:32])
                    ciphertext = cipher.encrypt(nonce, plaintext, None)
                    enc_path = gz_path.with_suffix(".enc")
                    with open(str(enc_path), "wb") as f_enc:
                        f_enc.write(nonce + ciphertext)
                    os.remove(str(gz_path))
                except Exception:
                    pass

    t = threading.Timer(300, encrypt_old_logs)
    t.daemon = True
    t.start()

# Remote Syslog handler
if SYSLOG.get("enabled", False):
    sh = logging.handlers.SysLogHandler(address=(SYSLOG.get("host"), SYSLOG.get("port")))
    sh.setLevel(logging.WARNING)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

def _ensure_db():
    db = Path(DB_PATH)
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        category TEXT,
        message TEXT
    )
    """)
    conn.commit()
    conn.close()

def _cleanup_old_db_entries():
    """
    Delete DB entries older than RETENTION_DAYS.
    """
    cutoff = int(time.time()) - RETENTION_DAYS * 86400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()

def log_event(category: str, message: bytes, level: str = "info"):
    """
    Encrypts `message` (bytes) with AES-GCM, base64‐encodes it, writes to SQLite;
    also logs plaintext (cha‐chacha encryption of files) to rotating file/console.
    """
    text = message.decode(errors="ignore")
    ts = int(time.time())

    # Encrypt SQLite payload
    try:
        aesgcm = AESGCM(AES_KEY)
        ct = aesgcm.encrypt(AES_NONCE, message, None)
        b64_ct = b64encode(ct).decode()
    except Exception as e:
        logger.error(f"[{category}] Encryption error: {e}")
        b64_ct = b64encode(message).decode()

    with _LOCK:
        _ensure_db()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO events (timestamp, category, message) VALUES (?, ?, ?)",
                (ts, category, b64_ct)
            )
            conn.commit()
            _cleanup_old_db_entries()
        finally:
            conn.close()

    # Python logger
    logfn = getattr(logger, level, logger.info)
    logfn(f"[{category}] {text}")

def _rotate_and_encrypt_backups():
    """
    Compress old DB files and encrypt with ChaCha20‑Poly1305.
    Runs daily.
    """
    global _db_conn
    while True:
        time.sleep(86400)  # once a day
        # Close current DB
        with _LOCK:
            _db_conn.close()
        # Backup and encrypt
        ts = datetime.utcnow().strftime("%Y%m%d")
        backup_name = f"{DB_PATH}.{ts}.gz"
        with open(DB_PATH, "rb") as f_in, gzip.open(backup_name, "wb") as f_out:
            f_out.writelines(f_in)
        nonce = secrets.token_bytes(12)
        chacha = ChaCha20Poly1305(AES_KEY[:32])
        with open(backup_name, "rb") as f:
            pt = f.read()
        ct = chacha.encrypt(nonce, pt, None)
        with open(backup_name + ".enc", "wb") as f:
            f.write(nonce + ct)
        os.remove(backup_name)
        # Reinit DB
        with _LOCK:
            _db_conn = sqlite3.connect(DB_PATH)

# Spawn backup thread
threading.Thread(target=_rotate_and_encrypt_backups, daemon=True).start()
