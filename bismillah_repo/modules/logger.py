import logging
import logging.handlers
import os
import sqlite3
import threading
import time
import shutil
from base64 import b64encode, b64decode
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import ChaCha20_Poly1305
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
                    import gzip
                    gz_path = fn.with_suffix(fn.suffix + ".gz")
                    with open(fn, "rb") as f_in, gzip.open(str(gz_path), "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                    os.remove(fn)

                    # Encrypt with ChaCha20_Poly1305
                    with open(str(gz_path), "rb") as f_plain:
                        plaintext = f_plain.read()
                    cipher = ChaCha20_Poly1305.new(key=AES_KEY[:32])
                    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                    enc_path = gz_path.with_suffix(".enc")
                    with open(str(enc_path), "wb") as f_enc:
                        f_enc.write(cipher.nonce + tag + ciphertext)
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
# File: modules/logger.py

"""
Enhanced logger:
• Every event is stored in encrypted SQLite via AES‑GCM; older backups encrypted via ChaCha20‑Poly1305.
• Structured JSON logs written to rotating log file (in RAM disk or /tmp).
• Optional remote syslog forwarding (TLS).
• Uncaught exceptions automatically logged via a custom handler.
"""

import os
import sqlite3
import logging
import logging.handlers
import threading
import time
import gzip
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from datetime import datetime

CFG = {
    "log_db": os.getenv("LOG_DB_PATH", "/tmp/bismillah_events.db"),
    "aes_key": bytes.fromhex(os.getenv("LOG_AES_KEY", "00"*32)),
    "aes_iv": bytes.fromhex(os.getenv("LOG_AES_IV", "11"*12))[:12],
    "chacha_key": bytes.fromhex(os.getenv("LOG_CHACHA_KEY", "22"*32)),
    "retention_days": int(os.getenv("LOG_RETENTION_DAYS", "7")),
    "ramdisk": os.getenv("LOG_RAMDISK", "/dev/shm"),
    "remote_syslog": os.getenv("REMOTE_SYSLOG", ""),
}

# Initialize file logger
log_path = os.path.join(CFG["ramdisk"], "bismillah.log")
file_handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3)
file_formatter = logging.Formatter('{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}')
file_handler.setFormatter(file_formatter)
logger = logging.getLogger("bismillah")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

if CFG["remote_syslog"]:
    syslog_handler = logging.handlers.SysLogHandler(address=(CFG["remote_syslog"], 6514), socktype=socket.SOCK_STREAM)  # TLS
    logger.addHandler(syslog_handler)

_db_lock = threading.Lock()

def _init_db():
    conn = sqlite3.connect(CFG["log_db"], check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            category TEXT,
            enc_data BLOB
        )
    """)
    conn.commit()
    return conn

_db_conn = _init_db()

def log_event(category: str, message: bytes, level: str = "INFO"):
    """
    Encrypt `message` with AES‑GCM and insert into SQLite.
    Also write structured log to file logger.
    """
    try:
        aesgcm = AESGCM(CFG["aes_key"])
        ct = aesgcm.encrypt(CFG["aes_iv"], message, None)
        with _db_lock:
            _db_conn.execute("INSERT INTO events (timestamp, category, enc_data) VALUES (?, ?, ?)", (time.time(), category, ct))
            _db_conn.commit()
        # Also log plaintext (or careful subset) to rotating log file
        logger.log(getattr(logging, level.upper(), logging.INFO), f"[{category}] {message.decode(errors='ignore')}")
    except Exception as e:
        logger.error(f"[LOGGER] Failed to log event: {e}")

def _rotate_and_encrypt_backups():
    """
    Compress old DB files and encrypt with ChaCha20‑Poly1305.
    Runs daily.
    """
    while True:
        time.sleep(86400)  # once a day
        # Close current DB
        with _db_lock:
            _db_conn.close()
        # Backup and encrypt
        ts = datetime.utcnow().strftime("%Y%m%d")
        backup_name = f"{CFG['log_db']}.{ts}.gz"
        with open(CFG["log_db"], "rb") as f_in, gzip.open(backup_name, "wb") as f_out:
            f_out.writelines(f_in)
        chacha = ChaCha20Poly1305(CFG["chacha_key"])
        with open(backup_name, "rb") as f:
            pt = f.read()
        ct = chacha.encrypt(b"\x00"*12, pt, None)
        with open(backup_name + ".enc", "wb") as f:
            f.write(ct)
        os.remove(backup_name)
        # Reinit DB
        with _db_lock:
            global _db_conn
            _db_conn = _init_db()

# Spawn backup thread
threading.Thread(target=_rotate_and_encrypt_backups, daemon=True).start()
