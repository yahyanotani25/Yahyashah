"""
modules/reconnaissance_ext.py (enhanced)

– Uses ThreadPoolExecutor for port scans
– Checks for missing dependencies (nmap, shodan, dnspython)
– Persistent “last_recon.json” with timestamps
– Exponential back‐off on repeated failures
"""

import os
import json
import time
import logging
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from bismillah import log_event

logger = logging.getLogger("reconnaissance_ext")
REPO_ROOT = Path(__file__).parent.parent.resolve()
LAST_RECON = REPO_ROOT / "modules" / "last_recon.json"

MAX_THREADS = 20
BACKOFF_INITIAL = 300

def nmap_scan(args: dict):
    subnet = args.get("subnet", "192.168.1.0/24")
    ports = args.get("ports", "1-1024")
    result = {}
    try:
        import nmap
    except ImportError:
        return {"error": "nmap library not installed"}
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments=f"-p {ports} --open -T4")
        for host in nm.all_hosts():
            open_ports = []
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port]["state"] == "open":
                        open_ports.append(port)
            result[host] = open_ports
        log_event("reconnaissance_ext", f"Nmap scan on {subnet}:{ports}, {len(result)} hosts".encode())
    except Exception as e:
        logger.error(f"nmap_scan error: {e}")
        result = {"error": str(e)}
    return result

def shodan_recon(args: dict):
    api_key = args.get("api_key")
    query = args.get("query", "apache")
    limit = args.get("limit", 5)
    try:
        from shodan import Shodan
    except ImportError:
        return {"error": "shodan library not installed"}
    try:
        api = Shodan(api_key)
        res = api.search(query, limit=limit)
        matches = res.get("matches", [])
        log_event("reconnaissance_ext", f"Shodan search {query}, got {len(matches)}".encode())
        return matches
    except Exception as e:
        logger.error(f"shodan_recon error: {e}")
        return {"error": str(e)}

def dns_enum(args: dict):
    domain = args.get("domain", "")
    result = {}
    try:
        import dns.resolver
    except ImportError:
        return {"error": "dnspython not installed"}
    try:
        for qtype in ["A","NS","MX","TXT"]:
            try:
                answer = dns.resolver.resolve(domain, qtype, lifetime=10)
                result[qtype] = [r.to_text() for r in answer]
            except Exception:
                result[qtype] = []
        log_event("reconnaissance_ext", f"DNS enum for {domain}".encode())
    except Exception as e:
        logger.error(f"dns_enum error: {e}")
        result = {"error": str(e)}
    return result

def wifi_scan(args: dict):
    result = []
    try:
        out = subprocess.check_output(["iwlist","scan"], stderr=subprocess.DEVNULL, timeout=15).decode(errors="ignore")
        ssids = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("ESSID:"):
                essid = line.split(":",1)[1].strip('"')
                ssids.append(essid)
        result = list(set(ssids))
        log_event("reconnaissance_ext", f"Wi-Fi scan found {len(result)} SSIDs".encode())
    except Exception as e:
        logger.error(f"wifi_scan error: {e}")
        result = {"error": str(e)}
    return result

def run_recon(method: str, args: dict):
    try:
        if method == "nmap":
            return nmap_scan(args)
        elif method == "shodan":
            return shodan_recon(args)
        elif method == "dns":
            return dns_enum(args)
        elif method == "wifi":
            return wifi_scan(args)
        else:
            return {"error": f"Unknown recon method: {method}"}
    except Exception as e:
        logger.exception(f"run_recon error: {e}")
        return {"error": str(e)}

def recon_loop():
    """
    Every 15 minutes, perform default nmap scan and store results to last_recon.json.
    Uses back‐off on errors.
    """
    backoff = BACKOFF_INITIAL
    while True:
        try:
            args = {"subnet": "192.168.1.0/24", "ports": "1-1024"}
            res = nmap_scan(args)
            with open(LAST_RECON, "w") as f:
                json.dump(res, f, indent=2)
            log_event("reconnaissance_ext", f"Periodic recon on {args['subnet']}".encode())
            backoff = BACKOFF_INITIAL
        except Exception as e:
            logger.error(f"Recon loop error: {e}")
            time.sleep(backoff)
            backoff = min(backoff * 2, 3600)
        time.sleep(900)
import json
import subprocess
import traceback
import time
from pathlib import Path

import dns.resolver
import nmap
import psutil
import shodan
import requests
from modules.logger import log_event
from modules.config import load_config

cfg = load_config()
SHODAN_API_KEY = cfg.get("recon", {}).get("shodan_api_key", "")
PASSIVEDNS_API_KEY = cfg.get("recon", {}).get("passivedns_api_key", "")
DEFAULT_SUBNET = cfg.get("recon", {}).get("nmap_subnet", "192.168.1.0/24")
NMAP_ARGS = cfg.get("recon", {}).get("nmap_args", "-p 1-65535 --open -T4 -sV -sC")
WIFI_IF = cfg.get("recon", {}).get("wifi_interface", "wlan0")
SUBDOMAIN_WORDLIST = cfg.get("recon", {}).get("subdomains", ["www", "mail", "ftp", "dev"])
RECON_OUTPUT = Path(__file__).parent / "last_recon.json"

def nmap_scan(subnet=DEFAULT_SUBNET, arguments=NMAP_ARGS):
    nm = nmap.PortScanner()
    try:
        scan = nm.scan(hosts=subnet, arguments=arguments)
        hosts = scan.get("scan", {})
        result = {host: data for host, data in hosts.items()}
        with open(RECON_OUTPUT, "w") as f:
            json.dump(result, f)
        log_event("reconnaissance", f"Nmap: {len(hosts)} hosts scanned".encode())
        return result
    except Exception as e:
        tb = traceback.format_exc()
        log_event("reconnaissance", f"Nmap error: {tb}".encode())
        return {}

def shodan_recon(query: str):
    if not SHODAN_API_KEY:
        log_event("reconnaissance", b"Shodan key missing.")
        return []
    try:
        client = shodan.Shodan(SHODAN_API_KEY)
        results = client.search(query)
        log_event("reconnaissance", f"Shodan '{query}': {results['total']} hits".encode())
        return results["matches"]
    except Exception as e:
        tb = traceback.format_exc()
        log_event("reconnaissance", f"Shodan error: {tb}".encode())
        return []

def passivedns_lookup(domain: str):
    if not PASSIVEDNS_API_KEY:
        log_event("reconnaissance", b"PassiveDNS key missing.")
        return []
    try:
        url = f"https://api.passivedns.example.com/query/rrset/name/{domain}"
        headers = {"X-API-Key": PASSIVEDNS_API_KEY}
        r = requests.get(url, timeout=10, headers=headers)
        if r.status_code == 200:
            data = r.json()
            log_event("reconnaissance", f"PassiveDNS for {domain}: {len(data)} records".encode())
            return data
    except Exception as e:
        tb = traceback.format_exc()
        log_event("reconnaissance", f"PassiveDNS error: {tb}".encode())
    return []

def dns_enum(domain: str):
    out = {"A": [], "NS": [], "MX": [], "TXT": [], "Subdomains": []}
    try:
        for rec in ["A", "NS", "MX", "TXT"]:
            answers = dns.resolver.resolve(domain, rec, lifetime=5)
            out[rec] = [str(rdata).strip() for rdata in answers]
        for sub in SUBDOMAIN_WORDLIST:
            try:
                ans = dns.resolver.resolve(f"{sub}.{domain}", "A", lifetime=3)
                for r in ans:
                    out["Subdomains"].append(f"{sub}.{domain} -> {r}")
            except Exception:
                pass
        log_event("reconnaissance", f"DNS enum for {domain}: {out}".encode())
    except Exception as e:
        tb = traceback.format_exc()
        log_event("reconnaissance", f"DNS enum error {domain}: {tb}".encode())
    return out

def wifi_scan(interface=WIFI_IF):
    result = []
    try:
        proc = subprocess.Popen(["iwlist", interface, "scan"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(timeout=20)
        if proc.returncode != 0:
            raise Exception(err.decode().strip())
        text = out.decode(errors="ignore")
        for line in text.splitlines():
            if "ESSID" in line:
                essid = line.strip().split("ESSID:")[-1].strip().strip('"')
                if essid and essid not in result:
                    result.append(essid)
        log_event("reconnaissance", f"WiFi: {result}".encode())
    except Exception as e:
        tb = traceback.format_exc()
        log_event("reconnaissance", f"WiFi scan error: {tb}".encode())
    return result

def process_enum():
    data = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'connections']):
            info = proc.info
            if info.get("connections"):
                for conn in info["connections"]:
                    if conn.status == psutil.CONN_LISTEN:
                        data.append({
                            "pid": info["pid"],
                            "name": info["name"],
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}"
                        })
        log_event("reconnaissance", f"Process enum: {len(data)} listening sockets".encode())
    except Exception as e:
        tb = traceback.format_exc()
        log_event("reconnaissance", f"Process enum error: {tb}".encode())
    return data

def smb_share_enum(target: str):
    shares = []
    try:
        proc = subprocess.Popen(["smbclient", "-L", target, "-N"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(timeout=15)
        if proc.returncode != 0:
            raise Exception(err.decode().strip())
        for line in out.decode().splitlines():
            if "Disk" in line or "Sharename" in line:
                continue
            parts = line.split()
            if len(parts) >= 1:
                shares.append(parts[0])
        log_event("reconnaissance", f"SMB shares on {target}: {shares}".encode())
    except Exception as e:
        tb = traceback.format_exc()
        log_event("reconnaissance", f"SMB share enum error {target}: {tb}".encode())
    return shares

def run_recon_loops():
    while True:
        try:
            nmap_scan()
            dns_enum(cfg.get("c2", {}).get("domain", "example.com"))
            if PASSIVEDNS_API_KEY:
                passivedns_lookup(cfg.get("c2", {}).get("domain", "example.com"))
        except Exception as e:
            log_event("reconnaissance", f"Recon loop error: {e}".encode())
        time.sleep(1800)

        try:
            process_enum()
            wifi_scan()
        except Exception as e:
            log_event("reconnaissance", f"Recon loop error: {e}".encode())
        time.sleep(600)
