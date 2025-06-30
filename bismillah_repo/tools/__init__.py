"""
Bismillah Framework - Tools Module

This package contains various utility tools for the Bismillah framework:

- c2_server.py: HTTP/HTTPS command and control server
- dns_c2_server.py: DNS-based command and control server
- mitm_sslstrip.py: HTTPS stripping and MitM proxy
- shellcode_gen.py: Polymorphic shellcode generator
- update_exploit_index.py: Updates the exploit database index
- cobaltstrike_stub: CobaltStrike compatibility layer
- metasploit_framework.sh: MSF integration wrapper
- impacket_ntlmrelayx: NTLM relay attack automation
"""

from .c2_server import app, start as start_http_c2
from .dns_c2_server import server as dns_server
from .shellcode_gen import generate_polymorphic_shellcode
from .update_exploit_index import main as update_exploit_index

__all__ = [
    'app', 'start_http_c2',
    'dns_server',
    'generate_polymorphic_shellcode',
    'update_exploit_index'
]
