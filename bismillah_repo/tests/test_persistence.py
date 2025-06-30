import sys
import os
import pytest
from modules.persistence_ext import linux_systemd_service, windows_run_key, macos_launchdaemon

def test_dummy_env(monkeypatch):
    # Simulate Linux environment without actual systemctl or root
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    with pytest.raises(Exception):
        linux_systemd_service("/path/to/nonexistent/script.sh")
