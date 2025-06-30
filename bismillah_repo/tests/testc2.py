import pytest
import threading
import time
from modules.icmp_c2 import TASKS, add_icmp_task, start_icmp_server

@pytest.mark.timeout(5)
def test_icmp_task_queue():
    # Add a task and verify it appears in TASKS
    bid = "testbeacon"
    task = {"action": "noop"}
    add_icmp_task(bid, task)
    assert bid in TASKS
    assert TASKS[bid][0]["task"] == task
