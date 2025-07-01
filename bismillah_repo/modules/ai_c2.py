# File: modules/ai_c2.py

"""
Enhanced AI‑driven C2 loop:
• Supports GPT‑4, local HuggingFace models (via transformers).
• Task prioritization (critical vs. normal).
• Automatic fallback to cached suggestions if LLM endpoint unavailable.
• Configurable polling interval and dynamic model selection.
"""

import os
import json
import time
import hashlib
import logging
import threading
from threading import Lock
from queue import PriorityQueue, Empty
from pathlib import Path
import requests

# Optional: local HF model inference
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False

logger = logging.getLogger("ai_c2")

CONFIG = {
    "lm_endpoint": os.getenv("LLM_ENDPOINT", ""),       # e.g., OpenAI or private
    "lm_key": os.getenv("LLM_KEY", ""),
    "fallback_local": True,                              # use HF pipeline if no remote
    "model_name": "gpt-4",                                # default
    "hf_model": "gpt2",                                   # local HF model
    "poll_interval": 10,                                  # seconds
}

_seen_lock = Lock()
_seen_tasks = set()

# PriorityQueue entries: (priority, timestamp, task_dict)
task_queue = PriorityQueue()

# Initialize HF pipeline if available
if HF_AVAILABLE and CONFIG["fallback_local"]:
    logger.info("[AI_C2] Loading local HF model for fallback...")
    hf_tokenizer = AutoTokenizer.from_pretrained(CONFIG["hf_model"])
    hf_model = AutoModelForCausalLM.from_pretrained(CONFIG["hf_model"])
    hf_pipe = pipeline("text-generation", model=hf_model, tokenizer=hf_tokenizer, max_length=256)
else:
    hf_pipe = None

def _hash_task(task: dict) -> str:
    s = json.dumps(task, sort_keys=True).encode()
    return hashlib.sha256(s).hexdigest()

def _call_remote_llm(prompt: str) -> str:
    """Use OpenAI‑style REST API."""
    try:
        headers = {"Authorization": f"Bearer {CONFIG['lm_key']}"}
        data = {"model": CONFIG["model_name"], "prompt": prompt, "max_tokens": 128}
        resp = requests.post(CONFIG["lm_endpoint"], headers=headers, json=data, timeout=10)
        resp.raise_for_status()
        return resp.json()["choices"][0]["text"].strip()
    except Exception as e:
        logger.warning(f"[AI_C2] Remote LLM failed: {e}")
        return ""

def _call_local_llm(prompt: str) -> str:
    """Fallback to local HF model."""
    if hf_pipe:
        out = hf_pipe(prompt, max_length=128, num_return_sequences=1)
        return out[0]["generated_text"].strip()
    return ""

def start_config_watcher():
    """Watch for configuration changes and reload config when needed"""
    def config_watcher_loop():
        config_file = Path(__file__).parent.parent / "config.json"
        last_modified = 0
        
        while True:
            try:
                if config_file.exists():
                    current_modified = config_file.stat().st_mtime
                    if current_modified > last_modified:
                        logger.info("[AI_C2] Configuration file changed, reloading...")
                        # Reload config from file
                        try:
                            with open(config_file, 'r') as f:
                                new_config = json.load(f)
                            # Update CONFIG with new values
                            if 'ai_c2' in new_config:
                                CONFIG.update(new_config['ai_c2'])
                            logger.info("[AI_C2] Configuration reloaded successfully")
                        except Exception as e:
                            logger.error(f"[AI_C2] Failed to reload config: {e}")
                        last_modified = current_modified
            except Exception as e:
                logger.error(f"[AI_C2] Config watcher error: {e}")
            
            time.sleep(30)  # Check every 30 seconds
    
    # Start config watcher in background thread
    watcher_thread = threading.Thread(target=config_watcher_loop, daemon=True)
    watcher_thread.start()
    logger.info("[AI_C2] Configuration watcher started")

def ai_c2_loop():
    """
    1) Reads ai_tasks.json for new tasks.
    2) Skips tasks already seen (via SHA256 hash).
    3) Assigns priority based on "critical" flag.
    4) For new tasks, calls LLM (remote or local) to augment "action" → "llm_suggestion".
    5) Enqueues into task_queue for core dispatcher to pick up.
    6) Polls every CONFIG['poll_interval'].
    """
    seen_file = Path(__file__).parent / "ai_tasks_seen.json"
    while True:
        time.sleep(CONFIG["poll_interval"])
        tasks_file = Path(__file__).parent / "ai_tasks.json"
        if not tasks_file.exists():
            continue
        try:
            tasks = json.load(open(tasks_file))
        except json.JSONDecodeError as e:
            logger.error(f"[AI_C2] Failed to parse ai_tasks.json: {e}")
            (tasks_file.parent / "ai_tasks_corrupt.json").write_bytes(tasks_file.read_bytes())
            tasks_file.unlink()  # move aside
            continue

        for entry in tasks:
            h = _hash_task(entry)
            with _seen_lock:
                if h in _seen_tasks:
                    continue
                _seen_tasks.add(h)
                # Save updated seen file
                with open(seen_file, "w") as f:
                    json.dump(list(_seen_tasks), f)

            # Determine priority (0=high if "critical":True)
            prio = 0 if entry.get("critical") else 1
            prompt = f"Task: {entry}\nGenerate a secure shell command or script to perform this action."
            suggestion = ""
            if CONFIG["lm_endpoint"]:
                suggestion = _call_remote_llm(prompt)
            if not suggestion and hf_pipe:
                suggestion = _call_local_llm(prompt)

            entry["llm_suggestion"] = suggestion or "No suggestion available"
            logger.info(f"[AI_C2] Augmented task: {entry}")

            # Put into queue: (prio, timestamp, entry)
            task_queue.put((prio, time.time(), entry))

        # Optionally clear ai_tasks.json to avoid re‑processing
        tasks_file.unlink()

def get_next_ai_task(timeout: int = 1) -> dict:
    """
    Core dispatcher calls this to retrieve next AI task.
    Returns None if no task within timeout.
    """
    try:
        prio, ts, task = task_queue.get(timeout=timeout)
        return task
    except Empty:
        return None
