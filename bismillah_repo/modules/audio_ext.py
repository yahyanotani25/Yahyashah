# modules/audio_ext.py

import os
import threading
import datetime
import wave
import time
import platform
import logging
from modules.logger import log_event

# Dependencies
try:
    import sounddevice as sd
    import soundfile as sf
except ImportError:
    sd = None
    sf = None

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

AUDIO_DIR = os.path.join(os.path.expanduser("~"), "audio_clips")
os.makedirs(AUDIO_DIR, exist_ok=True)

DEFAULT_DURATION = 10       # seconds
SAMPLE_RATE = 44100         # Hz
CHANNELS = 1
DEFAULT_INTERVAL = 120      # seconds

# ──────────────────────────────────────────────────────────────────────────────

def list_audio_devices():
    """
    Return a list of available input audio devices: [{'index': i, 'name': n}, ...]
    """
    if sd is None:
        return []
    devs = []
    try:
        for idx, info in enumerate(sd.query_devices()):
            if info["max_input_channels"] > 0:
                devs.append({"index": idx, "name": info["name"]})
    except Exception as e:
        logging.error(f"[audio_ext] list_audio_devices error: {e}")
    return devs

def record_audio_clip(duration: int = DEFAULT_DURATION, output_path: str = None, device=None) -> bool:
    """
    Records `duration` seconds from the specified microphone `device` (None=default).
    Writes to `output_path` (timestamped file in AUDIO_DIR if None).
    Returns True on success, False on failure.
    """
    if sd is None or sf is None:
        logging.error("[audio_ext] sounddevice or soundfile not installed")
        return False

    # Determine output file path
    if output_path is None:
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(AUDIO_DIR, f"audio_{ts}.wav")

    try:
        # If device is a name, find its index
        dev_index = None
        if device:
            devs = list_audio_devices()
            for d in devs:
                if device.lower() in d["name"].lower():
                    dev_index = d["index"]
                    break
            if dev_index is None and isinstance(device, int):
                dev_index = device
        # Record audio
        frames = sd.rec(int(duration * SAMPLE_RATE),
                        samplerate=SAMPLE_RATE,
                        channels=CHANNELS,
                        device=dev_index)
        sd.wait()
        sf.write(output_path, frames, SAMPLE_RATE, subtype="PCM_16")
        log_event({"type": "audio_record", "file": output_path})
        return True
    except Exception as e:
        logging.error(f"[audio_ext] record_audio_clip error: {e}")
        log_event({"type": "audio_record_failed", "error": str(e)})
        return False

def audio_worker(duration: int, interval: int, device=None):
    """
    Continuously record `duration`-second clips every `interval` seconds.
    """
    while True:
        record_audio_clip(duration=duration, output_path=None, device=device)
        time.sleep(interval)

def start_audio_capture(duration: int = DEFAULT_DURATION, interval: int = DEFAULT_INTERVAL, device=None):
    """
    Start a daemon thread that records `duration`-second audio clip every `interval` seconds.
    Returns Thread object.
    """
    if sd is None or sf is None:
        logging.error("[audio_ext] sounddevice or soundfile not installed; audio disabled")
        return None
    t = threading.Thread(target=audio_worker, args=(duration, interval, device), daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    if sd is None or sf is None:
        print("[!] Install: pip install sounddevice soundfile")
        exit(1)
    print("[+] Available audio devices (indexes):")
    for d in list_audio_devices():
        print(f"  {d['index']}: {d['name']}")
    print(f"[+] Recording {DEFAULT_DURATION}s clip …")
    if record_audio_clip():
        print(f"[+] Audio saved to {AUDIO_DIR}")
    else:
        print("[!] Recording failed.")
