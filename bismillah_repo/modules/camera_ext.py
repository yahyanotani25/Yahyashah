# modules/camera_ext.py

import os
import threading
import time
import datetime
import platform
import logging
from modules.logger import log_event

# Try OpenCV import
try:
    import cv2
except ImportError:
    cv2 = None

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
SCREENSHOT_DIR = os.path.join(os.path.expanduser("~"), "camera_snapshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

DEFAULT_INTERVAL = 60           # seconds
DEFAULT_FORMAT = "jpg"          # or "png"
MOTION_THRESHOLD = 100000       # pixel‐difference threshold for motion detection

# ──────────────────────────────────────────────────────────────────────────────

def take_snapshot(output_path: str) -> bool:
    """
    Capture a single image from the default webcam and write it to output_path.
    Returns True on success, False on failure.
    """
    if cv2 is None:
        logging.warning("[camera_ext] OpenCV not installed")
        return False

    cap = None
    try:
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW if platform.system() == "Windows" else cv2.CAP_ANY)
        if not cap.isOpened():
            logging.warning("[camera_ext] No webcam found or cannot be opened")
            return False

        ret, frame = cap.read()
        if not ret:
            return False

        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        ext = output_path.split(".")[-1].lower()
        if ext == "png":
            cv2.imwrite(output_path, frame, [cv2.IMWRITE_PNG_COMPRESSION, 3])
        else:
            # Default to JPEG
            cv2.imwrite(output_path, frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
        return True
    except Exception as e:
        logging.error(f"[camera_ext] take_snapshot error: {e}")
        return False
    finally:
        if cap:
            cap.release()

def detect_motion_and_snapshot(prev_frame, threshold: int = MOTION_THRESHOLD) -> (bool, any):
    """
    Compare prev_frame (grayscale) with new frame. If difference > threshold, return (True, new_frame).
    Else (False, new_frame).
    """
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW if platform.system() == "Windows" else cv2.CAP_ANY)
    if not cap.isOpened():
        return False, None
    ret, frame = cap.read()
    cap.release()
    if not ret or prev_frame is None:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if frame is not None else None
        return False, gray

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    diff = cv2.absdiff(prev_frame, gray)
    non_zero = cv2.countNonZero(diff)
    if non_zero > threshold:
        return True, gray
    return False, gray

def motion_snapshot_worker(interval: int):
    """
    Continuously check for motion at each 'interval'; if detected, save a snapshot.
    """
    prev_gray = None
    while True:
        motion, prev_gray = detect_motion_and_snapshot(prev_gray)
        if motion:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"motion_{ts}.{DEFAULT_FORMAT}"
            output_path = os.path.join(SCREENSHOT_DIR, filename)
            if take_snapshot(output_path):
                log_event({"type": "camera_motion_snapshot", "file": output_path})
        time.sleep(interval)

def snapshot_worker(interval: int, require_motion: bool = False):
    """
    Continuously take snapshots every 'interval' seconds. If require_motion=True, only when motion detected.
    """
    if require_motion:
        motion_snapshot_worker(interval)
    else:
        while True:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"cam_{ts}.{DEFAULT_FORMAT}"
            output_path = os.path.join(SCREENSHOT_DIR, filename)
            success = take_snapshot(output_path)
            if success:
                log_event({"type": "camera_snapshot", "file": output_path})
            else:
                log_event({"type": "camera_snapshot_failed"})
            time.sleep(interval)

def start_camera_capture(interval: int = DEFAULT_INTERVAL, require_motion: bool = False):
    """
    Spin up a daemon thread that takes a snapshot every 'interval' seconds (or only on motion).
    Returns the Thread object.
    """
    if cv2 is None:
        logging.error("[camera_ext] OpenCV not installed; camera capture disabled")
        return None
    t = threading.Thread(target=snapshot_worker, args=(interval, require_motion), daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    if cv2 is None:
        print("[!] OpenCV not installed. pip install opencv-python")
        exit(1)
    print(f"[+] One‐time snapshot to {SCREENSHOT_DIR}")
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(SCREENSHOT_DIR, f"one_{ts}.{DEFAULT_FORMAT}")
    if take_snapshot(out):
        print(f"[+] Snapshot saved: {out}")
    else:
        print("[!] Snapshot failed.")
