#!/usr/bin/env python3
"""
SOC Agent Dependency Installer
Automatically installs required Python packages
"""

import subprocess
import sys
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def install_package(package_name, import_name=None):
    """Install a Python package using pip"""
    if import_name is None:
        import_name = package_name.split('>=')[0].split('==')[0]
    
    try:
        # Try importing first
        __import__(import_name)
        logging.info(f"✓ {import_name} already installed")
        return True
    except ImportError:
        logging.info(f"Installing {package_name}...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", package_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
            logging.info(f"✓ Successfully installed {package_name}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"✗ Failed to install {package_name}: {e}")
            return False

def install_dependencies():
    """Install all required dependencies"""
    logging.info("=" * 60)
    logging.info("SOC Agent - Dependency Installation")
    logging.info("=" * 60)
    
    # Core dependencies (cross-platform)
    dependencies = [
        ("pyyaml>=6.0", "yaml"),
        ("requests>=2.28.0", "requests"),
        ("psutil>=5.9.0", "psutil"),
        ("watchdog>=2.3.0", "watchdog"),
    ]
    
    # Windows-specific dependencies
    if os.name == 'nt':
        dependencies.append(("pywin32>=305", "win32evtlog"))
    
    success_count = 0
    failed_packages = []
    
    for package, import_name in dependencies:
        if install_package(package, import_name):
            success_count += 1
        else:
            failed_packages.append(package)
    
    logging.info("=" * 60)
    logging.info(f"Installation Complete: {success_count}/{len(dependencies)} packages")
    
    if failed_packages:
        logging.error(f"Failed packages: {', '.join(failed_packages)}")
        logging.error("Please install manually using: pip install <package>")
        return False
    else:
        logging.info("✓ All dependencies installed successfully")
        return True

def main():
    """Main entry point"""
    try:
        success = install_dependencies()
        if success:
            logging.info("\n✓ Ready to start SOC Agent")
            logging.info("Run: python src/agent.py")
            sys.exit(0)
        else:
            logging.error("\n✗ Dependency installation failed")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
