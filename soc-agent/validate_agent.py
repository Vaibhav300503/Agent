#!/usr/bin/env python3
"""
SOC Agent Validation Script
Comprehensive testing and validation of all collectors and features
"""

import sys
import os
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)

def validate_file_exists(filepath, description):
    """Validate that a file exists"""
    if os.path.exists(filepath):
        logging.info(f"✓ {description}: {filepath}")
        return True
    else:
        logging.error(f"✗ {description} NOT FOUND: {filepath}")
        return False

def validate_imports():
    """Validate all critical imports work"""
    logging.info("\n" + "="*60)
    logging.info("Testing Imports")
    logging.info("="*60)
    
    imports_ok = True
    
    # Test core dependencies
    try:
        import yaml
        logging.info("✓ yaml (PyYAML)")
    except ImportError:
        logging.error("✗ yaml (PyYAML) - MISSING")
        imports_ok = False
    
    try:
        import requests
        logging.info("✓ requests")
    except ImportError:
        logging.error("✗ requests - MISSING")
        imports_ok = False
    
    try:
        import psutil
        logging.info("✓ psutil")
    except ImportError:
        logging.error("✗ psutil - MISSING (required for network monitoring)")
        imports_ok = False
    
    try:
        import watchdog
        logging.info("✓ watchdog")
    except ImportError:
        logging.error("✗ watchdog - MISSING (required for FIM)")
        imports_ok = False
    
    # Windows-specific
    if os.name == 'nt':
        try:
            import win32evtlog
            logging.info("✓ win32evtlog (pywin32)")
        except ImportError:
            logging.error("✗ win32evtlog (pywin32) - MISSING (required on Windows)")
            imports_ok = False
    
    return imports_ok

def validate_file_structure():
    """Validate all required files exist"""
    logging.info("\n" + "="*60)
    logging.info("Validating File Structure")
    logging.info("="*60)
    
    base_path = os.path.dirname(os.path.abspath(__file__))
    
    required_files = {
        'src/agent.py': 'Main Agent',
        'src/config.py': 'Configuration Module',
        'src/transport.py': 'Transport Module',
        'src/utils.py': 'Utilities Module',
        'src/collectors/base.py': 'Base Collector',
        'src/collectors/windows.py': 'Windows Collector',
        'src/collectors/linux.py': 'Linux Collector',
        'src/collectors/network.py': 'Network Collector',
        'src/collectors/fim.py': 'FIM Collector',
        'requirements.txt': 'Dependencies File',
        'install_dependencies.py': 'Dependency Installer'
    }
    
    all_exist = True
    for file_path, description in required_files.items():
        full_path = os.path.join(base_path, file_path)
        if not validate_file_exists(full_path, description):
            all_exist = False
    
    return all_exist

def validate_collectors():
    """Validate collector implementations"""
    logging.info("\n" + "="*60)
    logging.info("Validating Collectors")
    logging.info("="*60)
    
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))
    
    collectors_ok = True
    
    try:
        from collectors.base import BaseCollector
        logging.info("✓ BaseCollector imports successfully")
        
        # Check required methods
        required_methods = ['start', 'stop', 'send_log']
        for method in required_methods:
            if hasattr(BaseCollector, method):
                logging.info(f"  ✓ Method '{method}' exists")
            else:
                logging.error(f"  ✗ Method '{method}' MISSING")
                collectors_ok = False
    except Exception as e:
        logging.error(f"✗ BaseCollector import failed: {e}")
        collectors_ok = False
    
    # Test Windows collector
    if os.name == 'nt':
        try:
            from collectors.windows import WindowsCollector
            logging.info("✓ WindowsCollector imports successfully")
            
            # Check inheritance
            if issubclass(WindowsCollector, BaseCollector):
                logging.info("  ✓ Inherits from BaseCollector")
            else:
                logging.error("  ✗ Does NOT inherit from BaseCollector")
                collectors_ok = False
        except Exception as e:
            logging.error(f"✗ WindowsCollector import failed: {e}")
            collectors_ok = False
    
    # Test Linux collector
    try:
        from collectors.linux import LinuxCollector
        logging.info("✓ LinuxCollector imports successfully")
        
        if issubclass(LinuxCollector, BaseCollector):
            logging.info("  ✓ Inherits from BaseCollector")
        else:
            logging.error("  ✗ Does NOT inherit from BaseCollector")
            collectors_ok = False
    except Exception as e:
        logging.error(f"✗ LinuxCollector import failed: {e}")
        collectors_ok = False
    
    # Test Network collector
    try:
        from collectors.network import NetworkCollector
        logging.info("✓ NetworkCollector imports successfully")
        
        if issubclass(NetworkCollector, BaseCollector):
            logging.info("  ✓ Inherits from BaseCollector")
        else:
            logging.error("  ✗ Does NOT inherit from BaseCollector")
            collectors_ok = False
    except Exception as e:
        logging.error(f"✗ NetworkCollector import failed: {e}")
        collectors_ok = False
    
    # Test FIM collector
    try:
        from collectors.fim import FIMCollector
        logging.info("✓ FIMCollector imports successfully")
        
        if issubclass(FIMCollector, BaseCollector):
            logging.info("  ✓ Inherits from BaseCollector")
        else:
            logging.error("  ✗ Does NOT inherit from BaseCollector")
            collectors_ok = False
    except Exception as e:
        logging.error(f"✗ FIMCollector import failed: {e}")
        collectors_ok = False
    
    return collectors_ok

def validate_config():
    """Validate configuration module"""
    logging.info("\n" + "="*60)
    logging.info("Validating Configuration")
    logging.info("="*60)
    
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))
    
    try:
        from config import Config
        logging.info("✓ Config module imports successfully")
        
        # Test default config generation
        config = Config()
        logging.info("✓ Config object created")
        
        # Check properties
        required_properties = [
            'server_url', 'api_token', 'polling_interval',
            'enable_fim', 'enable_network_monitoring'
        ]
        
        for prop in required_properties:
            if hasattr(config, prop):
                logging.info(f"  ✓ Property '{prop}' exists")
            else:
                logging.error(f"  ✗ Property '{prop}' MISSING")
                return False
        
        return True
    except Exception as e:
        logging.error(f"✗ Config validation failed: {e}")
        return False

def main():
    """Run all validation checks"""
    logging.info("="*60)
    logging.info("SOC Agent - Comprehensive Validation")
    logging.info("="*60)
    
    results = {
        'Imports': validate_imports(),
        'File Structure': validate_file_structure(),
        'Collectors': validate_collectors(),
        'Configuration': validate_config()
    }
    
    logging.info("\n" + "="*60)
    logging.info("Validation Summary")
    logging.info("="*60)
    
    all_passed = True
    for category, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        logging.info(f"{category}: {status}")
        if not passed:
            all_passed = False
    
    logging.info("="*60)
    
    if all_passed:
        logging.info("\n✓✓✓ ALL VALIDATIONS PASSED ✓✓✓")
        logging.info("SOC Agent is ready for deployment")
        return 0
    else:
        logging.error("\n✗✗✗ VALIDATION FAILED ✗✗✗")
        logging.error("Please fix the issues above before deployment")
        return 1

if __name__ == "__main__":
    sys.exit(main())
