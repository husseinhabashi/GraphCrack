#!/usr/bin/env python3
"""
Utility functions for GraphQL Crack Engine
"""

import json
import sys
from datetime import datetime

def display_banner():
    """Display tool banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                   GRAPHQL CRACK ENGINE                       ║ 
    ║      Advanced GraphQL Security Assessment Toolkit            ║
    ║                   Authorized Use Only                        ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def legal_warning():
    """Display legal warning"""
    warning = """
       LEGAL WARNING: This tool is for authorized security testing only. 
       Unauthorized use against  systems you don't own or have explicit 
       permission to test is illegal.
       
    By continuing, you acknowledge that you are responsible for 
    ensuring you have proper authorization for any testing activities.
    """
    print(warning)
    print("─" * 60)

def setup_logging():
    """Setup logging configuration"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('graphql_crack.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('GraphQLCrack')

def print_success(message):
    """Print success message"""
    print(f"{message}")

def print_error(message):
    """Print error message"""
    print(f"{message}")

def print_warning(message):
    """Print warning message"""
    print(f"{message}")

def print_info(message):
    """Print info message"""
    print(f"{message}")

def save_json(data, filename):
    """Save data as JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print_error(f"Failed to save {filename}: {e}")
        return False

def load_json(filename):
    """Load data from JSON file"""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except Exception as e:
        print_error(f"Failed to load {filename}: {e}")
        return None