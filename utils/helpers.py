#!/usr/bin/env python3
"""
Utility & CLI helper functions for GraphQL Crack Engine
-------------------------------------------------------
Handles banners, logging, pretty-printing, JSON IO, and console aesthetics.
"""

import sys
import json
import logging
from datetime import datetime

# ANSI color map for rich terminal output (cross-compatible with most shells)
COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "reset": "\033[0m"
}

# ======================================================
# 🧠 CLI Display Elements
# ======================================================
def display_banner():
    """Display ASCII banner"""
    banner = f"""
{COLORS['cyan']}{COLORS['bold']}
╔══════════════════════════════════════════════════════════════╗
║                   GRAPHQL CRACK ENGINE                       ║
║        Advanced GraphQL Security Assessment Toolkit           ║
║                    Authorized Use Only                       ║
╚══════════════════════════════════════════════════════════════╝
{COLORS['reset']}
"""
    print(banner)

def legal_warning():
    """Display legal warning"""
    warning = f"""{COLORS['yellow']}
LEGAL WARNING: This tool is for authorized testing only.
Unauthorized use against systems you do not own or lack
explicit permission to assess is a federal offense.

By continuing, you accept full responsibility for ensuring
your actions are authorized and compliant.
{COLORS['reset']}
{"─" * 60}
"""
    print(warning)


# ======================================================
# ⚙️ Logging System
# ======================================================
def setup_logging(verbose: bool = False):
    """Configure logging (file + stdout)"""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("graphql_crack.log", mode="a", encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger("GraphQLCrack")
    logger.info("Logging initialized.")
    return logger


# ======================================================
# 💬 Colorized Console Output
# ======================================================
def print_success(message: str):
    print(f"{COLORS['green']}[+] {message}{COLORS['reset']}")

def print_error(message: str):
    print(f"{COLORS['red']}[!] {message}{COLORS['reset']}")

def print_warning(message: str):
    print(f"{COLORS['yellow']}[⚠] {message}{COLORS['reset']}")

def print_info(message: str):
    print(f"{COLORS['blue']}[*] {message}{COLORS['reset']}")


# ======================================================
# 📦 JSON IO Helpers
# ======================================================
def save_json(data, filename: str) -> bool:
    """Save dictionary/list to JSON file with timestamp & safe formatting."""
    try:
        safe_name = filename.strip()
        if not safe_name.endswith(".json"):
            safe_name += ".json"

        # Ensure ASCII safety + pretty print
        with open(safe_name, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print_success(f"Saved → {safe_name} ({len(str(data))} bytes)")
        return True
    except Exception as e:
        print_error(f"Failed to save {filename}: {e}")
        return False


def load_json(filename: str):
    """Load JSON from file safely."""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)
        print_success(f"Loaded JSON: {filename}")
        return data
    except FileNotFoundError:
        print_error(f"File not found: {filename}")
    except json.JSONDecodeError:
        print_error(f"Invalid JSON format in {filename}")
    except Exception as e:
        print_error(f"Failed to load {filename}: {e}")
    return None


# ======================================================
# 🧾 Utility Helpers
# ======================================================
def timestamp() -> str:
    """Return current timestamp for logging or filenames."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def write_event_log(message: str, level: str = "INFO"):
    """Append a timestamped event to the GraphQL Crack event log."""
    line = f"[{timestamp()}] [{level}] {message}\n"
    try:
        with open("graphql_events.log", "a", encoding="utf-8") as log:
            log.write(line)
    except Exception:
        pass  # avoid breaking runtime


# ======================================================
# 🧪 CLI Test Mode
# ======================================================
if __name__ == "__main__":
    display_banner()
    legal_warning()
    logger = setup_logging(verbose=True)
    print_info("This is an informational test message.")
    print_success("This is a success message.")
    print_warning("This is a warning.")
    print_error("This is an error.")
    logger.info("Helper utilities loaded successfully.")