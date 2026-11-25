
from pathlib import Path

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Application information
APP_TITLE = "LinkShield"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Cybersecurity URL and File Analysis Platform"

# Frontend directories
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Application settings
DEBUG = True
