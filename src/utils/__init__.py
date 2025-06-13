# utils/__init__.py

# You can optionally import frequently used utilities here for easier access
from .logger import setup_logging
from .database import get_db_connection, init_db
from .models import Base, URL, DiscoveredEndpoint, Vulnerability, HLNStats

# Example: setting up default logging when utils is imported
setup_logging()
