# vulnerabilities/__init__.py

# This file makes the 'vulnerabilities' directory a Python package.
# It's good practice to import core components here for easier access.

from .base_vulnerability import BaseVulnerability
from .xss import XSS
from .sqli import SQLi
from .rce import RCE
from .ssrf import SSRF
from .lfi import LFI
from .logic_flaws import LogicFlaws # Assuming this will be a class

# You can also import payloads here for convenience if needed later, e.g.:
# from . import payloads
