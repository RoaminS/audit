# config.py

TARGET_URL = "http://testphp.vulnweb.com" # Change this to your target website for testing
MAX_CRAWL_DEPTH = 3
USE_TOR = False # Set to True to enable Tor rotation
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = "your_tor_password" # Change this if you have a Tor control password

PROXY_LIST_PATH = "proxies.txt" # Path to your proxy list file (one proxy per line, e.g., http://host:port or user:pass@host:port)

REPORT_OUTPUT_DIR = "reports"
REPORT_BRANDING_LOGO = "assets/HebbScan_Logo.png" # Path to your branding logo (optional)

HLN_ITERATIONS_PER_ENDPOINT = 15 # How many times to test each endpoint with HLN
HLN_NUM_NEURONS = 10
HLN_LEARNING_RATE = 0.05
HLN_DECAY_RATE = 0.005

HEADLESS_BROWSER_CRAWLING = True # Use Playwright for dynamic JS crawling

# Logging
LOG_LEVEL = "INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL
