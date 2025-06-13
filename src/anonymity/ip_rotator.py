import asyncio
import httpx
import logging
import random
from collections import deque

logger = logging.getLogger(__name__)

class ProxyManager:
    def __init__(self, proxy_list_path=None):
        self.proxies = deque()
        if proxy_list_path:
            self._load_proxies(proxy_list_path)
        else:
            logger.warning("No proxy list path provided. IP rotation will be limited.")

    def _load_proxies(self, path):
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.proxies.append(line)
            logger.info(f"Loaded {len(self.proxies)} proxies from {path}")
        except FileNotFoundError:
            logger.error(f"Proxy list file not found: {path}")
        except Exception as e:
            logger.error(f"Error loading proxies: {e}")

    async def validate_proxy(self, proxy_url, timeout=5):
        try:
            async with httpx.AsyncClient(proxies={"http://": proxy_url, "https://": proxy_url}, timeout=timeout) as client:
                response = await client.get("http://httpbin.org/ip") # Test with a public IP checker
                if response.status_code == 200 and 'origin' in response.json():
                    logger.debug(f"Proxy {proxy_url} is valid. Origin IP: {response.json().get('origin')}")
                    return True
                else:
                    logger.warning(f"Proxy {proxy_url} invalid response: {response.status_code}")
                    return False
        except httpx.RequestError as e:
            logger.warning(f"Proxy {proxy_url} failed: {e}")
            return False
        except Exception as e:
            logger.warning(f"An unexpected error occurred while validating proxy {proxy_url}: {e}")
            return False

    async def get_valid_proxy(self):
        if not self.proxies:
            logger.warning("No proxies available in the pool.")
            return None

        for _ in range(len(self.proxies)): # Try all proxies once
            proxy = self.proxies.popleft()
            self.proxies.append(proxy) # Put it back at the end
            if await self.validate_proxy(proxy):
                logger.info(f"Using proxy: {proxy}")
                return proxy
            else:
                logger.warning(f"Removing invalid proxy: {proxy}")
        logger.error("No valid proxies found in the pool after attempting to validate all.")
        return None

class TorManager:
    def __init__(self, tor_port=9050, control_port=9051, password=None):
        try:
            from stem import Signal
            from stem.control import Controller
            self.tor_port = tor_port
            self.control_port = control_port
            self.password = password
            self.controller = None
            logger.info(f"TorManager initialized with SOCKS port {tor_port} and Control port {control_port}")
        except ImportError:
            logger.error("Stem library not found. Tor functionality will be disabled. Install with 'pip install stem'")
            self.tor_port = None

    def connect(self):
        if not self.tor_port:
            return False
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate(password=self.password)
            logger.info("Connected to Tor controller.")
            return True
        except Exception as e:
            logger.error(f"Could not connect to Tor controller: {e}. Make sure Tor is running.")
            self.controller = None
            return False

    def new_identity(self):
        if not self.controller:
            logger.warning("Tor controller not connected. Cannot request new identity.")
            return False
        try:
            self.controller.signal(Signal.NEWNYM)
            logger.info("Requested new Tor identity.")
            return True
        except Exception as e:
            logger.error(f"Error requesting new Tor identity: {e}")
            return False

    def get_tor_proxy(self):
        if self.tor_port:
            return f"socks5://127.0.0.1:{self.tor_port}"
        return None

class IpRotator:
    def __init__(self, proxy_list_path=None, use_tor=False, tor_port=9050, tor_control_port=9051, tor_password=None):
        self.proxy_manager = ProxyManager(proxy_list_path)
        self.use_tor = use_tor
        self.tor_manager = None
        if self.use_tor:
            self.tor_manager = TorManager(tor_port, tor_control_port, tor_password)
            if not self.tor_manager.connect():
                logger.error("Failed to connect to Tor. Disabling Tor rotation.")
                self.use_tor = False
        
        self.current_proxy = None
        self.proxy_type = None

    async def rotate_ip(self, force_tor=False):
        if force_tor and self.use_tor:
            if self.tor_manager.new_identity():
                self.current_proxy = self.tor_manager.get_tor_proxy()
                self.proxy_type = "Tor"
                logger.info(f"Switched to new Tor IP: {self.current_proxy}")
                return self.current_proxy
            else:
                logger.warning("Failed to get new Tor identity. Falling back to proxy pool if available.")
        
        proxy = await self.proxy_manager.get_valid_proxy()
        if proxy:
            self.current_proxy = proxy
            self.proxy_type = "HTTP/SOCKS Proxy"
            logger.info(f"Switched to proxy from pool: {self.current_proxy}")
            return self.current_proxy
        elif self.use_tor: # Try Tor if no proxies or if proxy pool failed
            if self.tor_manager.new_identity():
                self.current_proxy = self.tor_manager.get_tor_proxy()
                self.proxy_type = "Tor"
                logger.info(f"Switched to new Tor IP (fallback): {self.current_proxy}")
                return self.current_proxy
        
        logger.error("No valid IP source available. Continuing without proxy.")
        self.current_proxy = None
        self.proxy_type = "Direct"
        return None

    def get_current_proxy(self):
        return self.current_proxy

    def get_proxy_type(self):
        return self.proxy_type

# Example usage (for testing)
async def test_ip_rotator():
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

    # Create a dummy proxy list file for testing
    with open("proxies.txt", "w") as f:
        f.write("http://1.2.3.4:8080\n") # This will likely fail, but demonstrates validation
        f.write("http://proxy.example.com:8080\n") 
        f.write("http://another.valid.proxy:3128\n") # Add real, working proxies here for success

    rotator = IpRotator(proxy_list_path="proxies.txt", use_tor=True, tor_port=9050, tor_control_port=9051, tor_password="your_tor_password") # Replace with your Tor password if applicable
    
    print("\n--- Initial IP ---")
    await rotator.rotate_ip()
    print(f"Current IP source: {rotator.get_proxy_type()} - {rotator.get_current_proxy()}")

    print("\n--- Forced Tor IP ---")
    await rotator.rotate_ip(force_tor=True)
    print(f"Current IP source: {rotator.get_proxy_type()} - {rotator.get_current_proxy()}")

    print("\n--- Rotate from pool ---")
    await rotator.rotate_ip()
    print(f"Current IP source: {rotator.get_proxy_type()} - {rotator.get_current_proxy()}")

if __name__ == "__main__":
    asyncio.run(test_ip_rotator())
