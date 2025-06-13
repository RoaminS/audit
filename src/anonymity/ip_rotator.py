# anonymity/ip_rotator.py

import asyncio
import httpx
import logging
import time

from .proxy_manager import ProxyManager
from .tor_manager import TorManager

logger = logging.getLogger(__name__)

class IPRotator:
    def __init__(self, proxy_list=None, proxy_list_path=None, tor_enabled=True, tor_port=9050, tor_control_port=9051, tor_password=None,
                 proxy_validation_url='http://ipinfo.io/json', proxy_validation_timeout=5, proxy_rotate_interval=300):
        """
        Classe principale pour la rotation d'IP, intégrant la gestion des proxies et de Tor.

        Args:
            proxy_list (list): Une liste de chaînes de caractères de proxies (e.g., "http://user:pass@host:port").
            proxy_list_path (str): Chemin vers un fichier texte contenant une liste de proxies.
            tor_enabled (bool): Active ou désactive l'utilisation de Tor.
            tor_port (int): Le port SOCKS de Tor.
            tor_control_port (int): Le port de contrôle de Tor.
            tor_password (str): Le mot de passe pour le port de contrôle de Tor.
            proxy_validation_url (str): L'URL utilisée pour valider les proxies.
            proxy_validation_timeout (int): Le délai d'attente en secondes pour la validation des proxies.
            proxy_rotate_interval (int): L'intervalle en secondes pour la rotation des proxies.
        """
        self.proxy_manager = None
        if proxy_list or proxy_list_path:
            self.proxy_manager = ProxyManager(
                proxy_list=proxy_list,
                proxy_list_path=proxy_list_path,
                validation_url=proxy_validation_url,
                validation_timeout=proxy_validation_timeout,
                rotate_interval=proxy_rotate_interval
            )
            if proxy_list:
                logger.info(f"ProxyManager initialized with {len(proxy_list)} proxies from list.")
            elif proxy_list_path:
                logger.info(f"ProxyManager initialized with proxies from file: {proxy_list_path}.")
        else:
            logger.warning("No proxy list or path provided. Requests via proxy will not be possible.")

        self.tor_manager = None
        self.tor_enabled = tor_enabled
        if self.tor_enabled:
            self.tor_manager = TorManager(
                tor_port=tor_port,
                control_port=tor_control_port,
                password=tor_password
            )
            if self.tor_manager.is_connected:
                logger.info(f"TorManager initialized and connected on port {tor_control_port}.")
            else:
                logger.warning("TorManager initialized but could not connect. Tor usage might fail.")
                self.tor_enabled = False # Disable Tor if connection fails

        # Determine default usage based on availability
        self.current_ip_source = None # Can be "proxy", "tor", or "direct"
        self.current_proxy_or_tor_address = None

        if self.proxy_manager and len(self.proxy_manager.proxies) > 0:
            self.current_ip_source = "proxy"
            logger.info("Proxies are configured; they will be used by default.")
        elif self.tor_enabled:
            self.current_ip_source = "tor"
            logger.info("No proxies configured, Tor will be used by default.")
        else:
            self.current_ip_source = "direct"
            logger.info("No proxy or Tor configured. Requests will use direct IP by default.")


    async def get_proxies_for_request(self, force_tor=False):
        """
        Retourne le dictionnaire de proxies approprié pour une requête `httpx`.

        Args:
            force_tor (bool): Si True, force l'utilisation de Tor même si des proxies sont disponibles.

        Returns:
            dict: Dictionnaire au format `{"http://": proxy_url, "https://": proxy_url}` ou None.
        """
        if force_tor and self.tor_enabled and self.tor_manager and self.tor_manager.is_connected:
            logger.debug("Forcing use of Tor for the request.")
            self.current_ip_source = "tor"
            self.current_proxy_or_tor_address = f"socks5h://127.0.0.1:{self.tor_manager.tor_port}"
            return {
                "http://": self.current_proxy_or_tor_address,
                "https://": self.current_proxy_or_tor_address
            }
        elif self.current_ip_source == "proxy" and self.proxy_manager and self.proxy_manager.get_proxy():
            current_proxy = self.proxy_manager.get_proxy()
            logger.debug(f"Using proxy: {current_proxy}")
            self.current_proxy_or_tor_address = current_proxy
            return {
                "http://": current_proxy,
                "https://": current_proxy
            }
        elif self.current_ip_source == "tor" and self.tor_enabled and self.tor_manager and self.tor_manager.is_connected:
            logger.debug("Using Tor as no proxy is available or configured for default.")
            self.current_proxy_or_tor_address = f"socks5h://127.0.0.1:{self.tor_manager.tor_port}"
            return {
                "http://": self.current_proxy_or_tor_address,
                "https://": self.current_proxy_or_tor_address
            }
        else:
            logger.warning("No IP rotation mechanism available or selected. The request will use the direct IP.")
            self.current_ip_source = "direct"
            self.current_proxy_or_tor_address = None
            return None

    async def rotate_ip(self, force_tor=False):
        """
        Déclenche la rotation de l'IP.

        Args:
            force_tor (bool): Si True, force le renouvellement de l'IP Tor. Sinon, tente de faire pivoter le proxy.

        Returns:
            bool: True si la rotation a réussi, False sinon.
        """
        if force_tor and self.tor_enabled:
            logger.info("Attempting to rotate Tor IP (forced)...")
            if self.tor_manager and await self.tor_manager.renew_tor_ip():
                self.current_ip_source = "tor"
                self.current_proxy_or_tor_address = f"socks5h://127.0.0.1:{self.tor_manager.tor_port}"
                return True
            logger.warning("Failed to renew Tor IP (forced).")
            return False
        elif self.proxy_manager:
            logger.info("Attempting to rotate proxy...")
            self.proxy_manager.rotate_proxy()
            # If after rotation, there's a valid proxy, update state
            if self.proxy_manager.get_current_proxy():
                self.current_ip_source = "proxy"
                self.current_proxy_or_tor_address = self.proxy_manager.get_current_proxy()
                return True
            else:
                logger.warning("Proxy rotation did not yield a valid proxy.")
                # If no valid proxy after rotation, try Tor if enabled
                if self.tor_enabled:
                    logger.info("Falling back to Tor after failed proxy rotation.")
                    if self.tor_manager and await self.tor_manager.renew_tor_ip():
                        self.current_ip_source = "tor"
                        self.current_proxy_or_tor_address = f"socks5h://127.0.0.1:{self.tor_manager.tor_port}"
                        return True
            logger.error("No valid IP source available after rotation attempt.")
            self.current_ip_source = "direct"
            self.current_proxy_or_tor_address = None
            return False
        elif self.tor_enabled:
            logger.info("Attempting to rotate Tor IP (default)...")
            if self.tor_manager and await self.tor_manager.renew_tor_ip():
                self.current_ip_source = "tor"
                self.current_proxy_or_tor_address = f"socks5h://127.0.0.1:{self.tor_manager.tor_port}"
                return True
            logger.warning("Failed to renew Tor IP.")
            self.current_ip_source = "direct"
            self.current_proxy_or_tor_address = None
            return False
        else:
            logger.warning("No IP rotation mechanism configured.")
            self.current_ip_source = "direct"
            self.current_proxy_or_tor_address = None
            return False


    async def get_current_external_ip(self):
        """
        Récupère l'adresse IP externe actuelle en utilisant le mécanisme d'IP rotation en place.
        """
        proxies = await self.get_proxies_for_request() # Get the currently selected proxy/Tor config

        try:
            async with httpx.AsyncClient(proxies=proxies, timeout=10) as client:
                response = await client.get('http://ipinfo.io/json')
                if response.status_code == 200:
                    ip_info = response.json()
                    logger.info(f"Current external IP ({self.current_ip_source}): {ip_info.get('ip')}")
                    return ip_info.get('ip')
                else:
                    logger.error(f"Error: Status {response.status_code} when getting IP via {self.current_ip_source}.")
                    # If proxy or Tor failed, mark current source as potentially bad
                    if self.current_ip_source == "proxy" and self.proxy_manager and self.current_proxy_or_tor_address:
                        self.proxy_manager.mark_proxy_invalid(self.current_proxy_or_tor_address)
                    return None
        except httpx.RequestError as e:
            logger.error(f"Error getting IP via {self.current_ip_source}: {e}")
            # If proxy or Tor failed, mark current source as potentially bad
            if self.current_ip_source == "proxy" and self.proxy_manager and self.current_proxy_or_tor_address:
                self.proxy_manager.mark_proxy_invalid(self.current_proxy_or_tor_address)
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred while getting external IP: {e}")
            return None


    def get_current_proxy(self):
        """
        Returns the currently active proxy string, regardless of whether it's an HTTP proxy or Tor.
        """
        return self.current_proxy_or_tor_address

    def get_proxy_type(self):
        """
        Returns the type of IP source currently active ("proxy", "tor", or "direct").
        """
        return self.current_ip_source

    def close(self):
        """
        Ferme toutes les connexions gérées (Tor).
        """
        if self.tor_manager:
            self.tor_manager.close()
        logger.info("IPRotator closed.")

    async def __aenter__(self):
        # Validate all proxies on startup if a proxy manager exists
        if self.proxy_manager:
            await self.proxy_manager.validate_all_proxies()
            # After initial validation, select the first valid proxy
            self.proxy_manager.rotate_proxy() # This will select the first valid one if any
            if self.proxy_manager.get_current_proxy():
                self.current_ip_source = "proxy"
                self.current_proxy_or_tor_address = self.proxy_manager.get_current_proxy()

        # If no proxies or no valid proxies, and Tor is enabled, try to use Tor
        if (not self.proxy_manager or not self.proxy_manager.get_current_proxy()) and self.tor_enabled:
            if self.tor_manager and self.tor_manager.is_connected:
                # Optionally, you could renew Tor IP here on startup
                # await self.tor_manager.renew_tor_ip()
                self.current_ip_source = "tor"
                self.current_proxy_or_tor_address = f"socks5h://127.0.0.1:{self.tor_manager.tor_port}"
            else:
                logger.warning("Tor is enabled but not connected or no valid proxies available. Will use direct IP.")
                self.current_ip_source = "direct"
                self.current_proxy_or_tor_address = None
        elif not self.proxy_manager and not self.tor_enabled:
            logger.warning("Neither proxies nor Tor are enabled. Will use direct IP.")
            self.current_ip_source = "direct"
            self.current_proxy_or_tor_address = None

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logger.info("Testing IPRotator class...")

    # --- Setup for testing ---
    # For a real test, you'd need:
    # 1. Tor running with accessible SOCKS (9050) and Control (9051) ports.
    # 2. Functional HTTP/S proxies if you want to test them.

    # Mock httpx.AsyncClient.get for proxy validation and IP fetching
    original_httpx_get = httpx.AsyncClient.get

    class MockResponse:
        def __init__(self, status_code, ip_address):
            self.status_code = status_code
            self._ip = ip_address

        def json(self):
            return {"ip": self._ip}

    async def mock_httpx_client_get(url, proxies=None, timeout=None):
        if proxies:
            proxy_url = proxies.get("http://") or proxies.get("https://")
            if "mock-bad-proxy.com" in proxy_url:
                logger.debug(f"Simulating proxy failure for {proxy_url}")
                raise httpx.RequestError("Simulated connection error", request=httpx.Request("GET", url))
            elif "mock-good-proxy1.com" in proxy_url:
                logger.debug(f"Simulating success for {proxy_url}")
                return MockResponse(200, "100.100.100.100")
            elif "mock-good-proxy2.com" in proxy_url:
                logger.debug(f"Simulating success for {proxy_url}")
                return MockResponse(200, "200.200.200.200")
            elif "socks5h://127.0.0.1:9050" in proxy_url:
                logger.debug("Simulating Tor IP retrieval")
                # For this simple mock, return a fixed IP for Tor.
                # In a real scenario, this would go through a real Tor connection.
                return MockResponse(200, "3.3.3.3") # Simulated Tor IP
        
        logger.debug("Simulating direct IP retrieval")
        return MockResponse(200, "YOUR_PUBLIC_IP") # Direct IP

    httpx.AsyncClient.get = mock_httpx_client_get

    # Create a dummy proxy list file for testing
    with open("proxies_ip_rotator_test.txt", "w") as f:
        f.write("http://mock-good-proxy1.com:8080\n")
        f.write("http://mock-bad-proxy.com:8081\n")
        f.write("http://mock-good-proxy2.com:8082\n")

    async def run_tests():
        # --- Case 1: Tor only enabled ---
        print("\n--- TEST WITH TOR ONLY ---")
        async with IPRotator(proxy_list=None, tor_enabled=True, tor_password="your_tor_password") as rotator_tor_only:
            print(f"Initial IP (Tor): {await rotator_tor_only.get_current_external_ip()}")
            await asyncio.sleep(1) # Small pause for readability

            print("\nRotating Tor IP...")
            if await rotator_tor_only.rotate_ip(force_tor=True):
                await asyncio.sleep(5) # Give Tor time to change circuit
                print(f"New IP (Tor): {await rotator_tor_only.get_current_external_ip()}")
            else:
                print("Failed to rotate Tor IP or Tor not available.")

        # --- Case 2: Proxies only enabled (from file) ---
        print("\n--- TEST WITH PROXIES ONLY (FROM FILE) ---")
        async with IPRotator(proxy_list_path="proxies_ip_rotator_test.txt", tor_enabled=False, proxy_rotate_interval=5) as rotator_proxies_only:
            print(f"Initial IP (Proxy): {await rotator_proxies_only.get_current_external_ip()}")
            await asyncio.sleep(1)

            print("\nRotating proxy...")
            await rotator_proxies_only.rotate_ip(force_tor=False) # Explicitly rotating proxy
            print(f"New IP (Proxy after rotation): {await rotator_proxies_only.get_current_external_ip()}")

            print("\nWaiting to simulate automatic proxy rotation interval...")
            await asyncio.sleep(6) # Wait longer than rotate_interval (5s)

            print("\nFetching IP after rotation interval...")
            print(f"IP (Proxy after interval): {await rotator_proxies_only.get_current_external_ip()}")

            print("\nAttempting to mark a proxy as invalid and see rotation...")
            # Simulate a request that fails and marks the proxy as invalid
            current_p_before_failure = rotator_proxies_only.proxy_manager.get_current_proxy()
            print(f"Current proxy before simulated failure: {current_p_before_failure}")
            try:
                # Direct call to mock to simulate failure
                await httpx.AsyncClient(proxies={"http://": current_p_before_failure, "https://": current_p_before_failure}, timeout=1).get('http://ipinfo.io/json')
            except httpx.RequestError:
                print(f"Simulated failure for {current_p_before_failure}")
                rotator_proxies_only.proxy_manager.mark_proxy_invalid(current_p_before_failure)

            print(f"Proxy after simulated failure and rotation: {await rotator_proxies_only.get_current_external_ip()}")

        # --- Case 3: Proxies and Tor enabled (proxies prioritized by default) ---
        print("\n--- TEST WITH PROXIES AND TOR (PROXIES PRIORITY) ---")
        example_proxies_mixed_test = [
            "http://proxy1.example.com:8080", # Assume this works
            "http://proxy2.example.com:8080", # Assume this also works
        ]

        # Override mock for mixed test to handle these specific proxies and Tor
        async def mock_mixed_get(url, proxies=None, timeout=None):
            if proxies:
                proxy_url = proxies.get("http://") or proxies.get("https://")
                if "proxy1.example.com" in proxy_url:
                    return MockResponse(200, "1.1.1.1")
                elif "proxy2.example.com" in proxy_url:
                    return MockResponse(200, "2.2.2.2")
                elif f"socks5h://127.0.0.1:{rotator_mixed.tor_manager.tor_port}" in proxy_url:
                    return MockResponse(200, "3.3.3.3") # Simulated Tor IP
            return MockResponse(200, "YOUR_PUBLIC_IP_DIRECT")

        httpx.AsyncClient.get = mock_mixed_get

        async with IPRotator(proxy_list=example_proxies_mixed_test, tor_enabled=True, proxy_rotate_interval=5, tor_password="your_tor_password") as rotator_mixed:
            print(f"Initial IP (proxy priority): {await rotator_mixed.get_current_external_ip()}")
            await asyncio.sleep(1)

            print("\nForcing Tor IP for a specific request...")
            proxies_for_tor_request = await rotator_mixed.get_proxies_for_request(force_tor=True)
            try:
                async with httpx.AsyncClient(proxies=proxies_for_tor_request, timeout=10) as client:
                    response = await client.get('http://ipinfo.io/json')
                    if response.status_code == 200:
                        print(f"IP via Tor (forced): {response.json().get('ip')}")
            except httpx.RequestError as e:
                print(f"Error during forced Tor request: {e}")

            print("\nReturning to default usage (proxies)...")
            await rotator_mixed.rotate_ip(force_tor=False) # Rotate proxy
            print(f"IP after proxy rotation: {await rotator_mixed.get_current_external_ip()}")

    asyncio.run(run_tests())

    # Restore the original function
    httpx.AsyncClient.get = original_httpx_get
    logger.info("IPRotator class tests completed.")
