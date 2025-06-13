# anonymity/proxy_manager.py

import asyncio
import httpx
import logging
import time
from collections import deque

logger = logging.getLogger(__name__)

class ProxyManager:
    def __init__(self, proxy_list=None, proxy_list_path=None, validation_url='http://ipinfo.io/json', validation_timeout=5, rotate_interval=300):
        """
        Gère un pool de proxies, leur rotation et leur validation.

        Args:
            proxy_list (list): Une liste de chaînes de caractères de proxies (e.g., "http://user:pass@host:port").
            proxy_list_path (str): Chemin vers un fichier texte contenant une liste de proxies, un par ligne.
            validation_url (str): L'URL utilisée pour valider les proxies en vérifiant leur IP.
            validation_timeout (int): Le délai d'attente en secondes pour la validation des proxies.
            rotate_interval (int): L'intervalle en secondes après lequel un proxy est marqué comme "à faire pivoter".
        """
        self.proxies = deque()
        self.active_proxies = {}  # {proxy_url: {'last_used': timestamp, 'valid': boolean}}
        self.validation_url = validation_url
        self.validation_timeout = validation_timeout
        self.rotate_interval = rotate_interval

        if proxy_list:
            self._load_proxies_from_list(proxy_list)
        elif proxy_list_path:
            self._load_proxies_from_file(proxy_list_path)
        else:
            logger.warning("No proxy list or path provided. Proxy rotation will be limited.")

        self.current_proxy = None
        self.last_rotation_time = 0

    def _load_proxies_from_list(self, proxy_list):
        """Charge les proxies à partir d'une liste."""
        for proxy_url in proxy_list:
            self.proxies.append(proxy_url)
            self.active_proxies[proxy_url] = {'last_used': 0, 'valid': False}
        logger.info(f"Loaded {len(proxy_list)} proxies from list.")

    def _load_proxies_from_file(self, path):
        """Charge les proxies à partir d'un fichier."""
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.proxies.append(line)
                        self.active_proxies[line] = {'last_used': 0, 'valid': False}
            logger.info(f"Loaded {len(self.proxies)} proxies from {path}")
        except FileNotFoundError:
            logger.error(f"Proxy list file not found: {path}")
        except Exception as e:
            logger.error(f"Error loading proxies from file: {e}")

    async def validate_proxy(self, proxy_url):
        """
        Valide un proxy en tentant une requête via celui-ci de manière asynchrone.

        Args:
            proxy_url (str): L'URL du proxy à valider.

        Returns:
            bool: True si le proxy est valide, False sinon.
        """
        try:
            proxies = {
                "http://": proxy_url,
                "https://": proxy_url,
            }
            async with httpx.AsyncClient(proxies=proxies, timeout=self.validation_timeout) as client:
                response = await client.get(self.validation_url)
                if response.status_code == 200:
                    ip_info = response.json()
                    logger.debug(f"Proxy {proxy_url} valid. IP: {ip_info.get('ip')}")
                    self.active_proxies[proxy_url]['valid'] = True
                    return True
                else:
                    logger.warning(f"Proxy {proxy_url} invalid response: {response.status_code}")
                    self.active_proxies[proxy_url]['valid'] = False
                    return False
        except httpx.RequestError as e:
            logger.warning(f"Proxy {proxy_url} validation failed: {e}")
            self.active_proxies[proxy_url]['valid'] = False
            return False
        except Exception as e:
            logger.warning(f"An unexpected error occurred while validating proxy {proxy_url}: {e}")
            self.active_proxies[proxy_url]['valid'] = False
            return False

    async def validate_all_proxies(self):
        """Valide tous les proxies chargés de manière asynchrone."""
        logger.info("Validating all proxies...")
        tasks = [self.validate_proxy(proxy_url) for proxy_url in list(self.active_proxies.keys())]
        await asyncio.gather(*tasks)
        logger.info("Proxy validation completed.")

    def get_proxy(self):
        """
        Récupère un proxy valide du pool.
        Effectue une rotation si le proxy actuel est trop ancien ou invalide.

        Returns:
            str: L'URL du proxy actuel, ou None si aucun proxy valide n'est disponible.
        """
        if not self.active_proxies:
            logger.warning("No proxies loaded or active.")
            return None

        # Prioritize rotating if current proxy is old or invalid
        if self.current_proxy and (time.time() - self.active_proxies[self.current_proxy]['last_used'] > self.rotate_interval or not self.active_proxies[self.current_proxy]['valid']):
            logger.info(f"Current proxy {self.current_proxy} needs rotation or is invalid. Rotating...")
            self.rotate_proxy()
            return self.current_proxy

        # Initial selection or if current_proxy is None or invalid
        if not self.current_proxy or not self.active_proxies.get(self.current_proxy, {}).get('valid'):
            self.rotate_proxy()
            return self.current_proxy

        return self.current_proxy

    def rotate_proxy(self):
        """
        Fait pivoter le proxy vers le prochain proxy valide disponible dans le pool.
        """
        if not self.proxies:
            logger.warning("No proxies in the pool to rotate.")
            self.current_proxy = None
            return

        initial_len = len(self.proxies)
        for _ in range(initial_len): # Iterate through all available proxies once
            candidate_proxy = self.proxies.popleft()
            if self.active_proxies.get(candidate_proxy, {}).get('valid'):
                self.current_proxy = candidate_proxy
                self.active_proxies[self.current_proxy]['last_used'] = time.time()
                self.proxies.append(candidate_proxy) # Put it back at the end
                logger.info(f"Rotated to proxy: {self.current_proxy}")
                self.last_rotation_time = time.time()
                return
            else:
                # If invalid, put it at the end but don't consider it immediately
                self.proxies.append(candidate_proxy)
                logger.warning(f"Proxy {candidate_proxy} is invalid, skipping for rotation.")

        logger.error("Could not find a valid proxy for rotation. Consider re-validating all proxies.")
        self.current_proxy = None

    def mark_proxy_invalid(self, proxy_url):
        """
        Marque un proxy comme invalide.

        Args:
            proxy_url (str): L'URL du proxy à marquer comme invalide.
        """
        if proxy_url in self.active_proxies:
            self.active_proxies[proxy_url]['valid'] = False
            logger.warning(f"Proxy {proxy_url} marked as invalid.")
            # Trigger a rotation if the current proxy becomes invalid
            if self.current_proxy == proxy_url:
                logger.info("Current proxy became invalid. Triggering immediate rotation.")
                self.rotate_proxy()

    def get_current_proxy(self):
        """
        Retourne le proxy actuellement sélectionné.

        Returns:
            str: L'URL du proxy actuellement sélectionné, ou None.
        """
        return self.current_proxy

    def __len__(self):
        return len(self.proxies)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logger.info("Testing ProxyManager...")

    # Create a dummy proxy list file for testing
    with open("proxies_test.txt", "w") as f:
        f.write("http://mock-good-proxy1.com:8080\n")
        f.write("http://mock-bad-proxy.com:8081\n") # This will be simulated to fail
        f.write("http://mock-good-proxy2.com:8082\n")

    # Mocking httpx.AsyncClient for demonstration purposes
    # In a real scenario, these would be actual network requests.
    class MockResponse:
        def __init__(self, status_code, json_data=None):
            self.status_code = status_code
            self._json_data = json_data

        def json(self):
            return self._json_data

    async def mock_httpx_get(url, proxies=None, timeout=None):
        if proxies and "mock-bad-proxy.com" in proxies.get('http://', ''):
            logger.debug(f"Simulating failure for {proxies.get('http://')}")
            raise httpx.RequestError("Simulated connection error", request=httpx.Request("GET", url))
        elif proxies and ("mock-good-proxy1.com" in proxies.get('http://', '') or "mock-good-proxy2.com" in proxies.get('http://', '')):
            logger.debug(f"Simulating success for {proxies.get('http://')}")
            ip = "192.168.1.1" if "mock-good-proxy1.com" in proxies.get('http://', '') else "192.168.1.2"
            return MockResponse(200, {"ip": ip})
        else:
            # Fallback for direct requests if needed, but in this test, proxies are always used.
            return MockResponse(200, {"ip": "127.0.0.1"}) # Direct IP

    # Patch httpx.AsyncClient.get to use our mock
    original_httpx_get = httpx.AsyncClient.get
    httpx.AsyncClient.get = mock_httpx_get

    async def main():
        pm = ProxyManager(proxy_list_path="proxies_test.txt", validation_url='http://mock-ipinfo.io/json', rotate_interval=10)

        await pm.validate_all_proxies()

        print("\nAttempting to get the first proxy...")
        current_p = pm.get_proxy()
        if current_p:
            print(f"Current proxy: {current_p}")
        else:
            print("No proxy could be retrieved.")

        print("\nWaiting to simulate rotation interval...")
        await asyncio.sleep(11) # Wait longer than rotate_interval

        print("\nAttempting to get a new proxy after interval...")
        current_p = pm.get_proxy()
        if current_p:
            print(f"New proxy after rotation: {current_p}")
        else:
            print("No new proxy could be retrieved after rotation.")

        print("\nMarking current proxy as invalid and triggering rotation...")
        if pm.get_current_proxy():
            pm.mark_proxy_invalid(pm.get_current_proxy())
            print(f"Proxy after marking invalid: {pm.get_current_proxy()}")
        else:
            print("No current proxy to mark invalid.")

    asyncio.run(main())

    # Restore the original function
    httpx.AsyncClient.get = original_httpx_get
    logger.info("ProxyManager test completed.")
