# crawler/subdomain_finder.py

import asyncio
import httpx
import logging
from urllib.parse import urlparse

from anonymity.ip_rotator import IPRotator

logger = logging.getLogger(__name__)

class SubdomainFinder:
    def __init__(self, base_domain: str, ip_rotator: IPRotator, wordlist_path: str = None):
        """
        Initialise le module de découverte de sous-domaines.

        Args:
            base_domain (str): Le domaine cible pour la découverte de sous-domaines (e.g., "example.com").
            ip_rotator (IPRotator): Une instance de la classe IPRotator pour les requêtes anonymes.
            wordlist_path (str): Chemin vers un fichier de wordlist pour la force brute de sous-domaines.
        """
        self.base_domain = base_domain
        self.ip_rotator = ip_rotator
        self.wordlist = self._load_wordlist(wordlist_path) if wordlist_path else []
        self.discovered_subdomains = set()
        logger.info(f"SubdomainFinder initialized for domain: {base_domain}")

    def _load_wordlist(self, path: str) -> list[str]:
        """Charge une wordlist à partir d'un fichier."""
        try:
            with open(path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            logger.info(f"Loaded {len(wordlist)} words from wordlist: {path}")
            return wordlist
        except FileNotFoundError:
            logger.error(f"Wordlist file not found: {path}")
            return []
        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")
            return []

    async def _check_subdomain(self, subdomain: str) -> str | None:
        """
        Vérifie si un sous-domaine existe et est accessible.

        Args:
            subdomain (str): Le sous-domaine complet à vérifier (e.g., "www.example.com").

        Returns:
            str | None: Le sous-domaine s'il est accessible, None sinon.
        """
        test_url_http = f"http://{subdomain}"
        test_url_https = f"https://{subdomain}"
        
        proxies_config = await self.ip_rotator.get_proxies_for_request()
        async with httpx.AsyncClient(proxies=proxies_config, follow_redirects=True, timeout=5) as client:
            for url_to_check in [test_url_https, test_url_http]: # Prioritize HTTPS
                try:
                    logger.debug(f"Checking subdomain: {url_to_check}")
                    response = await client.get(url_to_check)
                        if response.status_code < 400:  # 2xx or 3xx status codes
                            logger.info(f"Subdomain discovered: {subdomain} (Status: {response.status_code})")
                            self.discovered_subdomains.add(subdomain)
                            return subdomain
                    except httpx.RequestError as e:
                        logger.debug(f"Subdomain {url_to_check} not accessible: {e}")
                        # Don't rotate IP here, as it's a brute-force check,
                        # and individual subdomain failures might not indicate a block.
                        # IP rotation is better handled by the main crawler's fetch logic.
                    except Exception as e:
                        logger.error(f"Unexpected error checking subdomain {url_to_check}: {e}")
        return None

    async def brute_force_subdomains(self, concurrency: int = 100) -> list[str]:
        """
        Découvre des sous-domaines par force brute en utilisant la wordlist.

        Args:
            concurrency (int): Le nombre de requêtes concurrentes à effectuer.

        Returns:
            list[str]: Une liste des sous-domaines découverts.
        """
        if not self.wordlist:
            logger.warning("No wordlist loaded for subdomain brute-forcing. Skipping.")
            return []

        logger.info(f"Starting subdomain brute-force for {self.base_domain} with {len(self.wordlist)} words...")
        tasks = []
        for prefix in self.wordlist:
            subdomain = f"{prefix}.{self.base_domain}"
            tasks.append(self._check_subdomain(subdomain))

        # Use asyncio.gather with a semaphore to control concurrency
        semaphore = asyncio.Semaphore(concurrency)
        async def bounded_check(sub):
            async with semaphore:
                return await self._check_subdomain(sub)

        results = await asyncio.gather(*[bounded_check(f"{prefix}.{self.base_domain}") for prefix in self.wordlist])
        
        # Filter out None results
        discovered = [s for s in results if s is not None]
        logger.info(f"Finished subdomain brute-force. Discovered {len(discovered)} subdomains.")
        return discovered

    async def passive_subdomain_discovery(self) -> list[str]:
        """
        Découvre des sous-domaines passivement en interrogeant des sources publiques.
        (Par exemple, Google dorks, Certificate Transparency logs, etc.)
        Pour cet exemple, nous simulerons quelques requêtes.

        Returns:
            list[str]: Une liste des sous-domaines découverts passivement.
        """
        logger.info(f"Starting passive subdomain discovery for {self.base_domain}...")
        
        passive_sources = [
            f"https://crt.sh/?q=%.{self.base_domain}&output=json",
            # Add other passive sources like public DNS databases, search engine results pages (SERP)
            # Be careful with rate limits for public services.
        ]

        found_subdomains = set()
        
        proxies_config = await self.ip_rotator.get_proxies_for_request()
        async with httpx.AsyncClient(proxies=proxies_config, follow_redirects=True, timeout=10) as client:
            for source_url in passive_sources:
                try:
                    logger.debug(f"Querying passive source: {source_url}")
                    response = await client.get(source_url)
                    response.raise_for_status()
                        
                        if "crt.sh" in source_url:
                            data = response.json()
                            for entry in data:
                                # Extract common name and SANs
                                name_value = entry.get('name_value')
                                if name_value:
                                    # Split by newline or comma to get individual domains
                                    for domain_entry in re.split(r'\s*,\s*|\n', name_value):
                                        if domain_entry.endswith(self.base_domain) and domain_entry != self.base_domain:
                                            # Remove wildcard prefix if present
                                            clean_domain = domain_entry.lstrip('*')
                                            if clean_domain.startswith('.'):
                                                clean_domain = clean_domain[1:]
                                            found_subdomains.add(clean_domain)
                                            logger.debug(f"Discovered passive subdomain: {clean_domain}")
                    except httpx.RequestError as e:
                        logger.warning(f"Error querying passive source {source_url}: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error in passive discovery from {source_url}: {e}")

        self.discovered_subdomains.update(found_subdomains)
        logger.info(f"Finished passive subdomain discovery. Discovered {len(found_subdomains)} new subdomains.")
        return list(found_subdomains)

    async def find_subdomains(self, brute_force: bool = True, passive: bool = True, concurrency: int = 100) -> list[str]:
        """
        Lance le processus de découverte de sous-domaines.

        Args:
            brute_force (bool): Active la découverte par force brute.
            passive (bool): Active la découverte passive.
            concurrency (int): Le niveau de concurrence pour la force brute.

        Returns:
            list[str]: Une liste de tous les sous-domaines uniques découverts.
        """
        logger.info(f"Starting overall subdomain discovery for {self.base_domain}...")
        
        tasks = []
        if passive:
            tasks.append(self.passive_subdomain_discovery())
        if brute_force and self.wordlist:
            tasks.append(self.brute_force_subdomains(concurrency))
        
        if tasks:
            await asyncio.gather(*tasks) # Run both methods concurrently if enabled
        else:
            logger.warning("No subdomain discovery methods enabled or no wordlist for brute-force.")

        logger.info(f"Total unique subdomains found for {self.base_domain}: {len(self.discovered_subdomains)}")
        return list(self.discovered_subdomains)

# Example Usage (for testing)
async def test_subdomain_finder():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    # Set httpx logger level to WARNING to reduce verbosity
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Dummy IpRotator for testing
    # In a real scenario, you'd pass a configured IPRotator instance
    class DummyIpRotator:
        def __init__(self):
            # Mock get_proxies_for_request to return None for direct connection
            self.proxies_for_request = None
            self.current_proxy = None
            self.proxy_type = "Direct"

        async def get_proxies_for_request(self, force_tor=False):
            # For testing, simply return None to indicate a direct connection
            return None
            
        def get_current_proxy(self): return self.current_proxy
        def get_proxy_type(self): return self.proxy_type
        async def rotate_ip(self): pass # No-op for dummy

    ip_rotator = DummyIpRotator()
    target_domain = "example.com" # Replace with a domain you have permission to test

    # Create a dummy wordlist file
    with open("subdomain_wordlist_test.txt", "w") as f:
        f.write("www\n")
        f.write("mail\n")
        f.write("blog\n")
        f.write("dev\n") # This one might not exist
        f.write("test\n")

    # Mock httpx.AsyncClient.get for subdomain checking (simulate some success/failure)
    original_httpx_get = httpx.AsyncClient.get

    async def mock_subdomain_httpx_get(url, proxies=None, timeout=None):
        if "www.example.com" in url or "mail.example.com" in url or "blog.example.com" in url or "crt.sh" in url:
            # Simulate successful response for these
            class MockResponse:
                def __init__(self, status_code, content=None, json_data=None):
                    self.status_code = status_code
                    self._content = content
                    self._json_data = json_data

                def json(self):
                    if self._json_data: return self._json_data
                    if "crt.sh" in url: # Simulate crt.sh response
                        return [{"name_value": f"www.{target_domain}\nsub1.{target_domain},sub2.{target_domain}", "id": 123}]
                    return {} # Default empty json

                @property
                def content(self):
                    return self._content.encode() if self._content else b''

                @property
                def text(self):
                    return self._content if self._content else ''

            return MockResponse(200, content="<html><body>Success</body></html>")
        else:
            # Simulate failure for others (e.g., dev.example.com)
            raise httpx.RequestError(f"Simulated connection error for {url}", request=httpx.Request("GET", url))

    httpx.AsyncClient.get = mock_subdomain_httpx_get

    sub_finder = SubdomainFinder(base_domain=target_domain, ip_rotator=ip_rotator, wordlist_path="subdomain_wordlist_test.txt")

    print(f"--- Discovering subdomains for {target_domain} ---")
    
    # Run both brute-force and passive discovery
    found_subdomains = await sub_finder.find_subdomains(brute_force=True, passive=True, concurrency=50)

    print("\n--- Discovered Subdomains ---")
    if found_subdomains:
        for sd in sorted(found_subdomains):
            print(sd)
    else:
        print("No subdomains found.")

    # Restore the original function
    httpx.AsyncClient.get = original_httpx_get

    print("\nSubdomainFinder test completed.")

if __name__ == "__main__":
    asyncio.run(test_subdomain_finder())
