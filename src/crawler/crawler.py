# crawler/crawler.py

import asyncio
import httpx
from urllib.parse import urljoin, urlparse, parse_qs
import logging
from playwright.async_api import async_playwright

from anonymity.ip_rotator import IPRotator # Import the IPRotator
from .parser import Parser # Import the Parser class
from .subdomain_finder import SubdomainFinder # Import the SubdomainFinder (though not directly used in crawl logic, but for integration)

logger = logging.getLogger(__name__)

class Crawler:
    def __init__(self, base_url: str, ip_rotator: IPRotator, max_depth: int = 5, headless: bool = True):
        """
        Initialise le moteur de crawling.

        Args:
            base_url (str): L'URL de base à partir de laquelle commencer le crawling.
            ip_rotator (IPRotator): Une instance de la classe IPRotator pour la gestion des IPs.
            max_depth (int): La profondeur maximale de crawling.
            headless (bool): Indique si le navigateur Playwright doit fonctionner en mode headless.
        """
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.ip_rotator = ip_rotator
        self.visited_urls = set()
        self.urls_to_visit = asyncio.Queue()
        self.discovered_endpoints = [] # List of dicts: {'url', 'method', 'params', 'type'}
        self.max_depth = max_depth
        self.headless = headless
        self.playwright_browser = None
        self.parser = Parser() # Initialize the parser
        self.subdomain_finder = SubdomainFinder(self.domain, self.ip_rotator) # Initialize subdomain finder

    async def _get_client(self, force_tor: bool = False) -> httpx.AsyncClient:
        """
        Retourne un client HTTPX configuré avec ou sans proxy/Tor selon l'IPRotator.

        Args:
            force_tor (bool): Si True, force l'utilisation de Tor pour ce client.

        Returns:
            httpx.AsyncClient: Un client HTTPX prêt à l'emploi.
        """
        # get_proxies_for_request handles the logic of selecting proxy or Tor
        proxies = await self.ip_rotator.get_proxies_for_request(force_tor=force_tor)
        
        # Ensure the client is created with the chosen proxy configuration
        return httpx.AsyncClient(proxies=proxies, follow_redirects=True, timeout=15) # Increased timeout slightly


    async def _fetch_url(self, url: str, method: str = "GET", data: dict = None, headers: dict = None, force_tor: bool = False) -> httpx.Response | None:
        """
        Récupère le contenu d'une URL en utilisant HTTPX, avec gestion des proxies et rotation d'IP.

        Args:
            url (str): L'URL à récupérer.
            method (str): La méthode HTTP (GET ou POST).
            data (dict): Les données à envoyer pour une requête POST.
            headers (dict): Les en-têtes HTTP à inclure.
            force_tor (bool): Si True, force l'utilisation de Tor pour cette requête.

        Returns:
            httpx.Response | None: L'objet réponse HTTPX si la requête est réussie, None sinon.
        """
        current_proxy_info = f"via {self.ip_rotator.get_current_proxy()} ({self.ip_rotator.get_proxy_type()})" if self.ip_rotator.get_current_proxy() else "directly"
        logger.info(f"Fetching {method} {url} {current_proxy_info}")
        try:
            async with await self._get_client(force_tor=force_tor) as client:
                if method.upper() == "GET":
                    response = await client.get(url, headers=headers)
                elif method.upper() == "POST":
                    response = await client.post(url, data=data, headers=headers)
                else:
                    logger.warning(f"Unsupported HTTP method: {method}")
                    return None
                response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                return response
        except httpx.HTTPStatusError as e:
            clean = e.response.text[:100].replace('\n', ' ')
            logger.warning(f"HTTP error for {url}: {e.response.status_code} - {clean}")
            # Consider rotating IP on certain status codes like 403, 429
            if e.response.status_code in [403, 429, 503]: # Added 503 Service Unavailable
                logger.warning(f"Detected potential block for {url}. Rotating IP.")
                await self.ip_rotator.rotate_ip() # Rotate to next available IP
            return None
        except httpx.RequestError as e:
            logger.error(f"Request error for {url}: {e}")
            await self.ip_rotator.rotate_ip() # Rotate IP on network errors (connection, timeout)
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred fetching {url}: {e}")
            return None

    async def _crawl_js_dynamic(self, url: str) -> tuple[list[str], list[dict]]:
        """
        Récupère et analyse le contenu généré par JavaScript à l'aide de Playwright.

        Args:
            url (str): L'URL à crawler dynamiquement.

        Returns:
            tuple[list[str], list[dict]]: Une liste de liens découverts et une liste de formulaires.
        """
        if not self.playwright_browser:
            logger.warning(f"Playwright browser not initialized. Skipping JS dynamic crawl for {url}")
            return [], []

        logger.info(f"Crawling JS dynamic content for {url}")
        page = None
        try:
            # Playwright doesn't inherently use httpx's proxy settings.
            # For Playwright, proxies are typically set at browser launch or context creation.
            # Here, we pass the current proxy to the launch arguments if it's an HTTP/S proxy.
            # SOCKS proxies with Playwright often require specific setup or environment variables.
            # For simplicity, we'll try to pass it as --proxy-server.
            
            launch_args = []
            current_proxy_address = self.ip_rotator.get_current_proxy()
            if current_proxy_address and not current_proxy_address.startswith("socks"): # Playwright's built-in proxy support for HTTP/S
                launch_args.append(f"--proxy-server={current_proxy_address}")
            elif current_proxy_address and current_proxy_address.startswith("socks"):
                logger.warning(f"Playwright does not natively support SOCKS5h proxies via --proxy-server. For {current_proxy_address}, you might need environment variables (e.g., ALL_PROXY) or a proxy extension.")
                # We won't add it to launch_args in this simple case.
            
            # Re-launch browser with proxy if necessary, or pass proxy to new_context
            # Simpler approach: Launch browser once and hope system proxy or env vars are set.
            # For full Playwright proxy control, consider passing proxy_server to launch.
            # await self.playwright_browser.chromium.launch(headless=self.headless, proxy={"server": current_proxy_address})

            context = await self.playwright_browser.new_context(
                # Playwright's proxy setting is usually done at context level
                # proxy={"server": current_proxy_address} if current_proxy_address else None
                # Or set HTTP_PROXY / HTTPS_PROXY env vars before launching browser
            )
            page = await context.new_page()

            # Listen for network requests if you want to capture them
            # requests_made = []
            # page.on('request', lambda request: requests_made.append(request.url))

            await page.goto(url, wait_until='networkidle')
            content = await page.content()

            # Parse the content for links and forms using the Parser
            links, forms, endpoints_from_js = self.parser.parse_html(content, url)
            
            # Add endpoints discovered from JS to the main list
            for ep in endpoints_from_js:
                self.discovered_endpoints.append(ep)

            # Extract URLs from network requests if we were listening for them
            # For a more robust approach, you'd iterate `requests_made` and parse them.
            # For now, we rely on the HTML parser.

            return list(links), forms

        except Exception as e:
            logger.error(f"Error crawling JS dynamic content for {url}: {e}")
            await self.ip_rotator.rotate_ip() # Rotate IP if Playwright run fails
            return [], []
        finally:
            if page:
                await page.close()

    async def start_crawl(self) -> tuple[list[str], list[dict]]:
        """
        Démarre le processus de crawling.

        Returns:
            tuple[list[str], list[dict]]: Une liste des URLs visitées et une liste des endpoints découverts.
        """
        logger.info(f"Starting crawl for {self.base_url}")
        await self.urls_to_visit.put((self.base_url, 0)) # (url, depth)

        if self.headless:
            logger.info("Initializing Playwright browser for JS crawling...")
            try:
                # Initialize Playwright outside the loop
                pw = await async_playwright().start()
                # Consider adding --proxy-server here if Playwright needs to use a specific proxy
                # E.g., proxy_server_arg = f"--proxy-server={self.ip_rotator.get_current_proxy()}" if self.ip_rotator.get_current_proxy() else None
                # self.playwright_browser = await pw.chromium.launch(headless=True, args=[proxy_server_arg] if proxy_server_arg else [])
                self.playwright_browser = await pw.chromium.launch(headless=True)
                logger.info("Playwright browser launched.")
            except Exception as e:
                logger.error(f"Failed to launch Playwright browser: {e}. JS dynamic crawling will be disabled.")
                self.headless = False # Disable if launch fails

        # Initial validation of proxies on crawler startup
        if self.ip_rotator.proxy_manager:
            logger.info("Performing initial proxy validation...")
            await self.ip_rotator.proxy_manager.validate_all_proxies()
            self.ip_rotator.proxy_manager.rotate_proxy() # Select the first valid proxy

        while not self.urls_to_visit.empty():
            current_url, depth = await self.urls_to_visit.get()

            # Normalize URL before checking visited
            normalized_url = current_url.split('#')[0].rstrip('/') # Remove fragments and trailing slashes
            if normalized_url in self.visited_urls or depth > self.max_depth:
                logger.debug(f"Skipping {normalized_url} (visited or max depth reached)")
                continue

            self.visited_urls.add(normalized_url)
            logger.info(f"Crawling (Depth {depth}): {normalized_url}")

            # First, try to fetch with httpx (for static content)
            response = await self._fetch_url(normalized_url)
            
            # If response is HTML, parse it for links and forms
            if response and response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                links, forms, endpoints_from_html = self.parser.parse_html(response.text, normalized_url)
                
                for link in links:
                    parsed_link = urlparse(link)
                    if parsed_link.netloc == self.domain: # Ensure it's still within the target domain
                        await self.urls_to_visit.put((link, depth + 1))
                
                for form_details in forms:
                    self.discovered_endpoints.append(form_details)

                for ep in endpoints_from_html:
                    self.discovered_endpoints.append(ep)
            
            # Then, if headless is enabled, crawl for dynamic content
            if self.headless:
                js_links, _ = await self._crawl_js_dynamic(normalized_url)
                for link in js_links:
                    parsed_link = urlparse(link)
                    if parsed_link.netloc == self.domain:
                        await self.urls_to_visit.put((link, depth + 1))
            
            # Subdomain discovery can be triggered periodically or at the end
            # Here, we'll do it separately or integrate it more subtly if needed.
            # For a full scan, you might want to call subdomain_finder.find_subdomains()
            # This would likely involve more time, so consider when to run it.

            await asyncio.sleep(1) # Be kind to the server, prevent aggressive hammering

        logger.info("Crawling finished.")
        if self.playwright_browser:
            await self.playwright_browser.close()
            logger.info("Playwright browser closed.")
            
        # Post-processing discovered endpoints: remove duplicates, normalize
        unique_endpoints = {}
        for ep in self.discovered_endpoints:
            # Create a hashable key for uniqueness
            # Use frozenset for params to make it hashable
            params_key = frozenset((p.get('name'), p.get('type'), p.get('value')) for p in ep.get('params', []))
            key = (ep['url'], ep['method'], params_key, ep.get('type')) 
            if key not in unique_endpoints:
                unique_endpoints[key] = ep
        
        self.discovered_endpoints = list(unique_endpoints.values())
        logger.info(f"Discovered {len(self.visited_urls)} unique URLs and {len(self.discovered_endpoints)} potential attack endpoints.")
        return list(self.visited_urls), self.discovered_endpoints

# Example Usage (for testing)
async def test_crawler():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    # Set httpx logger level to WARNING to reduce verbosity
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # For a real test, ensure Tor is running and you have a proxies.txt or list
    # Create a dummy proxy list file for testing if you want to use it
    # with open("proxies_crawler_test.txt", "w") as f:
    #     f.write("http://mock-good-proxy1.com:8080\n")
    #     f.write("http://mock-bad-proxy.com:8081\n") # This will be simulated to fail

    # Initialize IpRotator with some example configuration (adjust as needed for your setup)
    # Using a dummy proxy list and Tor enabled for demonstration.
    # Replace "your_tor_password" if you have one set for your Tor control port.
    ip_rotator = IPRotator(
        proxy_list_path="proxies_crawler_test.txt", # Create this file or pass proxy_list=[]
        tor_enabled=True,
        tor_port=9050,
        tor_control_port=9051,
        tor_password=None # Set your Tor password here if applicable
    )

    # Use a safe, public website for testing (e.g., testphp.vulnweb.com or a simple demo site you control)
    # For a quick test, using an internal IP or a very simple local server is safer and faster.
    target_url = "http://httpbin.org/html" # A simple page for testing parsing
    # target_url = "https://example.com" # A more realistic public site

    # Use async with for IPRotator to ensure it's properly initialized/closed
    async with ip_rotator:
        crawler = Crawler(base_url=target_url, ip_rotator=ip_rotator, max_depth=1, headless=False) # Set headless=True for JS crawling
        
        visited_urls, discovered_endpoints = await crawler.start_crawl()
        
        print("\n--- Visited URLs ---")
        for url in visited_urls:
            print(url)
            
        print("\n--- Discovered Endpoints ---")
        for ep in discovered_endpoints:
            print(f"URL: {ep['url']}, Method: {ep['method']}, Params: {ep['params']}, Type: {ep['type']}")

    print("\n--- Current External IP after crawl ---")
    current_ip = await ip_rotator.get_current_external_ip()
    print(f"IP: {current_ip}, Source: {ip_rotator.get_proxy_type()}")

if __name__ == "__main__":
    asyncio.run(test_crawler())
