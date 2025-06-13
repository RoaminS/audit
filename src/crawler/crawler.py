import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import logging
from playwright.async_api import async_playwright

logger = logging.getLogger(__name__)

class Crawler:
    def __init__(self, base_url, ip_rotator, max_depth=5, headless=True):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.ip_rotator = ip_rotator
        self.visited_urls = set()
        self.urls_to_visit = asyncio.Queue()
        self.discovered_endpoints = [] # (url, method, params, type)
        self.max_depth = max_depth
        self.headless = headless
        self.playwright_browser = None

    async def _get_client(self):
        proxy = self.ip_rotator.get_current_proxy()
        if proxy:
            return httpx.AsyncClient(proxies={"http://": proxy, "https://": proxy}, follow_redirects=True, timeout=10)
        return httpx.AsyncClient(follow_redirects=True, timeout=10)

    async def _fetch_url(self, url, method="GET", data=None, headers=None):
        current_proxy_info = f"via {self.ip_rotator.get_current_proxy()} ({self.ip_rotator.get_proxy_type()})" if self.ip_rotator.get_current_proxy() else "directly"
        logger.info(f"Fetching {method} {url} {current_proxy_info}")
        try:
            async with self._get_client() as client:
                if method.upper() == "GET":
                    response = await client.get(url, headers=headers)
                elif method.upper() == "POST":
                    response = await client.post(url, data=data, headers=headers)
                response.raise_for_status() # Raise an exception for HTTP errors
                return response
        except httpx.HTTPStatusError as e:
            logger.warning(f"HTTP error for {url}: {e.response.status_code} - {e.response.text[:100]}")
            # Consider rotating IP on certain status codes like 403, 429
            if e.response.status_code in [403, 429]:
                logger.warning(f"Detected potential block for {url}. Rotating IP.")
                await self.ip_rotator.rotate_ip()
            return None
        except httpx.RequestError as e:
            logger.error(f"Request error for {url}: {e}")
            await self.ip_rotator.rotate_ip() # Rotate IP on network errors
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred fetching {url}: {e}")
            return None

    async def _parse_html(self, html_content, current_url):
        soup = BeautifulSoup(html_content, 'lxml')
        links = set()
        forms = []

        # Extract links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(current_url, href)
            if urlparse(full_url).netloc == self.domain:
                links.add(full_url)
        
        # Extract forms
        for form_tag in soup.find_all('form'):
            form_action = form_tag.get('action')
            method = form_tag.get('method', 'GET').upper()
            full_action_url = urljoin(current_url, form_action) if form_action else current_url
            
            form_details = {
                'url': full_action_url,
                'method': method,
                'inputs': []
            }
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                input_value = input_tag.get('value', '')
                if input_name:
                    form_details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_value})
            
            forms.append(form_details)
            self.discovered_endpoints.append((full_action_url, method, form_details['inputs'], 'FORM'))

        # Extract script tags for potential API endpoints
        for script_tag in soup.find_all('script'):
            if script_tag.string:
                # Simple regex for now, can be improved with AST parsing for complex JS
                import re
                api_pattern = re.compile(r'["\'](/api/[\w/-]+)["\']')
                for match in api_pattern.finditer(script_tag.string):
                    endpoint = urljoin(current_url, match.group(1))
                    self.discovered_endpoints.append((endpoint, "GET/POST", [], 'API_JS'))
                    links.add(endpoint) # Add to links to visit if it's within domain

        # Extract URLs from CSS, images etc. (can be expanded)
        for link_tag in soup.find_all('link', rel='stylesheet', href=True):
            full_url = urljoin(current_url, link_tag['href'])
            if urlparse(full_url).netloc == self.domain:
                links.add(full_url)
        for img_tag in soup.find_all('img', src=True):
            full_url = urljoin(current_url, img_tag['src'])
            if urlparse(full_url).netloc == self.domain:
                links.add(full_url)
        
        return list(links), forms

    async def _crawl_js_dynamic(self, url):
        if not self.playwright_browser:
            logger.warning("Playwright browser not initialized. Skipping JS dynamic crawl for {url}")
            return [], []

        logger.info(f"Crawling JS dynamic content for {url}")
        page = None
        try:
            page = await self.playwright_browser.new_page()
            # Set proxy if available
            current_proxy = self.ip_rotator.get_current_proxy()
            if current_proxy:
                # Playwright expects a specific proxy format, e.g., 'http://user:pass@host:port'
                # This basic example assumes non-authenticated HTTP proxies. For SOCKS/Auth, more logic is needed.
                # await page.context.set_extra_http_headers({'Proxy-Authorization': '...'})
                # Note: Setting proxy for page context in Playwright is more involved,
                # usually configured at browser launch or via environment variables.
                # For this demo, we'll rely on HTTPX for proxying initial requests.
                # For Playwright, consider using `--proxy-server` arg during launch, or a dedicated library.
                pass 
            
            await page.goto(url, wait_until='networkidle')
            content = await page.content()

            # Capture all network requests made by the page
            requests = []
            page.on('request', lambda request: requests.append(request.url))
            
            # Additional wait to ensure all JS has executed and requests are made
            await asyncio.sleep(2) 

            # Extract new links from the rendered content
            soup = BeautifulSoup(content, 'lxml')
            links = set()
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == self.domain:
                    links.add(full_url)
            
            # Extract potential API endpoints from network requests
            for req_url in requests:
                parsed_req_url = urlparse(req_url)
                if parsed_req_url.netloc == self.domain:
                    # Simple heuristic: if path contains /api/, consider it an API endpoint
                    if "/api/" in parsed_req_url.path:
                        self.discovered_endpoints.append((req_url, "GET/POST", parse_qs(parsed_req_url.query), 'API_NETWORK'))
                        links.add(req_url) # Add to links to potentially crawl
            
            return list(links), [] # Forms are typically static HTML, less dynamic

        except Exception as e:
            logger.error(f"Error crawling JS dynamic content for {url}: {e}")
            return [], []
        finally:
            if page:
                await page.close()

    async def start_crawl(self):
        logger.info(f"Starting crawl for {self.base_url}")
        await self.urls_to_visit.put((self.base_url, 0)) # (url, depth)

        if self.headless:
            logger.info("Initializing Playwright browser for JS crawling...")
            try:
                self.playwright_browser = await async_playwright().start()
                self.playwright_browser = await self.playwright_browser.chromium.launch(headless=True)
                logger.info("Playwright browser launched.")
            except Exception as e:
                logger.error(f"Failed to launch Playwright browser: {e}. JS dynamic crawling will be disabled.")
                self.headless = False # Disable if launch fails

        while not self.urls_to_visit.empty():
            current_url, depth = await self.urls_to_visit.get()

            if current_url in self.visited_urls or depth > self.max_depth:
                continue

            self.visited_urls.add(current_url)
            logger.info(f"Crawling (Depth {depth}): {current_url}")

            # First, try to fetch with httpx (for static content)
            response = await self._fetch_url(current_url)
            if response and response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                links, forms = await self._parse_html(response.text, current_url)
                for link in links:
                    await self.urls_to_visit.put((link, depth + 1))
            
            # Then, if headless is enabled, crawl for dynamic content
            if self.headless:
                js_links, _ = await self._crawl_js_dynamic(current_url)
                for link in js_links:
                    await self.urls_to_visit.put((link, depth + 1))
            
            await asyncio.sleep(1) # Be kind to the server

        logger.info("Crawling finished.")
        if self.playwright_browser:
            await self.playwright_browser.close()
            logger.info("Playwright browser closed.")
        
        # Post-processing discovered endpoints: remove duplicates, normalize
        unique_endpoints = {}
        for url, method, params, _type in self.discovered_endpoints:
            key = (url, method, frozenset((p['name'], p.get('type')) for p in params)) # Use frozenset for params to make it hashable
            if key not in unique_endpoints:
                unique_endpoints[key] = {'url': url, 'method': method, 'params': params, 'type': _type}
        
        self.discovered_endpoints = list(unique_endpoints.values())
        logger.info(f"Discovered {len(self.visited_urls)} unique URLs and {len(self.discovered_endpoints)} potential attack endpoints.")
        return list(self.visited_urls), self.discovered_endpoints

# Example Usage (for testing)
async def test_crawler():
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

    # Dummy IpRotator for testing
    class DummyIpRotator:
        def get_current_proxy(self): return None
        def get_proxy_type(self): return "Direct"
        async def rotate_ip(self): pass

    ip_rotator = DummyIpRotator()
    # Use a safe, public website for testing (e.g., testphp.vulnweb.com or a simple demo site you control)
    target_url = "http://www.google.com" # Replace with a suitable test site
    crawler = Crawler(base_url=target_url, ip_rotator=ip_rotator, max_depth=1, headless=True) # Set headless=False if Playwright is not installed/configured

    visited_urls, discovered_endpoints = await crawler.start_crawl()
    
    print("\n--- Visited URLs ---")
    for url in visited_urls:
        print(url)
    
    print("\n--- Discovered Endpoints ---")
    for ep in discovered_endpoints:
        print(f"URL: {ep['url']}, Method: {ep['method']}, Params: {ep['params']}, Type: {ep['type']}")

if __name__ == "__main__":
    asyncio.run(test_crawler())
