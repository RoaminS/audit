# crawler/parser.py

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import logging

logger = logging.getLogger(__name__)

class Parser:
    def __init__(self):
        logger.info("Parser initialized.")

    def parse_html(self, html_content: str, base_url: str) -> tuple[list[str], list[dict], list[dict]]:
        """
        Analyse le contenu HTML pour extraire les liens, les formulaires et les endpoints potentiels.

        Args:
            html_content (str): Le contenu HTML à analyser.
            base_url (str): L'URL de base pour résoudre les chemins relatifs.

        Returns:
            tuple[list[str], list[dict], list[dict]]:
                - Une liste de liens absolus découverts.
                - Une liste de dictionnaires représentant les formulaires.
                - Une liste de dictionnaires représentant les endpoints API potentiels.
        """
        soup = BeautifulSoup(html_content, 'lxml')
        links = set()
        forms = []
        api_endpoints = [] # New list for API endpoints discovered statically

        domain = urlparse(base_url).netloc

        # Extract links (<a> tags)
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            # Only add links that belong to the same domain (or its subdomains)
            if urlparse(full_url).netloc.endswith(domain) or urlparse(full_url).netloc == domain:
                links.add(full_url)
        logger.debug(f"Found {len(links)} links.")

        # Extract forms
        for form_tag in soup.find_all('form'):
            form_action = form_tag.get('action')
            method = form_tag.get('method', 'GET').upper()
            full_action_url = urljoin(base_url, form_action) if form_action else base_url
            
            form_details = {
                'url': full_action_url,
                'method': method,
                'params': [] # Renamed from 'inputs' to 'params' for consistency with endpoints
            }
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                input_value = input_tag.get('value', '')
                if input_name:
                    form_details['params'].append({'name': input_name, 'type': input_type, 'value': input_value})
            
            forms.append({'url': full_action_url, 'method': method, 'params': form_details['params'], 'type': 'FORM'})
        logger.debug(f"Found {len(forms)} forms.")

        # Extract potential API endpoints from <script> tags and other attributes
        # This is a basic heuristic, can be improved with more sophisticated JS parsing
        api_pattern = re.compile(r'["\'](/(api|rest|graphql)/[\w./-]+)["\']') # Common API patterns

        for script_tag in soup.find_all('script'):
            if script_tag.string:
                for match in api_pattern.finditer(script_tag.string):
                    endpoint_path = match.group(1)
                    full_endpoint_url = urljoin(base_url, endpoint_path)
                    if urlparse(full_endpoint_url).netloc.endswith(domain) or urlparse(full_endpoint_url).netloc == domain:
                        # Assume common methods for API endpoints initially
                        api_endpoints.append({
                            'url': full_endpoint_url,
                            'method': 'GET/POST/PUT/DELETE', # Methods are often dynamic, so list possibilities
                            'params': [], # Parameters would require deeper JS analysis
                            'type': 'API_JS'
                        })
                        links.add(full_endpoint_url) # Add to links to visit if it's within domain
        
        # Also look for data-attributes that might hold URLs (e.g., data-api-url)
        for tag in soup.find_all(lambda tag: tag.has_attr('data-api-url') or tag.has_attr('data-endpoint')):
            api_url = tag.get('data-api-url') or tag.get('data-endpoint')
            if api_url:
                full_api_url = urljoin(base_url, api_url)
                if urlparse(full_api_url).netloc.endswith(domain) or urlparse(full_api_url).netloc == domain:
                    api_endpoints.append({
                        'url': full_api_url,
                        'method': 'GET/POST',
                        'params': [],
                        'type': 'API_DATA_ATTR'
                    })
                    links.add(full_api_url)

        # Extract URLs from CSS, images etc. (can be expanded to other resource types)
        for link_tag in soup.find_all('link', rel='stylesheet', href=True):
            full_url = urljoin(base_url, link_tag['href'])
            if urlparse(full_url).netloc.endswith(domain) or urlparse(full_url).netloc == domain:
                links.add(full_url)
        for img_tag in soup.find_all('img', src=True):
            full_url = urljoin(base_url, img_tag['src'])
            if urlparse(full_url).netloc.endswith(domain) or urlparse(full_url).netloc == domain:
                links.add(full_url)
        
        logger.debug(f"Found {len(api_endpoints)} API endpoints.")
        return list(links), forms, api_endpoints

# Example Usage (for testing)
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    parser = Parser()

    html_content = """
    <html>
    <head>
        <title>Test Page</title>
        <link rel="stylesheet" href="/css/style.css">
    </head>
    <body>
        <h1>Welcome</h1>
        <a href="/about">About Us</a>
        <a href="https://external.com/foo">External Link</a>
        <a href="../contact">Contact</a>
        <img src="/images/logo.png">

        <form action="/login" method="POST">
            <input type="text" name="username" value="guest">
            <input type="password" name="password">
            <button type="submit">Login</button>
        </form>

        <form action="/search" method="GET">
            <input type="text" name="query">
            <input type="hidden" name="csrf_token" value="abc123">
            <button type="submit">Search</button>
        </form>

        <div data-api-url="/api/users"></div>
        <button data-endpoint="/rest/items/123">Fetch Item</button>

        <script>
            console.log("Hello from script");
            const API_BASE = '/api/v1/';
            fetch(API_BASE + 'products').then(res => res.json());
            const userEndpoint = "/graphql";
            $.ajax({ url: userEndpoint + "/users" });
            var dynamicPath = "profile";
            var fullUrl = "/api/v2/" + dynamicPath + "/details";
            window.location.href = "/dashboard";
        </script>
        <script src="/js/app.js"></script>
    </body>
    </html>
    """
    base_url = "http://example.com/some/path/index.html"

    print(f"--- Parsing HTML from {base_url} ---")
    links, forms, api_endpoints = parser.parse_html(html_content, base_url)

    print("\n--- Discovered Links ---")
    for link in links:
        print(link)

    print("\n--- Discovered Forms ---")
    for form in forms:
        print(f"URL: {form['url']}, Method: {form['method']}, Params: {form['params']}")

    print("\n--- Discovered API Endpoints ---")
    for ep in api_endpoints:
        print(f"URL: {ep['url']}, Method: {ep['method']}, Type: {ep['type']}")

    # Test with a different base URL
    print("\n--- Parsing with a different base URL ---")
    html_content_root = """
    <html>
    <body>
        <a href="products">Products</a>
        <form action="login" method="POST"><input name="user"></form>
    </body>
    </html>
    """
    base_url_root = "http://anotherdomain.com/"
    links_root, forms_root, api_endpoints_root = parser.parse_html(html_content_root, base_url_root)
    print("\n--- Discovered Links (Root) ---")
    for link in links_root:
        print(link)
    print("\n--- Discovered Forms (Root) ---")
    for form in forms_root:
        print(f"URL: {form['url']}")
