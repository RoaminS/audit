# attack_surface/analyzer.py

import logging
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

class AttackSurfaceAnalyzer:
    """
    Analyse les données collectées (URLs visitées, endpoints, technologies détectées)
    pour identifier les points d'attaque potentiels.
    """
    def __init__(self):
        logger.info("AttackSurfaceAnalyzer initialized.")
        # Dictionnaire pour stocker les points d'attaque catégorisés
        self.attack_points: Dict[str, List[Dict[str, Any]]] = {
            "forms": [],
            "url_parameters": [],
            "headers": [],
            "api_endpoints": [],
            "cookies": [],
            "upload_points": [], # Potential file upload vulnerabilities
            "redirects": [],     # Open redirects
            "error_pages": []    # Pages that reveal sensitive info on error
        }

    def _normalize_url(self, url: str) -> str:
        """Normalise une URL en supprimant le fragment et en triant les paramètres de requête."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        sorted_query = sorted(query_params.items())
        normalized_query = urlencode(sorted_query, doseq=True) # doseq=True handles multiple values for same param
        
        # Reconstruct URL without fragment and with sorted query params
        return urlunparse(parsed._replace(query=normalized_query, fragment=''))

    def analyze_crawler_data(self, visited_urls: List[str], discovered_endpoints: List[Dict[str, Any]]):
        """
        Analyse les données provenant du crawler pour identifier les points d'attaque.

        Args:
            visited_urls (List[str]): Liste des URLs visitées par le crawler.
            discovered_endpoints (List[Dict[str, Any]]): Liste des endpoints découverts
                                                        (incluant formulaires et APIs).
        """
        logger.info("Analyzing crawler data for attack points.")

        # Analyze URLs for parameters
        for url in visited_urls:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            if query_params:
                param_details = {
                    "url": self._normalize_url(url),
                    "method": "GET",
                    "params": [{"name": k, "value": v[0] if v else ""} for k, v in query_params.items()],
                    "location": "URL_QUERY",
                    "description": f"URL with parameters: {url}"
                }
                self.attack_points["url_parameters"].append(param_details)
                logger.debug(f"Identified URL parameters: {url}")

        # Analyze discovered endpoints (forms and APIs)
        for endpoint in discovered_endpoints:
            endpoint_type = endpoint.get('type')
            if endpoint_type == 'FORM':
                form_details = {
                    "url": endpoint['url'],
                    "method": endpoint['method'],
                    "params": endpoint['params'],
                    "location": "FORM",
                    "description": f"HTML Form at {endpoint['url']}"
                }
                self.attack_points["forms"].append(form_details)
                logger.debug(f"Identified form: {endpoint['url']}")
            elif endpoint_type in ['API_JS', 'API_NETWORK', 'API_DATA_ATTR']:
                api_details = {
                    "url": endpoint['url'],
                    "method": endpoint.get('method', 'UNKNOWN'),
                    "params": endpoint.get('params', []),
                    "location": "API_ENDPOINT",
                    "type": endpoint_type,
                    "description": f"API Endpoint: {endpoint['url']}"
                }
                self.attack_points["api_endpoints"].append(api_details)
                logger.debug(f"Identified API endpoint: {endpoint['url']}")
            # Add other endpoint types if needed

        # Deduplicate identified attack points based on normalized URL, method, and parameters
        # This is a simplified deduplication; a more robust one might require hashing parameter names/types
        self._deduplicate_attack_points()
        logger.info(f"Finished analyzing crawler data. Total attack points identified: {sum(len(v) for v in self.attack_points.values())}")

    def analyze_tech_profile(self, tech_profiles: Dict[str, Set[str]]):
        """
        Analyse les technologies détectées pour identifier des points d'attaque connus
        (par exemple, CVEs, configurations par défaut).
        Ceci est une étape conceptuelle; l'intégration de bases de données de CVEs
        serait la prochaine étape.

        Args:
            tech_profiles (Dict[str, Set[str]]): Dictionnaire des technologies détectées par URL.
        """
        logger.info("Analyzing technology profiles for known vulnerabilities/attack vectors.")
        
        # This part would involve:
        # 1. Looking up detected technologies against known vulnerability databases (CVEs).
        # 2. Identifying common misconfigurations based on detected tech (e.g., default admin paths for WordPress).
        # 3. Suggesting specific tests based on tech (e.g., SSTI for templating engines, XSS for JS frameworks).

        for url, techs in tech_profiles.items():
            for tech in techs:
                # Example: If WordPress is detected, suggest checking for common vulnerabilities/plugins
                if tech == "WordPress":
                    self.attack_points["upload_points"].append({
                        "url": f"{url.rstrip('/')}/wp-admin/upload.php", # Common upload path
                        "method": "POST",
                        "params": [{"name": "action", "value": "upload-attachment"}],
                        "location": "Known WP Upload",
                        "description": "Potential WordPress file upload vulnerability (check permissions)."
                    })
                    # Add more specific checks for WordPress here (e.g., xmlrpc.php, default user enumeration)
                
                if tech == "PHP":
                    # Suggest checking for local file inclusion via common parameters
                    self.attack_points["url_parameters"].append({
                        "url": self._normalize_url(url + "?page=test.php"), # Example param
                        "method": "GET",
                        "params": [{"name": "page", "value": "test.php"}],
                        "location": "PHP LFI Potential",
                        "description": "Potential PHP Local File Inclusion (LFI) vulnerability. Test common LFI parameters."
                    })
                
                if tech == "Apache":
                    # Suggest checking for directory listing if not configured correctly
                    self.attack_points["error_pages"].append({
                        "url": url,
                        "method": "GET",
                        "params": [],
                        "location": "Apache Config",
                        "description": "Potential for directory listing or info disclosure on Apache. Check server configuration."
                    })
                
                # Add more rules based on other technologies
                # For example, for Angular/React, suggest client-side XSS.
                # For Node.js/Express, suggest checking for known middleware vulnerabilities.
        
        logger.info("Finished analyzing technology profiles.")


    def _deduplicate_attack_points(self):
        """Dédoublonne les points d'attaque stockés pour éviter les redondances."""
        for category, points_list in self.attack_points.items():
            unique_points = {}
            for point in points_list:
                # Create a hashable key for uniqueness
                # Normalize URL for consistent keys
                normalized_url = self._normalize_url(point['url'])
                
                # Parameters need careful handling for hashing (order, values)
                # Sort params by name and type for a consistent hash
                params_key = frozenset((p.get('name'), p.get('type')) for p in point.get('params', []))
                
                # Combine relevant fields into a tuple for the key
                key_elements = (normalized_url, point.get('method'), point.get('location'), params_key)
                
                # Use frozenset for dictionaries or lists inside the key if they contain variable order
                # For form inputs, frozenset of (name, type) might be sufficient for uniqueness
                
                unique_points[key_elements] = point # Store the original point

            self.attack_points[category] = list(unique_points.values())
        logger.debug("Deduplication of attack points completed.")


    def get_attack_surface_report(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Retourne le rapport final des points d'attaque identifiés.

        Returns:
            Dict[str, List[Dict[str, Any]]]: Un dictionnaire catégorisé des points d'attaque.
        """
        # Final deduplication just in case
        self._deduplicate_attack_points()
        
        report = {}
        for category, points in self.attack_points.items():
            report[category] = sorted(points, key=lambda x: x.get('url', '')) # Sort for consistent output
        
        total_unique_points = sum(len(v) for v in report.values())
        logger.info(f"Generated attack surface report with {total_unique_points} unique attack points.")
        return report

# Example Usage (for testing)
async def test_analyzer():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger("httpx").setLevel(logging.WARNING)

    analyzer = AttackSurfaceAnalyzer()

    # --- Simulate Crawler Data ---
    mock_visited_urls = [
        "http://example.com/",
        "http://example.com/about",
        "http://example.com/products?category=electronics&id=123",
        "http://example.com/contact.html?utm_source=email#section",
        "http://example.com/search?q=test&page=1"
    ]
    mock_discovered_endpoints = [
        # Form
        {'url': 'http://example.com/login', 'method': 'POST', 'params': [{'name': 'username', 'type': 'text', 'value': ''}, {'name': 'password', 'type': 'password', 'value': ''}], 'type': 'FORM'},
        # Another form to test deduplication
        {'url': 'http://example.com/login', 'method': 'POST', 'params': [{'name': 'username', 'type': 'text', 'value': ''}, {'name': 'password', 'type': 'password', 'value': ''}], 'type': 'FORM'},
        # API from JS
        {'url': 'http://example.com/api/v1/users', 'method': 'GET/POST', 'params': [], 'type': 'API_JS'},
        # API from network request (e.g., Playwright)
        {'url': 'http://example.com/api/data?id=abc', 'method': 'GET', 'params': [{'name': 'id', 'value': 'abc'}], 'type': 'API_NETWORK'},
        # Endpoint from data attribute
        {'url': 'http://example.com/endpoint/config', 'method': 'GET/POST', 'params': [], 'type': 'API_DATA_ATTR'},
    ]

    print("\n--- Analyzing Mock Crawler Data ---")
    analyzer.analyze_crawler_data(mock_visited_urls, mock_discovered_endpoints)

    # --- Simulate Tech Profiler Data ---
    mock_tech_profiles = {
        "http://example.com/": {"WordPress", "jQuery"},
        "http://example.com/products": {"PHP", "Nginx"},
        "http://example.com/admin": {"Apache"} # Assuming this URL is part of the crawl
    }

    print("\n--- Analyzing Mock Tech Profiler Data ---")
    analyzer.analyze_tech_profile(mock_tech_profiles)

    final_report = analyzer.get_attack_surface_report()

    print("\n--- Final Attack Surface Report ---")
    for category, points in final_report.items():
        print(f"\nCategory: {category.upper()}")
        if points:
            for i, point in enumerate(points):
                print(f"  {i+1}. URL: {point.get('url', 'N/A')}")
                print(f"     Method: {point.get('method', 'N/A')}")
                print(f"     Location: {point.get('location', 'N/A')}")
                if 'params' in point and point['params']:
                    print(f"     Params: {point['params']}")
                if 'type' in point:
                    print(f"     Type: {point['type']}")
                if 'description' in point:
                    print(f"     Description: {point['description']}")
        else:
            print("  No attack points identified in this category.")

    print("\n--- Attack Surface Analysis Completed ---")

if __name__ == "__main__":
    asyncio.run(test_analyzer())
