# vulnerabilities/xss.py

import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from .base_vulnerability import BaseVulnerability
from .payloads import XSS_PAYLOADS, XSS_DETECTION_PATTERNS

logger = logging.getLogger(__name__)

class XSS(BaseVulnerability):
    """
    Vérifie les vulnérabilités de Cross-Site Scripting (XSS).
    Supporte les XSS réfléchis et potentiellement les XSS stockés (via re-crawl).
    """
    name = "Cross-Site Scripting (XSS)"
    description = "Checks for XSS vulnerabilities by injecting payloads into parameters and observing response."
    severity = "High"
    cwe_id = "CWE-79"
    default_payloads = XSS_PAYLOADS

    def __init__(self, target_url: str, method: str, params: List[Dict[str, Any]], ip_rotator: Any):
        super().__init__(target_url, method, params, ip_rotator)
        logger.debug(f"Initialized XSS check for {target_url}.")

    async def _test_payload(self, url: str, method: str, original_params: List[Dict[str, Any]], payload: str) -> Optional[Any]:
        """
        Envoie une requête avec le payload injecté dans chaque paramètre.

        Args:
            url (str): L'URL cible.
            method (str): La méthode HTTP (GET/POST).
            original_params (List[Dict[str, Any]]): Les paramètres originaux de la requête.
            payload (str): Le payload XSS à injecter.

        Returns:
            Optional[Any]: L'objet réponse httpx si la requête réussit, None sinon.
        """
        for i, param in enumerate(original_params):
            test_params = [p.copy() for p in original_params] # Copy to avoid modifying original list
            test_params[i]['value'] = payload

            if method.upper() == "GET":
                parsed_url = urlparse(url)
                # Build new query string from test_params
                query_parts = []
                for p in test_params:
                    # Handle multiple values for same param name by using doseq=True
                    # urlencode expects a list of (name, value) tuples for multivalue
                    if isinstance(p['value'], list):
                        for val in p['value']:
                            query_parts.append((p['name'], val))
                    else:
                        query_parts.append((p['name'], p['value']))
                
                new_query = urlencode(query_parts, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                response = await self._make_request(test_url, "GET")
            elif method.upper() == "POST":
                post_data = {p['name']: p['value'] for p in test_params}
                response = await self._make_request(url, "POST", data=post_data)
            else:
                return None # Should not happen based on current logic

            if response:
                return response
        return None

    async def check(self) -> List[Dict[str, Any]]:
        """
        Exécute le test XSS en itérant sur les payloads.
        """
        if not self.params:
            logger.debug(f"No parameters for XSS check on {self.target_url}. Skipping.")
            return []

        logger.info(f"Starting XSS check for {self.target_url} ({self.method}) with {len(self.params)} params.")

        # Test with known XSS payloads
        for payload in self.default_payloads:
            logger.debug(f"Testing XSS payload: {payload}")
            response = await self._test_payload(self.target_url, self.method, self.params, payload)

            if response and response.status_code == 200:
                response_text = response.text
                # Check for reflection of the payload and then for XSS detection patterns
                if payload in response_text:
                    for pattern in XSS_DETECTION_PATTERNS:
                        if pattern in response_text:
                            proof = f"Payload '{payload}' reflected and XSS pattern '{pattern}' found in response."
                            self._report_vulnerability(payload, proof)
                            # Optionally, return immediately after first finding or continue for more
                            # return self.found_vulnerabilities # Uncomment to stop on first finding
                            break # Break from pattern loop, continue to next payload

        logger.info(f"Finished XSS check for {self.target_url}.")
        return self.found_vulnerabilities

# Example Usage (for testing)
async def test_xss_vuln():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger("httpx").setLevel(logging.WARNING) # Reduce httpx verbosity

    class MockIPRotator:
        async def get_proxies_for_request(self, force_tor=False):
            class AsyncProxyContext:
                async def __aenter__(self): return None
                async def __aexit__(self, exc_type, exc_val, exc_tb): pass
            return AsyncProxyContext(None)
        async def rotate_ip(self): pass

    ip_rotator = MockIPRotator()

    # Scenario 1: GET request with XSS
    # Simulate a vulnerable endpoint that reflects input
    # For a real test, you'd point this to a known vulnerable lab or your own test server.
    vulnerable_get_url = "http://localhost:8000/reflect?name=test"
    vulnerable_get_params = [{"name": "name", "value": "test_value"}]

    # Mock _make_request for local testing without a live server
    original_make_request = XSS._make_request
    async def mock_make_request_xss_get(self, url, method, data=None, headers=None, allow_redirects=True):
        if urlparse(url).path == "/reflect":
            query_params = parse_qs(urlparse(url).query)
            name_param = query_params.get('name', [''])[0]
            if name_param:
                # Simulate reflection and XSS payload execution
                mock_content = f"<html><body>Hello, {name_param}<script>alert(1)</script></body></html>"
                class MockResponse:
                    status_code = 200
                    text = mock_content
                    @property
                    def content(self): return self.text.encode()
                    def raise_for_status(self): pass
                return MockResponse()
        return None # Fallback to original or return error
    XSS._make_request = mock_make_request_xss_get # Monkey patch

    print("\n--- Testing XSS (GET) ---")
    xss_get_test = XSS(vulnerable_get_url, "GET", vulnerable_get_params, ip_rotator)
    xss_results_get = await xss_get_test.check()
    if xss_results_get:
        for res in xss_results_get:
            print(f"XSS GET Vulnerability Found: {res['url']} - Payload: {res['payload']} - Proof: {res['proof']}")
    else:
        print("No XSS GET vulnerabilities found.")

    # Scenario 2: POST request with XSS
    vulnerable_post_url = "http://localhost:8000/submit"
    vulnerable_post_params = [{"name": "comment", "type": "textarea", "value": "initial_comment"}]

    async def mock_make_request_xss_post(self, url, method, data=None, headers=None, allow_redirects=True):
        if urlparse(url).path == "/submit" and method.upper() == "POST" and data and "comment" in data:
            comment_param = data['comment']
            # Simulate reflection
            mock_content = f"<html><body>Your comment: {comment_param}<script>alert(1)</script></body></html>"
            class MockResponse:
                status_code = 200
                text = mock_content
                @property
                def content(self): return self.text.encode()
                def raise_for_status(self): pass
            return MockResponse()
        return None
    XSS._make_request = mock_make_request_xss_post # Monkey patch

    print("\n--- Testing XSS (POST) ---")
    xss_post_test = XSS(vulnerable_post_url, "POST", vulnerable_post_params, ip_rotator)
    xss_results_post = await xss_post_test.check()
    if xss_results_post:
        for res in xss_results_post:
            print(f"XSS POST Vulnerability Found: {res['url']} - Payload: {res['payload']} - Proof: {res['proof']}")
    else:
        print("No XSS POST vulnerabilities found.")

    # Restore original _make_request
    XSS._make_request = original_make_request

    print("\n--- XSS Tests Completed ---")

if __name__ == "__main__":
    asyncio.run(test_xss_vuln())
