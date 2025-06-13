# vulnerabilities/ssrf.py

import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse
import re

from .base_vulnerability import BaseVulnerability
from .payloads import SSRF_PAYLOADS, SSRF_DETECTION_PATTERNS

logger = logging.getLogger(__name__)

class SSRF(BaseVulnerability):
    """
    Vérifie les vulnérabilités de Server-Side Request Forgery (SSRF).
    """
    name = "Server-Side Request Forgery (SSRF)"
    description = "Checks for SSRF by injecting internal/external URLs into parameters and observing response."
    severity = "High"
    cwe_id = "CWE-918"
    default_payloads = SSRF_PAYLOADS

    def __init__(self, target_url: str, method: str, params: List[Dict[str, Any]], ip_rotator: Any):
        super().__init__(target_url, method, params, ip_rotator)
        logger.debug(f"Initialized SSRF check for {target_url}.")

    async def _test_payload(self, url: str, method: str, original_params: List[Dict[str, Any]], payload: str,
                            param_to_inject: Dict[str, Any]) -> Optional[Any]:
        """
        Envoie une requête avec le payload injecté dans le paramètre spécifié.
        """
        test_params = [p.copy() for p in original_params]
        for p in test_params:
            if p.get('name') == param_to_inject.get('name') and p.get('value') == param_to_inject.get('value'):
                p['value'] = payload
                break

        if method.upper() == "GET":
            parsed_url = urlparse(url)
            query_parts = []
            for p in test_params:
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
            return None
        
        return response

    async def check(self) -> List[Dict[str, Any]]:
        """
        Exécute le test SSRF en itérant sur les payloads.
        """
        if not self.params:
            logger.debug(f"No parameters for SSRF check on {self.target_url}. Skipping.")
            return []

        logger.info(f"Starting SSRF check for {self.target_url} ({self.method}) with {len(self.params)} params.")

        for param in self.params:
            if not param.get('name'): continue

            for payload in self.default_payloads:
                logger.debug(f"Testing SSRF payload '{payload}' in parameter '{param['name']}'")
                response = await self._test_payload(self.target_url, self.method, self.params, payload, param)

                if response and response.status_code == 200:
                    response_text = response.text
                    for pattern in SSRF_DETECTION_PATTERNS:
                        if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                            proof = f"SSRF pattern '{pattern}' found in response with payload '{payload}'."
                            self._report_vulnerability(payload, proof)
                            break # Move to next payload
        
        logger.info(f"Finished SSRF check for {self.target_url}.")
        return self.found_vulnerabilities

# Example Usage (for testing)
async def test_ssrf_vuln():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger("httpx").setLevel(logging.WARNING)

    class MockIPRotator:
        async def get_proxies_for_request(self, force_tor=False):
            class AsyncProxyContext:
                async def __aenter__(self): return None
                async def __aexit__(self, exc_type, exc_val, exc_tb): pass
            return AsyncProxyContext(None)
        async def rotate_ip(self): pass

    ip_rotator = MockIPRotator()

    # Simulate a vulnerable endpoint for SSRF
    vulnerable_url = "http://localhost:8000/image_proxy?url=external.com/image.jpg"
    vulnerable_params = [{"name": "url", "value": "external.com/image.jpg"}]

    original_make_request = SSRF._make_request
    async def mock_make_request_ssrf(self, url, method, data=None, headers=None, allow_redirects=True):
        if urlparse(url).path == "/image_proxy":
            if method.upper() == "GET":
                query_params = parse_qs(urlparse(url).query)
                target_url_param = query_params.get('url', [''])[0]
                
                # Simulate SSRF where injecting internal IP leaks content
                if "127.0.0.1" in target_url_param or "localhost" in target_url_param:
                    mock_content = "<html><body>Internal service content: admin_dashboard_login_page.html</body></html>"
                elif "metadata" in target_url_param: # AWS/GCP metadata service
                    mock_content = "<html><body>IAM Role: my-webapp-role</body></html>"
                else:
                    mock_content = "<html><body>External content successfully fetched.</body></html>"
                
                class MockResponse:
                    status_code = 200
                    text = mock_content
                    @property
                    def content(self): return self.text.encode()
                    def raise_for_status(self): pass
                return MockResponse()
        return None
    SSRF._make_request = mock_make_request_ssrf

    print("\n--- Testing SSRF ---")
    ssrf_test = SSRF(vulnerable_url, "GET", vulnerable_params, ip_rotator)
    ssrf_results = await ssrf_test.check()
    if ssrf_results:
        for res in ssrf_results:
            print(f"SSRF Vulnerability Found: {res['url']} - Payload: {res['payload']} - Proof: {res['proof']}")
    else:
        print("No SSRF vulnerabilities found.")

    SSRF._make_request = original_make_request

    print("\n--- SSRF Tests Completed ---")

if __name__ == "__main__":
    asyncio.run(test_ssrf_vuln())
