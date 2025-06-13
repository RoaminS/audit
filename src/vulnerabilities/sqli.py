# vulnerabilities/sqli.py

import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse
import re

from .base_vulnerability import BaseVulnerability
from .payloads import SQLI_PAYLOADS, SQLI_ERROR_PATTERNS, SQLI_BOOLEAN_PAYLOADS

logger = logging.getLogger(__name__)

class SQLi(BaseVulnerability):
    """
    Vérifie les vulnérabilités d'injection SQL (SQLi).
    Implémente la détection basée sur les erreurs et potentiellement la détection booléenne/basée sur le temps.
    """
    name = "SQL Injection (SQLi)"
    description = "Checks for SQL Injection vulnerabilities by injecting payloads into parameters and analyzing response."
    severity = "Critical"
    cwe_id = "CWE-89"
    default_payloads = SQLI_PAYLOADS

    def __init__(self, target_url: str, method: str, params: List[Dict[str, Any]], ip_rotator: Any):
        super().__init__(target_url, method, params, ip_rotator)
        logger.debug(f"Initialized SQLi check for {target_url}.")

    async def _test_payload(self, url: str, method: str, original_params: List[Dict[str, Any]], payload: str,
                            param_to_inject: Dict[str, Any]) -> Optional[Any]:
        """
        Envoie une requête avec le payload injecté dans le paramètre spécifié.

        Args:
            url (str): L'URL cible.
            method (str): La méthode HTTP (GET/POST).
            original_params (List[Dict[str, Any]]): Les paramètres originaux de la requête.
            payload (str): Le payload SQLi à injecter.
            param_to_inject (Dict[str, Any]): Le paramètre spécifique dans lequel injecter.

        Returns:
            Optional[Any]: L'objet réponse httpx si la requête réussit, None sinon.
        """
        test_params = [p.copy() for p in original_params]
        # Find the parameter to inject into and update its value
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
        Exécute le test SQLi en itérant sur les payloads et en vérifiant les erreurs.
        """
        if not self.params:
            logger.debug(f"No parameters for SQLi check on {self.target_url}. Skipping.")
            return []

        logger.info(f"Starting SQLi check for {self.target_url} ({self.method}) with {len(self.params)} params.")

        # Test each parameter
        for param in self.params:
            if not param.get('name'): continue # Skip if no parameter name

            # Test Error-based SQLi
            for payload in self.default_payloads:
                logger.debug(f"Testing SQLi payload '{payload}' in parameter '{param['name']}'")
                response = await self._test_payload(self.target_url, self.method, self.params, payload, param)

                if response and response.status_code == 200:
                    response_text = response.text
                    for error_pattern in SQLI_ERROR_PATTERNS:
                        if re.search(error_pattern, response_text, re.IGNORECASE):
                            proof = f"SQL error pattern '{error_pattern}' found in response with payload '{payload}'."
                            self._report_vulnerability(payload, proof)
                            break # Found for this pattern, move to next payload
            
            # TODO: Implement time-based and boolean-based SQLi (more complex)
            # For time-based, you'd send a payload with a sleep command and measure response time.
            # For boolean-based, you'd send true/false conditions and compare responses.
            # This requires fetching a baseline response first.
            
            # Example placeholder for boolean-based (conceptual)
            """
            logger.debug(f"Testing Boolean-based SQLi for parameter '{param['name']}'")
            # Get baseline response
            baseline_response = await self._test_payload(self.target_url, self.method, self.params, param['value'], param)
            if baseline_response:
                for true_payload, false_payload in SQLI_BOOLEAN_PAYLOADS:
                    response_true = await self._test_payload(self.target_url, self.method, self.params, true_payload, param)
                    response_false = await self._test_payload(self.target_url, self.method, self.params, false_payload, param)

                    if response_true and response_false:
                        # Logic to compare responses (size, content, status)
                        # This is highly dependent on the target's behavior
                        if len(response_true.text) != len(response_false.text) and response_true.status_code == 200:
                            proof = f"Boolean-based SQLi detected: response for '{true_payload}' differs from '{false_payload}'."
                            self._report_vulnerability(true_payload, proof, severity="High")
            """

        logger.info(f"Finished SQLi check for {self.target_url}.")
        return self.found_vulnerabilities

# Example Usage (for testing)
async def test_sqli_vuln():
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

    # Simulate a vulnerable endpoint that shows SQL errors
    vulnerable_url = "http://localhost:8000/product?id=1"
    vulnerable_params = [{"name": "id", "value": "1"}]

    # Mock _make_request for local testing
    original_make_request = SQLi._make_request
    async def mock_make_request_sqli(self, url, method, data=None, headers=None, allow_redirects=True):
        if urlparse(url).path == "/product":
            if method.upper() == "GET":
                query_params = parse_qs(urlparse(url).query)
                product_id = query_params.get('id', [''])[0]
                if "'" in product_id: # Simulate SQL error
                    mock_content = "<html><body>An error occurred: SQLSTATE[HY000]: General error: 1 no such column: users.name</body></html>"
                    class MockResponse:
                        status_code = 500 # Internal Server Error
                        text = mock_content
                        @property
                        def content(self): return self.text.encode()
                        def raise_for_status(self): raise httpx.HTTPStatusError("Simulated error", request=httpx.Request("GET", url), response=self)
                    return MockResponse()
                else: # Simulate valid response
                    mock_content = "<html><body>Product Details</body></html>"
                    class MockResponse:
                        status_code = 200
                        text = mock_content
                        @property
                        def content(self): return self.text.encode()
                        def raise_for_status(self): pass
                    return MockResponse()
        return None # Fallback or original behavior
    SQLi._make_request = mock_make_request_sqli

    print("\n--- Testing SQL Injection ---")
    sqli_test = SQLi(vulnerable_url, "GET", vulnerable_params, ip_rotator)
    sqli_results = await sqli_test.check()
    if sqli_results:
        for res in sqli_results:
            print(f"SQLi Vulnerability Found: {res['url']} - Payload: {res['payload']} - Proof: {res['proof']}")
    else:
        print("No SQL Injection vulnerabilities found.")

    # Restore original _make_request
    SQLi._make_request = original_make_request

    print("\n--- SQL Injection Tests Completed ---")

if __name__ == "__main__":
    asyncio.run(test_sqli_vuln())
