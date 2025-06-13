# vulnerabilities/logic_flaws.py

import logging
from typing import List, Dict, Any, Optional

from .base_vulnerability import BaseVulnerability

logger = logging.getLogger(__name__)

class LogicFlaws(BaseVulnerability):
    """
    Vérifie les failles logiques.
    Les failles logiques sont souvent spécifiques à l'application et difficiles à automatiser.
    Cette classe est un point de départ conceptuel, nécessitant une analyse plus approfondie.
    """
    name = "Logic Flaws"
    description = "Identifies potential logic flaws (e.g., bypassing authentication, payment manipulation)."
    severity = "Medium" # Severity can vary greatly depending on impact
    cwe_id = "CWE-840" # Business Logic Errors (General category)
    # Logic flaws typically don't have default payloads like other vulns, as they're context-specific.
    default_payloads = [] 

    def __init__(self, target_url: str, method: str, params: List[Dict[str, Any]], ip_rotator: Any):
        super().__init__(target_url, method, params, ip_rotator)
        logger.debug(f"Initialized LogicFlaws check for {target_url}.")
        # Additional state might be needed for multi-step logic flaw testing
        self.session_cookies: Dict[str, str] = {} # Example: for tracking session state

    async def check(self) -> List[Dict[str, Any]]:
        """
        Exécute les tests pour les failles logiques.
        Ceci est un placeholder; l'implémentation concrète dépendra de la logique
        spécifique de l'application.

        Pour une automatisation, cela pourrait impliquer:
        - Tester les changements de prix/quantité sur les pages e-commerce.
        - Tenter de passer des étapes de workflow (ex: passer directement à la confirmation de commande).
        - Tester des valeurs négatives/zéros pour les prix/quantités.
        - Vérifier l'accès à des ressources non autorisées en modifiant les IDs (IDOR).
        - Tester la validation côté client seulement.
        """
        logger.info(f"Starting Logic Flaws check for {self.target_url} ({self.method}) with {len(self.params)} params.")

        # Example: Simple IDOR (Insecure Direct Object Reference) check
        # This assumes a URL like /users/{id} or /orders/{id}
        parsed_url = urlparse(self.target_url)
        path_segments = [s for s in parsed_url.path.split('/') if s]
        
        # Look for numeric IDs in path segments or query parameters
        if path_segments:
            for i, segment in enumerate(path_segments):
                if segment.isdigit():
                    original_id = int(segment)
                    # Try to access a slightly different ID
                    test_id = original_id + 1 
                    test_path_segments = list(path_segments)
                    test_path_segments[i] = str(test_id)
                    test_url_path = '/' + '/'.join(test_path_segments)
                    test_url = urlunparse(parsed_url._replace(path=test_url_path))

                    logger.debug(f"Testing IDOR by changing {original_id} to {test_id} at {test_url}")
                    response = await self._make_request(test_url, "GET", headers={'Cookie': urlencode(self.session_cookies) if self.session_cookies else ''})

                    # Basic IDOR detection: if response is 200 OK and contains data not expected for original ID
                    # This is highly heuristic and needs fine-tuning
                    if response and response.status_code == 200:
                        # You'd need to compare content with original or check for specific unauthorized content
                        # For a real IDOR, you'd make a request as user A, then as user B with user A's resource ID.
                        # For simplicity, if we get content we weren't expecting, it's a potential flaw.
                        if "username" in response.text or "order_details" in response.text: # Placeholder patterns
                            proof = f"Potentially accessed resource for ID {test_id} from {original_id}. Response snippet: {response.text[:100]}"
                            self._report_vulnerability(str(test_id), proof, description=f"Possible IDOR on parameter in URL path: {segment}", severity="High")
                            # Only report once per target URL for IDOR for now
                            return self.found_vulnerabilities

        # Example: Parameter Tampering (e.g., price manipulation in POST request)
        if self.method.upper() == "POST" and self.params:
            for param in self.params:
                if "price" in param['name'].lower() or "amount" in param['name'].lower() or "quantity" in param['name'].lower():
                    try:
                        original_value = float(param['value'])
                        if original_value > 0:
                            # Try setting to 0 or a negative value
                            for manipulated_value in [0.0, -1.0]:
                                logger.debug(f"Testing parameter tampering for {param['name']} with value {manipulated_value}")
                                test_params = [p.copy() for p in self.params]
                                for p in test_params:
                                    if p['name'] == param['name']:
                                        p['value'] = str(manipulated_value) # Send as string
                                        break
                                post_data = {p['name']: p['value'] for p in test_params}
                                response = await self._make_request(self.target_url, "POST", data=post_data)

                                if response and response.status_code == 200:
                                    # This is where a real logic flaw check is hard:
                                    # You need to know if the manipulation succeeded (e.g., item added to cart for free).
                                    # This often requires parsing dynamic content or multi-step analysis.
                                    if "success" in response.text.lower() and "price" not in response.text.lower(): # Highly heuristic
                                        proof = f"Manipulated '{param['name']}' to '{manipulated_value}'. Success response suggests flaw."
                                        self._report_vulnerability(str(manipulated_value), proof, description=f"Potential price/quantity manipulation for {param['name']}", severity="High")
                                        # return self.found_vulnerabilities # Uncomment to stop on first
                    except ValueError:
                        pass # Not a numeric parameter

        logger.info(f"Finished Logic Flaws check for {self.target_url}.")
        return self.found_vulnerabilities

# Example Usage (for testing)
async def test_logic_flaws_vuln():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger("httpx").setLevel(logging.WARNING)

    class MockIPRotator:
        async def get_proxies_for_request(self, force_tor=False):
            class AsyncProxyContext:
                async def __aenter__(self): return None
                async async def __aexit__(self, exc_type, exc_val, exc_tb): pass
            return AsyncProxyContext(None)
        async def rotate_ip(self): pass

    ip_rotator = MockIPRotator()

    # Scenario 1: IDOR in URL path
    vulnerable_idor_url = "http://localhost:8000/users/123"
    vulnerable_idor_params = [] # ID in path, not query/form params

    original_make_request = LogicFlaws._make_request
    async def mock_make_request_logic(self, url, method, data=None, headers=None, allow_redirects=True):
        parsed_url = urlparse(url)
        if parsed_url.path.startswith("/users/"):
            user_id = parsed_url.path.split('/')[-1]
            if user_id == "124": # Simulate unauthorized access to user 124's data
                mock_content = "<html><body><h1>User Profile for Jane Doe (ID: 124)</h1><p>Email: jane.doe@example.com</p></body></html>"
                class MockResponse:
                    status_code = 200
                    text = mock_content
                    @property
                    def content(self): return self.text.encode()
                    def raise_for_status(self): pass
                return MockResponse()
            elif user_id == "123":
                 mock_content = "<html><body><h1>User Profile for John Doe (ID: 123)</h1></body></html>"
                 class MockResponse:
                    status_code = 200
                    text = mock_content
                    @property
                    def content(self): return self.text.encode()
                    def raise_for_status(self): pass
                 return MockResponse()
        elif parsed_url.path == "/buy_item":
            if method.upper() == "POST" and data and 'price' in data:
                if float(data['price']) <= 0:
                    mock_content = "<html><body><h2>Order Confirmation</h2><p>Item: Test Product - Price: $0.00</p></body></html>"
                    class MockResponse:
                        status_code = 200
                        text = mock_content
                        @property
                        def content(self): return self.text.encode()
                        def raise_for_status(self): pass
                    return MockResponse()
                else:
                    mock_content = "<html><body>Normal purchase flow.</body></html>"
                    class MockResponse:
                        status_code = 200
                        text = mock_content
                        @property
                        def content(self): return self.text.encode()
                        def raise_for_status(self): pass
                    return MockResponse()
        return None
    LogicFlaws._make_request = mock_make_request_logic

    print("\n--- Testing Logic Flaws (IDOR) ---")
    logic_idor_test = LogicFlaws(vulnerable_idor_url, "GET", vulnerable_idor_params, ip_rotator)
    logic_results_idor = await logic_idor_test.check()
    if logic_results_idor:
        for res in logic_results_idor:
            print(f"Logic Flaw (IDOR) Found: {res['url']} - Payload: {res['payload']} - Proof: {res['proof']}")
    else:
        print("No Logic Flaws (IDOR) found.")

    # Scenario 2: Price Manipulation
    vulnerable_price_url = "http://localhost:8000/buy_item"
    vulnerable_price_params = [{"name": "item_id", "value": "A1"}, {"name": "price", "value": "99.99"}]

    print("\n--- Testing Logic Flaws (Price Manipulation) ---")
    logic_price_test = LogicFlaws(vulnerable_price_url, "POST", vulnerable_price_params, ip_rotator)
    logic_results_price = await logic_price_test.check()
    if logic_results_price:
        for res in logic_results_price:
            print(f"Logic Flaw (Price) Found: {res['url']} - Payload: {res['payload']} - Proof: {res['proof']}")
    else:
        print("No Logic Flaws (Price) found.")

    LogicFlaws._make_request = original_make_request

    print("\n--- Logic Flaws Tests Completed ---")

if __name__ == "__main__":
    asyncio.run(test_logic_flaws_vuln())
