# vulnerabilities/rce.py

import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse
import re

from .base_vulnerability import BaseVulnerability
from .payloads import RCE_PAYLOADS, RCE_DETECTION_PATTERNS

logger = logging.getLogger(__name__)

class RCE(BaseVulnerability):
    """
    Vérifie les vulnérabilités d'exécution de code à distance (RCE).
    """
    name = "Remote Code Execution (RCE)"
    description = "Checks for RCE by injecting system commands or code into parameters and observing response."
    severity = "Critical"
    cwe_id = "CWE-78" # OS Command Injection
    default_payloads = RCE_PAYLOADS

    def __init__(self, target_url: str, method: str, params: List[Dict[str, Any]], ip_rotator: Any):
        super().__init__(target_url, method, params, ip_rotator)
        logger.debug(f"Initialized RCE check for {target_url}.")

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
        Exécute le test RCE en itérant sur les payloads.
        """
        if not self.params:
            logger.debug(f"No parameters for RCE check on {self.target_url}. Skipping.")
            return []

        logger.info(f"Starting RCE check for {self.target_url} ({self.method}) with {len(self.params)} params.")

        for param in self.params:
            if not param.get('name'): continue

            for payload in self.default_payloads:
                logger.debug(f"Testing RCE payload '{payload}' in parameter '{param['name']}'")
                response = await self._test_payload(self.target_url, self.method, self.params, payload, param)

                if response and response.status_code == 200:
                    response_text = response.text
                    for pattern in RCE_DETECTION_PATTERNS:
                        if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                            proof = f"RCE pattern '{pattern}' found in response with payload '{payload}'."
                            self._report_vulnerability(payload, proof)
                            break # Move to next payload
        
        logger.info(f"Finished RCE check for {self.target_url}.")
        return self.found_vulnerabilities

# Example Usage (for testing)
async def test_rce_vuln():
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

    # Simulate a vulnerable endpoint for RCE
    vulnerable_url = "http://localhost:8000/exec?cmd=ls"
    vulnerable_params = [{"name": "cmd", "value": "ls"}]

    original_make_request = RCE._make_request
    async def mock_make_request_rce(self, url, method, data=None, headers=None, allow_redirects=True):
        if urlparse(url).path == "/exec":
            if method.upper() == "GET":
                query_params = parse_qs(urlparse(url).query)
                cmd_param = query_params.get('cmd', [''])[0]
                
                # Simulate command execution output
                if "whoami" in cmd_param:
                    mock_content = "<html><body><pre>root</pre></body></html>"
                elif "cat /etc/passwd" in cmd_param:
                    mock_content = "<html><body><pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre></body></html>"
                else:
                    mock_content = "<html><body>Command not found or benign output.</body></html>"
                
                class MockResponse:
                    status_code = 200
                    text = mock_content
                    @property
                    def content(self): return self.text.encode()
                    def raise_for_status(self): pass
                return MockResponse()
        return None
    RCE._make_request = mock_make_request_rce

    print("\n--- Testing RCE ---")
    rce_test = RCE(vulnerable_url, "GET", vulnerable_params, ip_rotator)
    rce_results = await rce_test.check()
    if rce_results:
        for res in rce_results:
            print(f"RCE Vulnerability Found: {res['url']} - Payload: {res['payload']} - Proof: {res['proof']}")
    else:
        print("No RCE vulnerabilities found.")

    RCE._make_request = original_make_request

    print("\n--- RCE Tests Completed ---")

if __name__ == "__main__":
    asyncio.run(test_rce_vuln())
