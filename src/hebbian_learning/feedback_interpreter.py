# hebbian_learning/feedback_interpreter.py

import logging
import re
from typing import Any, Tuple, Optional, Dict

# Assuming we can import detection patterns from the vulnerabilities module
# This requires that 'vulnerabilities' is a package and 'payloads' is a module within it.
from vulnerabilities.payloads import (
    XSS_DETECTION_PATTERNS,
    SQLI_ERROR_PATTERNS,
    RCE_DETECTION_PATTERNS,
    SSRF_DETECTION_PATTERNS,
    LFI_DETECTION_PATTERNS
)

logger = logging.getLogger(__name__)

class FeedbackInterpreter:
    """
    Interprète les réponses HTTP pour fournir un signal de feedback aux réseaux Hebbien.
    Il analyse le code de statut HTTP et le contenu de la réponse par rapport
    à des patterns de détection de vulnérabilités spécifiques.
    """
    def __init__(self):
        logger.info("FeedbackInterpreter initialized.")

    def interpret_response(self, vulnerability_type: str, response: Any, payload: str) -> Tuple[int, Optional[str]]:
        """
        Interprète la réponse HTTP pour déterminer le succès ou l'échec d'une attaque.

        Args:
            vulnerability_type (str): Le type de vulnérabilité testé (ex: 'XSS', 'SQLi').
            response (Any): L'objet réponse HTTP (doit avoir .status_code et .text).
            payload (str): Le payload utilisé dans la requête.

        Returns:
            Tuple[int, Optional[str]]: Un tuple contenant:
                                     - Un signal de feedback (+1 pour succès, -1 pour échec, 0 pour neutre/inconnu).
                                     - Une preuve de la vulnérabilité si trouvée (str), None sinon.
        """
        feedback_signal = -1 # Default to failure
        proof = None

        if response is None:
            logger.debug(f"No response object provided for {vulnerability_type} test with payload: '{payload}'. Returning failure.")
            return -1, "No HTTP response object provided."

        response_text = response.text
        status_code = response.status_code

        # Log for debugging interpretation
        logger.debug(f"Interpreting response for {vulnerability_type} (Status: {status_code}) with payload: '{payload}'")

        # Prioritize successful status codes for potential detection (2xx)
        # Also consider server errors (5xx) for SQLi/RCE which often reveal errors
        if 200 <= status_code < 300 or status_code >= 500:
            if vulnerability_type == "XSS":
                # For XSS, we need both payload reflection AND a specific execution pattern
                if payload in response_text:
                    for pattern in XSS_DETECTION_PATTERNS:
                        if pattern in response_text:
                            feedback_signal = 1
                            proof = f"Payload '{payload}' reflected and XSS pattern '{pattern}' found in response."
                            logger.debug(f"XSS detected for payload '{payload}'")
                            break
            elif vulnerability_type == "SQLi":
                # For error-based SQLi, look for error patterns
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                        feedback_signal = 1
                        proof = f"SQL error pattern '{pattern}' found in response (Status {status_code}) with payload '{payload}'."
                        logger.debug(f"SQLi (error-based) detected for payload '{payload}'")
                        break
                # TODO: Implement time-based and boolean-based SQLi detection logic here
                # which would require comparing response times or content length/differences.
            elif vulnerability_type == "RCE":
                for pattern in RCE_DETECTION_PATTERNS:
                    if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                        feedback_signal = 1
                        proof = f"RCE detection pattern '{pattern}' found in response with payload '{payload}'."
                        logger.debug(f"RCE detected for payload '{payload}'")
                        break
            elif vulnerability_type == "SSRF":
                for pattern in SSRF_DETECTION_PATTERN:
                    if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                        feedback_signal = 1
                        proof = f"SSRF detection pattern '{pattern}' found in response with payload '{payload}'."
                        logger.debug(f"SSRF detected for payload '{payload}'")
                        break
            elif vulnerability_type == "LFI":
                for pattern in LFI_DETECTION_PATTERNS:
                    if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                        feedback_signal = 1
                        proof = f"LFI detection pattern '{pattern}' found in response with payload '{payload}'."
                        logger.debug(f"LFI detected for payload '{payload}'")
                        break
            elif vulnerability_type == "LogicFlaws":
                # Logic flaws are highly contextual and very difficult to automate
                # with generic patterns. This is mostly a placeholder for now.
                # Real detection often requires stateful analysis, comparison with baseline,
                # or very specific keywords/conditions relevant to the target application's logic.
                # Example: If trying price manipulation, check if "price: $0.00" appears in confirmation.
                if "success" in response_text.lower() and "price: $0.00" in response_text: # Very specific example
                    feedback_signal = 1
                    proof = f"Potential logic flaw: price manipulation to zero detected with payload '{payload}'."
                elif status_code == 200 and "admin_dashboard" in response_text and "unauthorized" not in response_text: # Example for IDOR success
                    feedback_signal = 1
                    proof = f"Potential logic flaw: unauthorized access to admin dashboard detected with payload '{payload}'."
                else:
                    feedback_signal = 0 # Neutral for uncertain logic flaw detections

        # If a vulnerability was detected, feedback_signal would be 1.
        # If no specific pattern was matched for success, it remains -1 (failure).
        
        if feedback_signal == -1 and proof is None:
            proof = f"No specific vulnerability patterns detected for {vulnerability_type}. Status: {status_code}"
            logger.debug(proof)

        return feedback_signal, proof

# Example Usage (for testing)
import asyncio

async def test_feedback_interpreter():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    # Reduce httpx verbosity if it were imported directly
    # logging.getLogger("httpx").setLevel(logging.WARNING) 

    interpreter = FeedbackInterpreter()

    # Mock Response class for testing without actual HTTP requests
    class MockResponse:
        def __init__(self, status_code: int, text: str):
            self.status_code = status_code
            self.text = text
            self.content = text.encode('utf-8') # Simulate bytes content for httpx compatibility

    print("\n--- Testing Feedback Interpreter ---")

    # Scenario 1: XSS Success
    xss_payload = "<script>alert(1)</script>"
    xss_response_success = MockResponse(200, f"<html><body>User input: {xss_payload} <script>alert(1)</script></body></html>")
    signal, proof = interpreter.interpret_response("XSS", xss_response_success, xss_payload)
    print(f"XSS (Success): Signal={signal}, Proof='{proof}'")
    assert signal == 1 and proof is not None

    # Scenario 2: XSS Failure (payload not reflected)
    xss_response_fail_no_reflection = MockResponse(200, "<html><body>Input was sanitized.</body></html>")
    signal, proof = interpreter.interpret_response("XSS", xss_response_fail_no_reflection, xss_payload)
    print(f"XSS (Fail - no reflection): Signal={signal}, Proof='{proof}'")
    assert signal == -1 and proof is not None

    # Scenario 3: SQLi Success (error-based, 200 OK)
    sqli_payload = "' OR 1=1 --"
    sqli_response_success_200 = MockResponse(200, "<html><body>An error occurred: SQL syntax error near 'OR 1=1'</body></html>")
    signal, proof = interpreter.interpret_response("SQLi", sqli_response_success_200, sqli_payload)
    print(f"SQLi (Success - 200 error): Signal={signal}, Proof='{proof}'")
    assert signal == 1 and proof is not None

    # Scenario 4: SQLi Success (error-based, 500 Internal Server Error)
    sqli_response_success_500 = MockResponse(500, "<html><body>SQLSTATE[HY000]: General error: 1 no such table: users</body></html>")
    signal, proof = interpreter.interpret_response("SQLi", sqli_response_success_500, sqli_payload)
    print(f"SQLi (Success - 500 error): Signal={signal}, Proof='{proof}'")
    assert signal == 1 and proof is not None

    # Scenario 5: RCE Success
    rce_payload = "; cat /etc/passwd"
    rce_response_success = MockResponse(200, f"<html><body><pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre></body></html>")
    signal, proof = interpreter.interpret_response("RCE", rce_response_success, rce_payload)
    print(f"RCE (Success): Signal={signal}, Proof='{proof}'")
    assert signal == 1 and proof is not None

    # Scenario 6: SSRF Success
    ssrf_payload = "http://169.254.169.254/latest/meta-data/"
    ssrf_response_success = MockResponse(200, "<html><body><h1>EC2 Metadata Service</h1><p>iam/security-credentials/</p></body></html>")
    signal, proof = interpreter.interpret_response("SSRF", ssrf_response_success, ssrf_payload)
    print(f"SSRF (Success): Signal={signal}, Proof='{proof}'")
    assert signal == 1 and proof is not None

    # Scenario 7: LFI Success
    lfi_payload = "../../../etc/passwd"
    lfi_response_success = MockResponse(200, "<html><body><pre>root:x:0:0:root:/root:/bin/bash</pre></body></html>")
    signal, proof = interpreter.interpret_response("LFI", lfi_response_success, lfi_payload)
    print(f"LFI (Success): Signal={signal}, Proof='{proof}'")
    assert signal == 1 and proof is not None

    # Scenario 8: Logic Flaw Success (Price manipulation)
    logic_payload_price = "price=0"
    logic_response_price_success = MockResponse(200, "<html><body>Order Confirmation: Item added for price: $0.00</body></html>")
    signal, proof = interpreter.interpret_response("LogicFlaws", logic_response_price_success, logic_payload_price)
    print(f"LogicFlaws (Price Success): Signal={signal}, Proof='{proof}'")
    assert signal == 1 and proof is not None
    
    # Scenario 9: Logic Flaw Success (Admin access bypass)
    logic_payload_admin = "user_id=1&role=admin"
    logic_response_admin_success = MockResponse(200, "<html><body>Welcome to Admin Dashboard</body></html>")
    signal, proof = interpreter.interpret_response("LogicFlaws", logic_response_admin_success, logic_payload_admin)
    print(f"LogicFlaws (Admin Success): Signal={signal}, Proof='{proof}'")
    assert signal == 1 and proof is not None

    # Scenario 10: Generic Failure (no specific pattern matched)
    generic_payload = "test_payload"
    generic_response_fail = MockResponse(200, "<html><body>No relevant content.</body></html>")
    signal, proof = interpreter.interpret_response("XSS", generic_response_fail, generic_payload)
    print(f"Generic (Fail): Signal={signal}, Proof='{proof}'")
    assert signal == -1 and proof is not None

    print("\n--- All Feedback Interpreter Tests Completed ---")

if __name__ == "__main__":
    asyncio.run(test_feedback_interpreter())
