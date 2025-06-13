import logging

logger = logging.getLogger(__name__)

class CentralMemory:
    """
    Acts as a central knowledge base for Hebbian Networks to share and generalize patterns.
    """
    def __init__(self):
        # Stores successful patterns categorized by vulnerability type
        # Structure: {vuln_type: {payload_hash: {'payload': '...', 'contexts': [...]}}}
        self.successful_patterns_db = {}
        logger.info("Central Memory initialized.")

    def add_successful_pattern(self, vulnerability_type, payload, endpoint_context):
        """
        Adds a successful payload to the central memory.
        """
        if vulnerability_type not in self.successful_patterns_db:
            self.successful_patterns_db[vulnerability_type] = {}
        
        payload_hash = hash(payload) # Simple hash for quick lookup
        if payload_hash not in self.successful_patterns_db[vulnerability_type]:
            self.successful_patterns_db[vulnerability_type][payload_hash] = {
                'payload': payload,
                'contexts': []
            }
        
        # Avoid duplicate contexts for the same payload
        if endpoint_context not in self.successful_patterns_db[vulnerability_type][payload_hash]['contexts']:
            self.successful_patterns_db[vulnerability_type][payload_hash]['contexts'].append(endpoint_context)
            logger.debug(f"Added successful pattern '{payload}' for {vulnerability_type} in Central Memory. Context: {endpoint_context.get('url')}")

    def get_generalized_patterns(self, vulnerability_type, target_tech_profile=None):
        """
        Retrieves generalized or specific successful patterns for a given vulnerability type.
        This is where the 'cross-learning' magic happens.
        
        For a more advanced implementation:
        - Analyze `target_tech_profile` to filter patterns.
        - Group similar payloads and contexts to extract common components.
        - Use clustering or association rules to find highly effective "building blocks" of payloads.
        - Prioritize patterns based on their success rate across contexts.
        """
        generalized_payloads = set()
        if vulnerability_type in self.successful_patterns_db:
            for payload_data in self.successful_patterns_db[vulnerability_type].values():
                payload = payload_data['payload']
                # Basic generalization: just return all successful payloads of that type
                # Advanced: filter based on target_tech_profile, apply NLP/regex for pattern extraction
                
                # For demo, if target_tech_profile is provided, we can simulate filtering.
                # E.g., if target_tech_profile indicates 'PHP', prioritize PHP-specific payloads if stored.
                # (This would require storing tech_profile with payload contexts in add_successful_pattern)
                
                generalized_payloads.add(payload)
        
        logger.debug(f"Retrieved {len(generalized_payloads)} generalized patterns for {vulnerability_type}.")
        return list(generalized_payloads)

    def get_all_patterns(self):
        """Returns all stored successful patterns for reporting/dashboard."""
        all_patterns = []
        for vuln_type, patterns_data in self.successful_patterns_db.items():
            for payload_data in patterns_data.values():
                all_patterns.append({
                    'vulnerability_type': vuln_type,
                    'payload': payload_data['payload'],
                    'contexts_count': len(payload_data['contexts'])
                })
        return all_patterns

# Example Usage
if __name__ == "__main__":
    cm = CentralMemory()

    # Simulate adding successful patterns
    cm.add_successful_pattern('SQLi', "' OR 1=1 --", {'url': 'http://site1.com/login', 'tech': 'PHP'})
    cm.add_successful_pattern('SQLi', "' UNION SELECT 1,NULL,NULL--", {'url': 'http://site2.com/data', 'tech': 'ASP'})
    cm.add_successful_pattern('XSS', "<script>alert('xss')</script>", {'url': 'http://site3.com/search', 'tech': 'React'})
    cm.add_successful_pattern('SQLi', "' OR 1=1 --", {'url': 'http://site4.com/product', 'tech': 'PHP'}) # Same payload, new context

    print("\n--- Generalized SQLi Patterns ---")
    sqli_patterns = cm.get_generalized_patterns('SQLi')
    for p in sqli_patterns:
        print(p)

    print("\n--- Generalized XSS Patterns ---")
    xss_patterns = cm.get_generalized_patterns('XSS')
    for p in xss_patterns:
        print(p)
    
    print("\n--- All Stored Patterns ---")
    all_stored = cm.get_all_patterns()
    for item in all_stored:
        print(f"Type: {item['vulnerability_type']}, Payload: {item['payload']}, Contexts: {item['contexts_count']}")
