# hebbian_learning/central_memory.py

import logging
from typing import List, Dict, Any, Set, Optional

logger = logging.getLogger(__name__)

class CentralMemory:
    """
    Agit comme une base de connaissances centrale pour les réseaux Hebbien afin de
    partager et de généraliser des motifs de payloads réussis.
    """
    def __init__(self):
        # Stores successful patterns categorized by vulnerability type
        # Structure: {vuln_type: {payload_hash: {'payload': '...', 'contexts': [...]}}}
        self.successful_patterns_db: Dict[str, Dict[int, Dict[str, Any]]] = {}
        logger.info("Central Memory initialized.")

    def add_successful_pattern(self, vulnerability_type: str, payload: str, endpoint_context: Dict[str, Any]):
        """
        Ajoute un payload réussi à la mémoire centrale.

        Args:
            vulnerability_type (str): Le type de vulnérabilité (ex: 'XSS', 'SQLi').
            payload (str): Le payload qui a réussi.
            endpoint_context (Dict[str, Any]): Le contexte du point d'attaque où le payload a réussi.
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
        # Note: endpoint_context dicts might not be hashable directly without converting to frozenset/tuple
        # For simplicity, we'll assume exact dict match for now, or you might need a more robust context hash.
        if endpoint_context not in self.successful_patterns_db[vulnerability_type][payload_hash]['contexts']:
            self.successful_patterns_db[vulnerability_type][payload_hash]['contexts'].append(endpoint_context)
            logger.debug(f"Added successful pattern '{payload}' for {vulnerability_type} in Central Memory. Context: {endpoint_context.get('url')}")
        else:
            logger.debug(f"Context already exists for successful pattern '{payload}' for {vulnerability_type}. Skipping addition.")


    def get_generalized_patterns(self, vulnerability_type: str, target_tech_profile: Optional[Set[str]] = None) -> List[str]:
        """
        Récupère les motifs de payloads généralisés ou spécifiques pour un type de vulnérabilité donné.
        C'est ici que la "magie du cross-learning" peut opérer.

        Args:
            vulnerability_type (str): Le type de vulnérabilité.
            target_tech_profile (Optional[Set[str]]): L'ensemble des technologies détectées
                                                    sur la cible actuelle.

        Returns:
            List[str]: Une liste de payloads généralisés.
        """
        generalized_payloads: Set[str] = set()
        if vulnerability_type in self.successful_patterns_db:
            for payload_data in self.successful_patterns_db[vulnerability_type].values():
                payload = payload_data['payload']
                contexts = payload_data['contexts']
                
                # Basic generalization: just return all successful payloads of that type
                # Advanced: filter based on target_tech_profile, apply NLP/regex for pattern extraction
                
                # Example: If target_tech_profile is provided, filter based on matching technologies
                if target_tech_profile:
                    context_matched = False
                    for context in contexts:
                        context_tech = context.get('tech', '')
                        # Simple check: if context tech is in target_tech_profile or general
                        if not context_tech or context_tech in target_tech_profile:
                            generalized_payloads.add(payload)
                            context_matched = True
                            break
                    if not context_matched:
                        logger.debug(f"Payload '{payload}' for {vulnerability_type} skipped due to no matching tech profile.")
                else:
                    # If no target_tech_profile, return all successful patterns for the type
                    generalized_payloads.add(payload)
            
        logger.debug(f"Retrieved {len(generalized_payloads)} generalized patterns for {vulnerability_type}.")
        return list(generalized_payloads)

    def get_all_patterns(self) -> List[Dict[str, Any]]:
        """
        Retourne tous les motifs réussis stockés pour le rapport/tableau de bord.

        Returns:
            List[Dict[str, Any]]: Une liste de dictionnaires décrivant les motifs stockés.
        """
        all_patterns = []
        for vuln_type, patterns_data in self.successful_patterns_db.items():
            for payload_data in patterns_data.values():
                all_patterns.append({
                    'vulnerability_type': vuln_type,
                    'payload': payload_data['payload'],
                    'contexts_count': len(payload_data['contexts'])
                })
        logger.debug(f"Returning {len(all_patterns)} total stored patterns.")
        return all_patterns

# Example Usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    cm = CentralMemory()

    # Simulate adding successful patterns
    cm.add_successful_pattern('SQLi', "' OR 1=1 --", {'url': 'http://site1.com/login', 'tech': 'PHP'})
    cm.add_successful_pattern('SQLi', "' UNION SELECT 1,NULL,NULL--", {'url': 'http://site2.com/data', 'tech': 'ASP'})
    cm.add_successful_pattern('XSS', "<script>alert('xss')</script>", {'url': 'http://site3.com/search', 'tech': 'React'})
    cm.add_successful_pattern('SQLi', "' OR 1=1 --", {'url': 'http://site4.com/product', 'tech': 'PHP'}) # Same payload, new context
    cm.add_successful_pattern('XSS', "<img src=x onerror=alert(1)>", {'url': 'http://site5.com/comment', 'tech': 'NodeJS'})


    print("\n--- Generalized SQLi Patterns (no tech filter) ---")
    sqli_patterns = cm.get_generalized_patterns('SQLi')
    for p in sqli_patterns:
        print(p)

    print("\n--- Generalized SQLi Patterns (filtered for PHP) ---")
    sqli_php_patterns = cm.get_generalized_patterns('SQLi', target_tech_profile={'PHP'})
    for p in sqli_php_patterns:
        print(p)

    print("\n--- Generalized XSS Patterns (no tech filter) ---")
    xss_patterns = cm.get_generalized_patterns('XSS')
    for p in xss_patterns:
        print(p)
    
    print("\n--- Generalized XSS Patterns (filtered for React) ---")
    xss_react_patterns = cm.get_generalized_patterns('XSS', target_tech_profile={'React'})
    for p in xss_react_patterns:
        print(p)

    print("\n--- All Stored Patterns ---")
    all_stored = cm.get_all_patterns()
    for item in all_stored:
        print(f"Type: {item['vulnerability_type']}, Payload: {item['payload']}, Contexts: {item['contexts_count']}")
