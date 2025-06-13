Audit-Scan-autonome

```

+--------------------------+     +------------------------+
|    IP Rotation Module    |<--->|   Proxy/VPN Manager  |
| (Anonymity & Evasion)    |     |                        |
+--------------------------+     +------------------------+
              |                               ^
              V                               |
+-------------------------------------------------------------+
|                                                             |
|                   **CORE HEBBSCAN ENGINE** |
|                                                             |
| +---------------------+   +---------------------+         |
| |  Crawler & Mapper   |<->|  Target Profiler    |         |
| | (Discovery, Parsing)|   |(Tech, Framework, OS)|         |
| +---------------------+   +---------------------+         |
|            |                               ^               |
|            V                               |               |
| +---------------------+   +---------------------+         |
| |  Attack Surface     |<->|  Vulnerability      |         |
| |  Analyzer           |   |  Detector           |         |
| | (Endpoints, Forms,  |   | (Classic & Logic)   |         |
| |  APIs, Assets)      |   +---------------------+         |
| +---------------------+                 ^                 |
|            |                            |                 |
|            V                            |                 |
| +---------------------+   +---------------------+         |
| |  Attack Orchestrator|<->|  Hebbian Learning   |         |
| | (Attack Strategy,   |   |  Network (HLN)      |         |
| |  Feedback Loop)     |   |  (Payload Gen, Adapt)|         |
| +---------------------+   +---------------------+         |
|            |                            |                 |
|            V                            |                 |
| +---------------------+   +---------------------+         |
| |  Central Memory &   |<->|  Cross-Learning     |         |
| |  Knowledge Base     |   |  Module             |         |
| | (Learned Patterns,  |   | (Pattern Sharing,    |         |
| |  Attack Context)    |   |  Generalization)    |         |
| +---------------------+   +---------------------+         |
|                                                             |
+-------------------------------------------------------------+
              |                               ^
              V                               |
+--------------------------+     +--------------------------+
|     Reporting Module     |<--->|     Web Dashboard        |
| (PDF Generation, Visuals)|     | (Streamlit, Real-time)   |
+--------------------------+     +--------------------------+

```


src/
* `__init__.py`
* `anonymity/`
    * `__init__.py`
    * `proxy_manager.py`: Gère le pool de proxies, la rotation, la validation.
    * `tor_manager.py`: Intègre le contrôle de Tor.
    * `ip_rotator.py`: La classe principale qui utilise `proxy_manager` et `tor_manager`.
* `crawler/`
    * `__init__.py`
    * `crawler.py`: Le moteur de crawling (HTTPX, Playwright).
    * `parser.py`: Analyse HTML/JS pour extraire liens, formulaires, endpoints.
    * `subdomain_finder.py`: Modules pour la découverte de sous-domaines.
* `profiler/`
    * `__init__.py`
    * `tech_detector.py`: Détecte les technologies web.
* `attack_surface/`
    * `__init__.py`
    * `analyzer.py`: Identifie les points d'attaque (forms, params, headers, APIs).
* `vulnerabilities/`
    * `__init__.py`
    * `base_vulnerability.py`: Classe abstraite pour les vulnérabilités.
    * `xss.py`, `sqli.py`, `rce.py`, `ssrf.py`, `lfi.py`, `logic_flaws.py`, etc.: Implémentations spécifiques de chaque type de faille.
    * `payloads.py`: Base de données de payloads initiaux et patterns.
* `hebbian_learning/`
    * `__init__.py`
    * `hebbian_neuron.py`: Implémentation d'un neurone Hebbien simple.
    * `hebbian_network.py`: Un réseau de neurones Hebbien pour un point d'attaque donné.
    * `central_memory.py`: La base de connaissances centrale pour le cross-learning.
    * `feedback_interpreter.py`: Interprète les réponses HTTP pour les HLN.
* `orchestrator/`
    * `__init__.py`
    * `attack_orchestrator.py`: Coordonne les attaques, sélectionne les HLN, gère les requêtes.
* `reporting/`
    * `__init__.py`
    * `pdf_generator.py`: Génère les rapports PDF.
    * `dashboard.py`: Script Streamlit pour le dashboard.
* `utils/`
    * `__init__.py`
    * `logger.py`: Module de logging centralisé.
    * `helpers.py`: Fonctions utilitaires diverses.
    * `database.py`: Gère le stockage des résultats (SQLite pour la démo, extensible).
    * `models.py`: Modèles de données pour les URLs, vulnérabilités, etc.
