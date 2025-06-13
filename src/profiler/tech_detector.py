# profiler/tech_detector.py

import httpx
import logging
import re
from typing import Dict, List, Set, Any

logger = logging.getLogger(__name__)

class TechDetector:
    """
    Détecte les technologies web utilisées sur un site en analysant les en-têtes HTTP,
    le contenu HTML et les fichiers JavaScript.
    """
    def __init__(self):
        # Règles de détection des technologies.
        # Format: {'tech_name': {'headers': {'header_name': 'regex'}, 'html': 'regex', 'js': 'regex', 'url': 'regex'}}
        # Ces règles sont simplifiées et peuvent être étendues considérablement.
        self.detection_rules = {
            "WordPress": {
                "html": r"wp-content|wp-includes|wordpress",
                "headers": {"x-pingback": r".*"},
                "url": r"wp-login\.php|wp-admin"
            },
            "Joomla": {
                "html": r"joomla\.css|joomla\.js|com_content",
                "headers": {"x-joomla-version": r".*"},
                "url": r"/index\.php\?option=com_content"
            },
            "Drupal": {
                "html": r"drupal\.js|sites/default/files",
                "headers": {"x-drupal-cache": r".*"},
                "url": r"/?q=node/\d+"
            },
            "React": {
                "html": r"<div id=\"root\">|<div data-reactroot",
                "js": r"ReactDOM\.(render|createRoot)|React\.createElement"
            },
            "Angular": {
                "html": r"<app-root>|<ng-app",
                "js": r"angular\.module|ng-version"
            },
            "Vue.js": {
                "html": r"<div id=\"app\">|<div data-v-",
                "js": r"Vue\.config|__vue_app__"
            },
            "jQuery": {
                "js": r"jQuery\.fn\.jquery|\\.ajax\\(|\\$\\(|\\.\\$|\\[object jQuery\\]"
            },
            "Bootstrap": {
                "html": r"cdn\.jsdelivr\.net/npm/bootstrap|bootstrap\.(min\.)?css",
                "headers": {},
                "js": r"bootstrap\.bundle\.min\.js|data-toggle=\"collapse\""
            },
            "Nginx": {
                "headers": {"server": r"nginx"}
            },
            "Apache": {
                "headers": {"server": r"apache"}
            },
            "IIS": {
                "headers": {"server": r"IIS"}
            },
            "PHP": {
                "headers": {"x-powered-by": r"PHP"},
                "url": r"\.php"
            },
            "ASP.NET": {
                "headers": {"x-aspnet-version": r".*|x-powered-by": r"ASP\.NET"},
                "html": r"__VIEWSTATE"
            },
            "Node.js (Express)": {
                "headers": {"x-powered-by": r"Express"}
            },
            "OpenSSL": {
                "headers": {"server": r"OpenSSL"}
            },
            "Cloudflare": {
                "headers": {"server": r"cloudflare"},
                "html": r"cf-email|cf-container"
            },
            "Google Analytics": {
                "html": r"googletagmanager\.com/gtag/js|google-analytics\.com/analytics\.js"
            },
            "Google Tag Manager": {
                "html": r"googletagmanager\.com/gtm\.js"
            },
            "Font Awesome": {
                "html": r"fontawesome\.com/releases"
            },
            "Sentry": {
                "js": r"Sentry\.init"
            },
            "Grafana": {
                "html": r"<grafana-app>",
                "url": r"/grafana"
            }
            # Ajoutez plus de règles ici
        }
        logger.info("TechDetector initialized with detection rules.")

    async def detect(self, url: str, response: httpx.Response = None, html_content: str = None, js_content: str = None) -> Set[str]:
        """
        Détecte les technologies web basées sur la réponse HTTP, le contenu HTML et JS.

        Args:
            url (str): L'URL de la ressource.
            response (httpx.Response, optional): L'objet réponse HTTPX.
            html_content (str, optional): Le contenu HTML de la page.
            js_content (str, optional): Le contenu JavaScript de la page (peut être concaténé).

        Returns:
            Set[str]: Un ensemble des noms de technologies détectées.
        """
        detected_techs = set()
        
        # S'assurer que nous avons du contenu à analyser
        if response is None and html_content is None and js_content is None:
            logger.warning(f"No response or content provided for {url}. Cannot perform detection.")
            return detected_techs

        logger.debug(f"Starting technology detection for: {url}")

        for tech, rules in self.detection_rules.items():
            # Détection par en-têtes HTTP
            if "headers" in rules and response:
                for header_name, pattern_str in rules["headers"].items():
                    if header_name in response.headers:
                        if re.search(pattern_str, response.headers[header_name], re.IGNORECASE):
                            detected_techs.add(tech)
                            logger.debug(f"Detected {tech} via header '{header_name}' on {url}")

            # Détection par contenu HTML
            if "html" in rules and html_content:
                if re.search(rules["html"], html_content, re.IGNORECASE):
                    detected_techs.add(tech)
                    logger.debug(f"Detected {tech} via HTML content on {url}")

            # Détection par contenu JavaScript
            if "js" in rules and js_content:
                if re.search(rules["js"], js_content, re.IGNORECASE):
                    detected_techs.add(tech)
                    logger.debug(f"Detected {tech} via JavaScript content on {url}")
            
            # Détection par URL
            if "url" in rules and url:
                if re.search(rules["url"], url, re.IGNORECASE):
                    detected_techs.add(tech)
                    logger.debug(f"Detected {tech} via URL pattern on {url}")
        
        logger.info(f"Finished technology detection for {url}. Detected: {', '.join(detected_techs) if detected_techs else 'None'}")
        return detected_techs

    async def get_tech_profile(self, urls: List[str], ip_rotator: Any) -> Dict[str, Set[str]]:
        """
        Récupère le profil technologique pour une liste d'URLs en utilisant IPRotator
        pour la résilience et l'anonymat.

        Args:
            urls (List[str]): Liste des URLs à profiler.
            ip_rotator (Any): Une instance de la classe IPRotator pour les requêtes.

        Returns:
            Dict[str, Set[str]]: Un dictionnaire où la clé est l'URL et la valeur est un ensemble
                                  des technologies détectées pour cette URL.
        """
        tech_profiles = {}
        for url in urls:
            logger.info(f"Profiling technologies for URL: {url}")
            response = None
            html_content = None
            js_content = None

            try:
                # Utilise _get_client de Crawler pour la compatibilité proxy/Tor
                # Note: Ici, nous avons besoin d'un moyen de récupérer le client avec proxy.
                # Pour éviter une dépendance circulaire directe avec Crawler, nous allons
                # simuler l'appel à une méthode de httpx.AsyncClient ou passer la config proxy.
                
                # Solution temporaire: Le IPRotator devrait fournir les configs de proxy
                async with await ip_rotator.get_proxies_for_request() as proxies_config:
                    async with httpx.AsyncClient(proxies=proxies_config, follow_redirects=True, timeout=10) as client:
                        response = await client.get(url)
                        response.raise_for_status()
                        html_content = response.text
                        
                        # Pour une détection JS plus approfondie, on pourrait vouloir
                        # extraire les scripts et les charger. Pour l'instant, on se base
                        # sur le contenu HTML des scripts.
                        # Cela nécessiterait une étape de scraping de Playwright si la page
                        # est fortement dynamique pour récupérer le JS après exécution.
                        
                        # Simple extraction de contenu JS pour les scripts inlines
                        js_inline_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
                        inline_scripts = "".join(js_inline_pattern.findall(html_content))
                        
                        # Charger les scripts externes si possible (nécessiterait de les télécharger)
                        # Pour cet exemple, on se concentre sur l'analyse de ce qui est déjà là.
                        
                        js_content = inline_scripts #+ downloaded_external_js_content if available
                        
            except httpx.RequestError as e:
                logger.error(f"Failed to fetch {url} for tech profiling: {e}")
                # Peut-être faire une rotation d'IP ici aussi si la requête échoue
                await ip_rotator.rotate_ip()
            except Exception as e:
                logger.error(f"An unexpected error occurred during tech profiling for {url}: {e}")

            if response:
                detected = await self.detect(url=url, response=response, html_content=html_content, js_content=js_content)
                tech_profiles[url] = detected
            else:
                tech_profiles[url] = set() # Aucune détection si la requête a échoué

        return tech_profiles

# Exemple d'utilisation (pour les tests)
async def test_tech_detector():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Dummy IPRotator pour les tests
    class DummyIpRotator:
        def __init__(self):
            self.current_proxy = None
            self.proxy_type = "Direct"

        async def get_proxies_for_request(self, force_tor=False):
            class AsyncProxyContext:
                async def __aenter__(self):
                    return self.proxies
                async def __aexit__(self, exc_type, exc_val, exc_tb):
                    pass
                def __init__(self, proxies):
                    self.proxies = proxies
            return AsyncProxyContext(None) # Pas de proxy pour ce test simple

        def get_current_proxy(self): return self.current_proxy
        def get_proxy_type(self): return self.proxy_type
        async def rotate_ip(self): pass

    ip_rotator = DummyIpRotator()
    detector = TechDetector()

    test_urls = [
        "https://wordpress.com/",          # Devrait détecter WordPress
        "https://www.joomla.org/",           # Devrait détecter Joomla
        "https://react.dev/",               # Devrait détecter React
        "https://angular.io/",              # Devrait détecter Angular
        "https://vuejs.org/",               # Devrait détecter Vue.js
        "https://www.w3.org/Style/CSS/",    # Un site simple, moins de technologies spécifiques
        "http://httpbin.org/html"           # Un site de test pour le HTML
    ]

    print("\n--- Starting Technology Detection Test ---")
    tech_results = await detector.get_tech_profile(test_urls, ip_rotator)

    for url, techs in tech_results.items():
        print(f"\nURL: {url}")
        if techs:
            print(f"  Detected Technologies: {', '.join(techs)}")
        else:
            print("  No specific technologies detected or failed to fetch.")

    print("\n--- Technology Detection Test Completed ---")

if __name__ == "__main__":
    asyncio.run(test_tech_detector())
