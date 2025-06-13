# anonymity/proxy_manager.py

import random
import requests
import time
from collections import deque

class ProxyManager:
    def __init__(self, proxy_list=None, validation_url='http://ipinfo.io/json', validation_timeout=5, rotate_interval=300):
        """
        Gère un pool de proxies, leur rotation et leur validation.

        Args:
            proxy_list (list): Une liste de chaînes de caractères de proxies (e.g., "http://user:pass@host:port").
            validation_url (str): L'URL utilisée pour valider les proxies en vérifiant leur IP.
            validation_timeout (int): Le délai d'attente en secondes pour la validation des proxies.
            rotate_interval (int): L'intervalle en secondes après lequel un proxy est marqué comme "à faire pivoter".
        """
        self.proxies = deque()
        self.active_proxies = {}  # {proxy_url: {'last_used': timestamp, 'valid': boolean}}
        self.validation_url = validation_url
        self.validation_timeout = validation_timeout
        self.rotate_interval = rotate_interval
        self.load_proxies(proxy_list)
        self.current_proxy = None
        self.last_rotation_time = 0

    def load_proxies(self, proxy_list):
        """
        Charge les proxies dans le gestionnaire.

        Args:
            proxy_list (list): Une liste de chaînes de caractères de proxies.
        """
        if proxy_list:
            for proxy_url in proxy_list:
                self.proxies.append(proxy_url)
                self.active_proxies[proxy_url] = {'last_used': 0, 'valid': False}
            print(f"Chargement de {len(proxy_list)} proxies.")
            self.validate_all_proxies()
        else:
            print("Aucune liste de proxies fournie.")

    def validate_proxy(self, proxy_url):
        """
        Valide un proxy en tentant une requête via celui-ci.

        Args:
            proxy_url (str): L'URL du proxy à valider.

        Returns:
            bool: True si le proxy est valide, False sinon.
        """
        try:
            proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }
            response = requests.get(self.validation_url, proxies=proxies, timeout=self.validation_timeout)
            if response.status_code == 200:
                ip_info = response.json()
                print(f"Proxy {proxy_url} valide. IP: {ip_info.get('ip')}")
                self.active_proxies[proxy_url]['valid'] = True
                return True
            else:
                print(f"Proxy {proxy_url} invalide. Statut: {response.status_code}")
                self.active_proxies[proxy_url]['valid'] = False
                return False
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la validation du proxy {proxy_url}: {e}")
            self.active_proxies[proxy_url]['valid'] = False
            return False

    def validate_all_proxies(self):
        """Valide tous les proxies chargés."""
        print("Validation de tous les proxies...")
        for proxy_url in list(self.active_proxies.keys()): # Iterate over a copy to allow modification
            self.validate_proxy(proxy_url)
        print("Validation des proxies terminée.")

    def get_proxy(self):
        """
        Récupère un proxy valide du pool.
        Effectue une rotation si le proxy actuel est trop ancien ou invalide.

        Returns:
            str: L'URL du proxy actuel, ou None si aucun proxy valide n'est disponible.
        """
        if not self.active_proxies:
            print("Aucun proxy n'est chargé ou actif.")
            return None

        # Prioritize rotating if current proxy is old or invalid
        if self.current_proxy and (time.time() - self.active_proxies[self.current_proxy]['last_used'] > self.rotate_interval or not self.active_proxies[self.current_proxy]['valid']):
            print(f"Proxy actuel {self.current_proxy} à faire pivoter ou invalide. Rotation...")
            self.rotate_proxy()
            return self.current_proxy

        # Initial selection or if current_proxy is None
        if not self.current_proxy or not self.active_proxies.get(self.current_proxy, {}).get('valid'):
            self.rotate_proxy()
            return self.current_proxy

        return self.current_proxy

    def rotate_proxy(self):
        """
        Fait pivoter le proxy vers le prochain proxy valide disponible dans le pool.
        """
        if not self.proxies:
            print("Aucun proxy dans le pool pour effectuer une rotation.")
            self.current_proxy = None
            return

        initial_len = len(self.proxies)
        for _ in range(initial_len): # Iterate through all available proxies once
            candidate_proxy = self.proxies.popleft()
            if self.active_proxies.get(candidate_proxy, {}).get('valid'):
                self.current_proxy = candidate_proxy
                self.active_proxies[self.current_proxy]['last_used'] = time.time()
                self.proxies.append(candidate_proxy) # Put it back at the end
                print(f"Rotation vers le proxy: {self.current_proxy}")
                self.last_rotation_time = time.time()
                return
            else:
                # If invalid, put it at the end but don't consider it immediately
                self.proxies.append(candidate_proxy)
                print(f"Proxy {candidate_proxy} est invalide, skipping pour la rotation.")

        print("Impossible de trouver un proxy valide pour la rotation. Réessayez de valider tous les proxies.")
        self.current_proxy = None

    def mark_proxy_invalid(self, proxy_url):
        """
        Marque un proxy comme invalide.

        Args:
            proxy_url (str): L'URL du proxy à marquer comme invalide.
        """
        if proxy_url in self.active_proxies:
            self.active_proxies[proxy_url]['valid'] = False
            print(f"Proxy {proxy_url} marqué comme invalide.")
            # Trigger a rotation if the current proxy becomes invalid
            if self.current_proxy == proxy_url:
                print("Le proxy actuel est devenu invalide. Déclenchement d'une rotation immédiate.")
                self.rotate_proxy()

    def get_current_proxy(self):
        """
        Retourne le proxy actuellement sélectionné.

        Returns:
            str: L'URL du proxy actuellement sélectionné, ou None.
        """
        return self.current_proxy

    def __len__(self):
        return len(self.proxies)

if __name__ == '__main__':
    # Exemple d'utilisation
    print("Test du ProxyManager...")

    # Liste de proxies d'exemple (remplacez par vos propres proxies)
    # Pour le test, nous allons simuler un proxy qui pourrait échouer
    example_proxies = [
        "http://good.proxy.com:8080",
        "http://user:pass@bad.proxy.com:8081", # Ceci pourrait échouer
        "http://another.good.proxy.com:8082",
    ]

    # Pour un test réel, utilisez de vrais proxies ou un service de mock.
    # Ici, nous allons simuler le comportement de validation.
    # NOTE: Pour que cet exemple fonctionne réellement avec la validation,
    # vous devrez avoir des proxies fonctionnels ou un serveur de test local.

    # Mocking requests.get for demonstration purposes
    original_get = requests.get

    def mock_requests_get(url, proxies=None, timeout=None):
        if proxies and "bad.proxy.com" in proxies.get('http', ''):
            print(f"Simulating failure for {proxies.get('http')}")
            raise requests.exceptions.RequestException("Simulated connection error")
        elif proxies and ("good.proxy.com" in proxies.get('http', '') or "another.good.proxy.com" in proxies.get('http', '')):
            print(f"Simulating success for {proxies.get('http')}")
            class MockResponse:
                def __init__(self):
                    self.status_code = 200
                def json(self):
                    return {"ip": "192.168.1.1"}
            return MockResponse()
        else:
            return original_get(url, proxies=proxies, timeout=timeout)

    requests.get = mock_requests_get

    pm = ProxyManager(proxy_list=example_proxies, validation_url='http://mock-ipinfo.io/json', rotate_interval=10)

    print("\nTentative de récupération du premier proxy...")
    current_p = pm.get_proxy()
    if current_p:
        print(f"Proxy actuel: {current_p}")
    else:
        print("Aucun proxy n'a pu être récupéré.")

    print("\nAttente pour simuler la rotation...")
    time.sleep(11) # Attendre plus que rotate_interval

    print("\nTentative de récupération d'un nouveau proxy après intervalle...")
    current_p = pm.get_proxy()
    if current_p:
        print(f"Nouveau proxy après rotation: {current_p}")
    else:
        print("Aucun nouveau proxy n'a pu être récupéré après rotation.")

    print("\nMarquage du proxy actuel comme invalide et déclenchement d'une rotation...")
    if pm.get_current_proxy():
        pm.mark_proxy_invalid(pm.get_current_proxy())
        print(f"Proxy après marquage invalide: {pm.get_current_proxy()}")
    else:
        print("Pas de proxy actuel à marquer invalide.")

    # Restaurer la fonction originale
    requests.get = original_get
    print("\nTest du ProxyManager terminé.")
