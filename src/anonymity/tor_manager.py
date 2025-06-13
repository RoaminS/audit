# anonymity/tor_manager.py

import time
from stem import Signal
from stem.control import Controller
import requests

class TorManager:
    def __init__(self, tor_port=9050, control_port=9051, password=None):
        """
        Intègre le contrôle du service Tor pour la rotation d'IP.

        Args:
            tor_port (int): Le port SOCKS de Tor (généralement 9050).
            control_port (int): Le port de contrôle de Tor (généralement 9051).
            password (str): Le mot de passe pour le port de contrôle de Tor.
                            Si non fourni, il est assumé que le contrôle est sans mot de passe
                            (ex: configuré via CookieAuthentication).
        """
        self.tor_port = tor_port
        self.control_port = control_port
        self.password = password
        self.controller = None
        self.is_connected = False
        self.connect()

    def connect(self):
        """
        Établit une connexion avec le port de contrôle de Tor.
        """
        try:
            self.controller = Controller.from_port(port=self.control_port)
            if self.password:
                self.controller.authenticate(password=self.password)
            else:
                # Attempting to authenticate without password, assuming CookieAuthentication or no auth
                try:
                    self.controller.authenticate()
                except Exception as e:
                    print(f"Avertissement: Impossible d'authentifier sans mot de passe. Assurez-vous que Tor est configuré pour CookieAuthentication ou pas d'authentification sur le port de contrôle. Erreur: {e}")

            self.is_connected = True
            print(f"Connecté au port de contrôle de Tor sur {self.control_port}")
        except Exception as e:
            self.is_connected = False
            print(f"Erreur de connexion au port de contrôle de Tor sur {self.control_port}: {e}")

    def renew_tor_ip(self):
        """
        Demande à Tor de changer son circuit et donc d'obtenir une nouvelle IP.

        Returns:
            bool: True si la rotation de l'IP a réussi, False sinon.
        """
        if not self.is_connected:
            self.connect() # Tente de se reconnecter si non connecté
            if not self.is_connected:
                print("Impossible de renouveler l'IP: non connecté au port de contrôle de Tor.")
                return False

        try:
            print("Renouvellement de l'IP Tor...")
            self.controller.signal(Signal.NEWNYM)
            print("Signal NEWNYM envoyé. Attente de la nouvelle IP...")
            time.sleep(self.controller.get_newnym_wait()) # Attendre le temps recommandé par Tor
            print("Nouvelle IP Tor demandée.")
            return True
        except Exception as e:
            print(f"Erreur lors du renouvellement de l'IP Tor: {e}")
            return False

    def get_current_external_ip(self):
        """
        Récupère l'adresse IP externe actuelle en utilisant Tor.

        Returns:
            str: L'adresse IP externe ou None en cas d'erreur.
        """
        proxies = {
            "http": f"socks5h://127.0.0.1:{self.tor_port}",
            "https": f"socks5h://127.0.0.1:{self.tor_port}"
        }
        try:
            response = requests.get('http://ipinfo.io/json', proxies=proxies, timeout=10)
            if response.status_code == 200:
                ip_info = response.json()
                return ip_info.get('ip')
            else:
                print(f"Erreur: Statut {response.status_code} lors de la récupération de l'IP via Tor.")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la récupération de l'IP via Tor: {e}")
            return None

    def close(self):
        """
        Ferme la connexion au port de contrôle de Tor.
        """
        if self.controller:
            self.controller.close()
            self.is_connected = False
            print("Connexion au contrôleur Tor fermée.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

if __name__ == '__main__':
    print("Test du TorManager...")

    # Assurez-vous que Tor est en cours d'exécution et que le port de contrôle (9051)
    # est accessible. Si vous utilisez un mot de passe, modifiez la ligne suivante.
    # Pour de nombreux setups, si vous configurez ControlPort avec CookieAuthentication,
    # vous n'avez pas besoin de spécifier un mot de passe ici.

    # Exemple pour macOS/Linux (assurez-vous que le fichier de cookie est lisible par l'utilisateur)
    # try:
    #     with open("/opt/homebrew/var/lib/tor/control_auth_cookie", "rb") as f:
    #         cookie = f.read()
    #     # Si vous utilisez un cookie, authentification se fait via le cookie.
    #     # La classe TorManager devrait être modifiée pour gérer l'authentification par cookie.
    #     # Pour l'exemple simple, nous allons supposer soit pas de mot de passe soit un mot de passe simple.
    # except FileNotFoundError:
    #     print("Fichier de cookie d'authentification Tor non trouvé.")
    #     print("Assurez-vous que Tor est configuré pour l'authentification par cookie ou par mot de passe.")
    #     print("Pour le test, nous allons tenter sans mot de passe.")
    #     # Pour tester sans mot de passe, vous devez avoir 'ControlPort 9051' et 'CookieAuthentication 0' ou 'HashedControlPassword ""'
    #     # dans votre torrc (ce qui est déconseillé pour la production).

    tm = TorManager() # Assurez-vous que Tor est en cours d'exécution et accessible

    if tm.is_connected:
        print(f"\nIP actuelle via Tor: {tm.get_current_external_ip()}")

        print("\nTentative de renouvellement d'IP Tor...")
        if tm.renew_tor_ip():
            time.sleep(5) # Donner un peu de temps pour que Tor établisse le nouveau circuit
            new_ip = tm.get_current_external_ip()
            print(f"Nouvelle IP via Tor: {new_ip}")
        else:
            print("Échec du renouvellement de l'IP Tor.")
    else:
        print("Impossible de tester TorManager car la connexion a échoué.")

    tm.close()
    print("\nTest du TorManager terminé.")
