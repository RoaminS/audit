# anonymity/tor_manager.py

import time
import logging
import httpx # Used for checking external IP via Tor SOCKS proxy

try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False
    logging.error("Stem library not found. Tor functionality will be disabled. Install with 'pip install stem'")

logger = logging.getLogger(__name__)

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
        if not STEM_AVAILABLE:
            self.tor_port = None
            self.control_port = None
            self.password = None
            self.controller = None
            self.is_connected = False
            logger.error("TorManager is not functional due to missing 'stem' library.")
            return

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
        if not STEM_AVAILABLE or self.is_connected:
            return self.is_connected

        try:
            self.controller = Controller.from_port(port=self.control_port)
            if self.password:
                self.controller.authenticate(password=self.password)
            else:
                # Attempting to authenticate without password, assuming CookieAuthentication or no auth
                try:
                    self.controller.authenticate()
                except Exception as e:
                    logger.warning(f"Could not authenticate without password. Ensure Tor is configured for CookieAuthentication or no authentication on control port. Error: {e}")

            self.is_connected = True
            logger.info(f"Connected to Tor control port on {self.control_port}")
            return True
        except Exception as e:
            self.is_connected = False
            logger.error(f"Error connecting to Tor control port on {self.control_port}: {e}")
            return False

    async def renew_tor_ip(self):
        """
        Demande à Tor de changer son circuit et donc d'obtenir une nouvelle IP.

        Returns:
            bool: True si la rotation de l'IP a réussi, False sinon.
        """
        if not STEM_AVAILABLE:
            logger.error("Cannot renew Tor IP: 'stem' library is not available.")
            return False

        if not self.is_connected:
            self.connect() # Attempt to reconnect if not connected
            if not self.is_connected:
                logger.error("Cannot renew IP: not connected to Tor control port.")
                return False

        try:
            logger.info("Renewing Tor IP...")
            self.controller.signal(Signal.NEWNYM)
            logger.info("NEWNYM signal sent. Waiting for new IP...")
            # Use asyncio.sleep for non-blocking wait
            await asyncio.sleep(self.controller.get_newnym_wait())
            logger.info("New Tor IP requested.")
            return True
        except Exception as e:
            logger.error(f"Error renewing Tor IP: {e}")
            return False

    async def get_current_external_ip(self):
        """
        Récupère l'adresse IP externe actuelle en utilisant Tor.

        Returns:
            str: L'adresse IP externe ou None en cas d'erreur.
        """
        if not self.tor_port:
            logger.warning("Tor SOCKS port not configured or stem not available. Cannot get IP via Tor.")
            return None

        proxies = {
            "http://": f"socks5h://127.0.0.1:{self.tor_port}",
            "https://": f"socks5h://127.0.0.1:{self.tor_port}"
        }
        try:
            async with httpx.AsyncClient(proxies=proxies, timeout=10) as client:
                response = await client.get('http://ipinfo.io/json')
                if response.status_code == 200:
                    ip_info = response.json()
                    return ip_info.get('ip')
                else:
                    logger.error(f"Error: Status {response.status_code} when getting IP via Tor.")
                    return None
        except httpx.RequestError as e:
            logger.error(f"Error getting IP via Tor: {e}")
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred while getting IP via Tor: {e}")
            return None


    def close(self):
        """
        Ferme la connexion au port de contrôle de Tor.
        """
        if self.controller:
            self.controller.close()
            self.is_connected = False
            logger.info("Tor controller connection closed.")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logger.info("Testing TorManager...")

    async def main():
        # Ensure Tor is running and its control port (9051) is accessible.
        # If you're using a password, replace 'your_tor_password' with it.
        # For many setups, if you configure ControlPort with CookieAuthentication,
        # you might not need to specify a password here.
        tm = TorManager(password="your_tor_password") # Replace if you have a password, or remove.

        if tm.is_connected:
            current_ip = await tm.get_current_external_ip()
            print(f"\nCurrent IP via Tor: {current_ip}")

            print("\nAttempting to renew Tor IP...")
            if await tm.renew_tor_ip():
                # Give some time for Tor to establish the new circuit
                await asyncio.sleep(5)
                new_ip = await tm.get_current_external_ip()
                print(f"New IP via Tor: {new_ip}")
            else:
                print("Failed to renew Tor IP.")
        else:
            print("Cannot test TorManager as connection failed.")

        tm.close()
        logger.info("TorManager test completed.")

    asyncio.run(main())
