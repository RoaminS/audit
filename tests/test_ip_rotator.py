import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from anonymity.ip_rotator import IPRotator

class DummyTorManager:
    def __init__(self):
        self.tor_port = 9050
        self.is_connected = True
    async def renew_tor_ip(self):
        return True
    def close(self):
        pass

@pytest.mark.asyncio
async def test_iprotator_switches_to_tor_after_three_429():
    rotator = IPRotator(proxy_list=None, tor_enabled=False)
    # Inject dummy Tor manager to avoid external dependencies
    rotator.tor_enabled = True
    rotator.tor_manager = DummyTorManager()
    rotator.current_ip_source = "direct"

    # Simulate three consecutive 429 responses
    await rotator.record_http_status(429)
    assert rotator.get_proxy_type() != "tor"

    await rotator.record_http_status(429)
    assert rotator.get_proxy_type() != "tor"

    await rotator.record_http_status(429)
    assert rotator.get_proxy_type() == "tor"
