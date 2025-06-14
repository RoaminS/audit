import json
import hashlib
from typing import Any


def hash_data(data: Any) -> str:
    """Return a SHA-256 hash of the given data."""
    json_data = json.dumps(data, sort_keys=True)
    return hashlib.sha256(json_data.encode("utf-8")).hexdigest()
