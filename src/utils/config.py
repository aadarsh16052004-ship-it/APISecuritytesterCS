import yaml
from typing import Any, Dict

class Config:
    """Loads configuration from YAML file."""

    def __init__(self, path: str = "config.yaml"):
        self.path = path
        self.data: Dict[str, Any] = {}
        self.load()

    def load(self):
        try:
            with open(self.path, "r") as f:
                self.data = yaml.safe_load(f)
        except Exception as e:
            raise Exception(f"Failed to load config: {e}")

    def get(self, key: str, default=None):
        keys = key.split(".")
        value = self.data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value or default

    def get_base_url(self):
        return self.get("api.base_url", "")

    def get_timeout(self):
        return self.get("api.timeout", 30)

    def ssl_verify(self):
        return self.get("api.verify_ssl", True)
