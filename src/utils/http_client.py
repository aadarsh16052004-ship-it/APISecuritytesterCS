import requests
from requests.auth import HTTPBasicAuth

class HTTPClient:
    """HTTP Client with auth support."""

    def __init__(self, base_url: str, timeout: int = 30, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.auth_headers = {}

    def set_bearer(self, token: str):
        self.auth_headers["Authorization"] = f"Bearer {token}"

    def set_api_key(self, header: str, key: str):
        self.auth_headers[header] = key

    def set_basic(self, user: str, pwd: str):
        self.session.auth = HTTPBasicAuth(user, pwd)

    def request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {**self.auth_headers, **kwargs.pop("headers", {})}
        return self.session.request(
            method=method.upper(),
            url=url,
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers=headers,
            **kwargs
        )

    def get(self, endpoint, **kw): return self.request("GET", endpoint, **kw)
    def post(self, endpoint, **kw): return self.request("POST", endpoint, **kw)
