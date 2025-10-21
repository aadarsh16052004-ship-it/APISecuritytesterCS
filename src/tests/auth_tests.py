class AuthTests:
    """Authentication security tests."""

    def __init__(self, client):
        self.client = client

    def test_no_auth(self, endpoint):
        headers = self.client.auth_headers.copy()
        self.client.auth_headers = {}
        resp = self.client.get(endpoint)
        self.client.auth_headers = headers
        return {
            "test_name": "No Authentication",
            "endpoint": endpoint,
            "vulnerable": resp.status_code == 200,
            "severity": "HIGH",
            "description": "Accessible without authentication" if resp.status_code == 200 else "Properly secured",
        }

    def test_invalid_token(self, endpoint):
        self.client.auth_headers = {"Authorization": "Bearer invalid"}
        resp = self.client.get(endpoint)
        return {
            "test_name": "Invalid Token",
            "endpoint": endpoint,
            "vulnerable": resp.status_code == 200,
            "severity": "CRITICAL",
            "description": "Invalid token accepted" if resp.status_code == 200 else "Rejected correctly",
        }

    def run_all_tests(self, endpoints):
        results = []
        for e in endpoints:
            results.append(self.test_no_auth(e))
            results.append(self.test_invalid_token(e))
        return results
