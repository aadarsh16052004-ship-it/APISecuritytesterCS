class HeaderTests:
    """HTTP security headers tests."""

    def __init__(self, client):
        self.client = client

    def test_headers(self, endpoint):
        resp = self.client.get(endpoint)
        missing = []
        required = ["X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
        for h in required:
            if h not in resp.headers:
                missing.append(h)
        return {
            "test_name": "Security Headers",
            "endpoint": endpoint,
            "vulnerable": bool(missing),
            "severity": "MEDIUM",
            "description": f"Missing headers: {', '.join(missing)}" if missing else "All headers present"
        }

    def run_all_tests(self, endpoints):
        return [self.test_headers(e) for e in endpoints]
