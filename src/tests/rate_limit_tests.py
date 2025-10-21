import time

class RateLimitTests:
    """Rate limiting tests."""

    def __init__(self, client):
        self.client = client

    def test_limit(self, endpoint, count, window):
        start = time.time()
        hits = 0
        for _ in range(count):
            r = self.client.get(endpoint)
            if r.status_code == 429:
                return {"test_name": "Rate Limiting", "endpoint": endpoint, "vulnerable": False, "severity": "LOW", "description": "Rate limiting active"}
            hits += 1
            if time.time() - start > window:
                break
        return {"test_name": "Rate Limiting", "endpoint": endpoint, "vulnerable": True, "severity": "MEDIUM", "description": f"No rate limit after {hits} requests"}

    def run_all_tests(self, endpoints, count, window):
        return [self.test_limit(e, count, window) for e in endpoints]
