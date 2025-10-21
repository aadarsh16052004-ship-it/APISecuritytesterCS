class InjectionTests:
    """SQL/XSS injection tests."""

    def __init__(self, client, payloads):
        self.client = client
        self.payloads = payloads

    def test_sql_injection(self, endpoint, param):
        for p in self.payloads.get("sql_payloads", []):
            r = self.client.get(endpoint, params={param: p})
            if any(x in r.text.lower() for x in ["sql", "syntax", "query failed"]):
                return {"test_name": "SQL Injection", "endpoint": endpoint, "vulnerable": True, "severity": "CRITICAL", "description": f"Payload: {p}"}
        return {"test_name": "SQL Injection", "endpoint": endpoint, "vulnerable": False, "severity": "INFO", "description": "No SQLi"}

    def test_xss(self, endpoint, param):
        for p in self.payloads.get("xss_payloads", []):
            r = self.client.get(endpoint, params={param: p})
            if p in r.text:
                return {"test_name": "XSS", "endpoint": endpoint, "vulnerable": True, "severity": "HIGH", "description": "Reflected payload"}
        return {"test_name": "XSS", "endpoint": endpoint, "vulnerable": False, "severity": "INFO", "description": "No XSS"}

    def run_all_tests(self, cases):
        results = []
        for c in cases:
            results.append(self.test_sql_injection(c["endpoint"], c["parameter"]))
            results.append(self.test_xss(c["endpoint"], c["parameter"]))
        return results
