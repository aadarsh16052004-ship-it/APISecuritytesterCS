import os
import sys

# ✅ Force Python to include project root and src/ in import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.config import Config
from utils.http_client import HTTPClient
from core.vulnerability_checker import VulnerabilityChecker
from core.report_generator import ReportGenerator
from tests.auth_tests import AuthTests
from tests.injection_tests import InjectionTests
from tests.rate_limit_tests import RateLimitTests
from tests.header_tests import HeaderTests


def main():
    print("\n🛡️ API Security Tester\n")

    cfg = Config("config.yaml")
    client = HTTPClient(cfg.get_base_url(), cfg.get_timeout(), cfg.ssl_verify())
    checker = VulnerabilityChecker()
    reporter = ReportGenerator(cfg.get("reporting.output_dir", "reports"))
    tests = cfg.get("tests.enabled", [])

    if "auth_tests" in tests:
        checker.add_results(AuthTests(client).run_all_tests(["/users", "/posts"]))

    if "injection_tests" in tests:
        payloads = cfg.get("tests.injection", {})
        checker.add_results(InjectionTests(client, payloads).run_all_tests([{"endpoint": "/search", "parameter": "q"}]))

    if "rate_limit_tests" in tests:
        rate = cfg.get("tests.rate_limit", {})
        checker.add_results(RateLimitTests(client).run_all_tests(["/users"], rate["requests_count"], rate["time_window"]))

    if "header_tests" in tests:
        checker.add_results(HeaderTests(client).run_all_tests(["/users", "/profile"]))

    stats, vulns, recs = checker.stats(), checker.vulns, checker.recommendations()
    path = reporter.save_html(stats, vulns, recs)
    print(f"\n✅ Scan complete! Report saved at: {path}\n")


if __name__ == "__main__":
    main()
