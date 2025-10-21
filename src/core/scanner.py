"""Main security scanner orchestrator"""

from typing import List, Dict, Any
from ..utils.http_client import HTTPClient
from ..utils.config import Config
from ..tests.auth_tests import AuthTests
from ..tests.injection_tests import InjectionTests
from ..tests.rate_limit_tests import RateLimitTests
from ..tests.header_tests import HeaderTests
from .vulnerability_checker import VulnerabilityChecker


class SecurityScanner:
    """Main API security scanner"""
    
    def __init__(self, config: Config):
        self.config = config
        self.client = self._setup_client()
        self.vulnerability_checker = VulnerabilityChecker()
        self.results: List[Dict[str, Any]] = []
    
    def _setup_client(self) -> HTTPClient:
        """Setup HTTP client with authentication"""
        client = HTTPClient(
            base_url=self.config.get_base_url(),
            timeout=self.config.get_timeout(),
            verify_ssl=self.config.is_ssl_verify_enabled()
        )
        
        # Configure authentication
        auth_config = self.config.get_auth_config()
        auth_type = auth_config.get('type', 'none')
        
        if auth_type == 'bearer':
            token = auth_config.get('token', '')
            if token:
                client.set_bearer_token(token)
        elif auth_type == 'api_key':
            header = auth_config.get('api_key_header', 'X-API-Key')
            key = auth_config.get('api_key_value', '')
            if key:
                client.set_api_key(header, key)
        elif auth_type == 'basic':
            username = auth_config.get('username', '')
            password = auth_config.get('password', '')
            if username and password:
                client.set_basic_auth(username, password)
        
        return client
    
    def run_auth_tests(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Run authentication tests"""
        print("\n[*] Running Authentication Tests...")
        auth_tester = AuthTests(self.client)
        results = auth_tester.run_all_tests(endpoints)
        self.results.extend(results)
        self.vulnerability_checker.add_results(results)
        return results
    
    def run_injection_tests(self, test_cases: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Run injection tests"""
        print("\n[*] Running Injection Tests...")
        payloads = self.config.get('tests.injection', {})
        injection_tester = InjectionTests(self.client, payloads)
        results = injection_tester.run_all_tests(test_cases)
        self.results.extend(results)
        self.vulnerability_checker.add_results(results)
        return results
    
    def run_rate_limit_tests(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Run rate limiting tests"""
        print("\n[*] Running Rate Limit Tests...")
        rate_limit_config = self.config.get('tests.rate_limit', {})
        requests_count = rate_limit_config.get('requests_count', 100)
        time_window = rate_limit_config.get('time_window', 60)
        
        rate_limit_tester = RateLimitTests(self.client)
        results = rate_limit_tester.run_all_tests(endpoints, requests_count, time_window)
        self.results.extend(results)
        self.vulnerability_checker.add_results(results)
        return results
    
    def run_header_tests(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Run security header tests"""
        print("\n[*] Running Security Header Tests...")
        header_tester = HeaderTests(self.client)
        results = header_tester.run_all_tests(endpoints)
        self.results.extend(results)
        self.vulnerability_checker.add_results(results)
        return results
    
    def run_full_scan(
        self,
        endpoints: List[str],
        injection_test_cases: List[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Run full security scan"""
        print("\n" + "="*60)
        print("API Security Scanner - Full Scan Starting")
        print("="*60)
        print(f"Target: {self.config.get_base_url()}")
        print(f"Endpoints to test: {len(endpoints)}")
        
        enabled_tests = self.config.get('tests.enabled', [])
        
        # Run enabled tests
        if 'auth_tests' in enabled_tests:
            self.run_auth_tests(endpoints)
        
        if 'injection_tests' in enabled_tests and injection_test_cases:
            self.run_injection_tests(injection_test_cases)
        
        if 'rate_limit_tests' in enabled_tests:
            self.run_rate_limit_tests(endpoints[:2])  # Limit to 2 endpoints
        
        if 'header_tests' in enabled_tests:
            self.run_header_tests(endpoints)
        
        # Generate summary
        stats = self.vulnerability_checker.get_statistics()
        recommendations = self.vulnerability_checker.get_recommendations()
        
        scan_summary = {
            'total_tests': len(self.results),
            'vulnerabilities': self.vulnerability_checker.vulnerabilities,
            'statistics': stats,
            'recommendations': recommendations,
            'all_results': self.results
        }
        
        print("\n" + "="*60)
        print("Scan Complete!")
        print("="*60)
        print(f"Total Tests Run: {scan_summary['total_tests']}")
        print(f"Vulnerabilities Found: {stats['total_vulnerabilities']}")
        print(f"Risk Score: {stats['risk_score']}/100")
        
        return scan_summary