import os
import sys

# ✅ Force Python to include project root and src/ in import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from flask import Flask, render_template, request
from utils.http_client import HTTPClient
from core.vulnerability_checker import VulnerabilityChecker
from tests.auth_tests import AuthTests
from tests.injection_tests import InjectionTests
from tests.rate_limit_tests import RateLimitTests
from tests.header_tests import HeaderTests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run_tests', methods=['POST'])
def run_tests():
    base = request.form['base_url']
    tests = request.form.getlist('tests')
    client = HTTPClient(base)
    checker = VulnerabilityChecker()

    if "auth" in tests: checker.add_results(AuthTests(client).run_all_tests(["/users"]))
    if "injection" in tests:
        payloads = {"sql_payloads":["' OR '1'='1"], "xss_payloads":["<script>alert(1)</script>"]}
        checker.add_results(InjectionTests(client, payloads).run_all_tests([{"endpoint":"/search","parameter":"q"}]))
    if "rate" in tests: checker.add_results(RateLimitTests(client).run_all_tests(["/users"],10,5))
    if "header" in tests: checker.add_results(HeaderTests(client).run_all_tests(["/users"]))

    return render_template('results.html', stats=checker.stats(), vulns=checker.vulns, recs=checker.recommendations())


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
