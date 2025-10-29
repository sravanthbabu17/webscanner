import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
from concurrent.futures import ThreadPoolExecutor

class WebSecurityScanner:
    def __init__(self, target_url, max_depth=2, checks=None):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.checks = checks or ["sql", "xss", "sensitive", "headers"]
        colorama.init()

    def crawl(self, url, depth=0):
        if depth > self.max_depth or url in self.visited:
            return
        self.visited.add(url)
        try:
            resp = self.session.get(url, timeout=4, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all('a', href=True):
                next_url = urllib.parse.urljoin(url, a['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth+1)
        except Exception:
            pass

    def check_sql_injection(self, url):
        try:
            payload = "' OR '1'='1"
            test_url = f"{url}?test={payload}"
            resp = self.session.get(test_url, timeout=4, verify=False)
            errors = ["sql syntax", "unexpected end of SQL", "mysql_fetch", "syntax error"]
            for error in errors:
                if error in resp.text.lower():
                    self.vulnerabilities.append({
                        "type": "SQL Injection",
                        "detail": f"Potential SQLi at {url}",
                        "recommendation": "Validate and sanitize inputs server-side."
                    })
                    return
        except Exception:
            pass

    def check_xss(self, url):
        try:
            payload = "<script>alert('x')</script>"
            test_url = f"{url}?xss={payload}"
            resp = self.session.get(test_url, timeout=4, verify=False)
            if payload in resp.text:
                self.vulnerabilities.append({
                    "type": "XSS",
                    "detail": f"Possible reflected XSS at {url}",
                    "recommendation": "Escape output and use Content-Security-Policy."
                })
        except Exception:
            pass

    def check_sensitive_info(self, url):
        try:
            resp = self.session.get(url, timeout=4, verify=False)
            keywords = ["password", "secret", "api_key", "token"]
            for keyword in keywords:
                if keyword in resp.text.lower():
                    self.vulnerabilities.append({
                        "type": "Sensitive Information",
                        "detail": f"Sensitive info ({keyword}) found at {url}",
                        "recommendation": "Do not hard-code credentials; use env variables."
                    })
        except Exception:
            pass

    def check_security_headers(self, url):
        try:
            resp = self.session.get(url, timeout=4, verify=False)
            required_headers = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security']
            for header in required_headers:
                if header not in resp.headers:
                    self.vulnerabilities.append({
                        "type": "Missing Security Headers",
                        "detail": f"Missing {header} at {url}",
                        "recommendation": f"Add {header} header for robust security."
                    })
        except Exception:
            pass

    def scan(self):
        self.crawl(self.target_url)
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited:
                if "sql" in self.checks:
                    executor.submit(self.check_sql_injection, url)
                if "xss" in self.checks:
                    executor.submit(self.check_xss, url)
                if "sensitive" in self.checks:
                    executor.submit(self.check_sensitive_info, url)
                if "headers" in self.checks:
                    executor.submit(self.check_security_headers, url)
        return self.vulnerabilities, len(self.visited)
