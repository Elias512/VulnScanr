"""
Security Headers Scanner
"""
from src.scanners.base import BaseScanner

class SecurityHeadersScanner(BaseScanner):
    def __init__(self, session, logger, verbose=False):
        super().__init__(session, logger, verbose)
        self.security_headers = {
            'Strict-Transport-Security': {'severity': 'Medium', 'desc': 'HSTS'},
            'Content-Security-Policy': {'severity': 'Medium', 'desc': 'CSP'},
            'X-Content-Type-Options': {'severity': 'Low', 'desc': 'X-Content-Type-Options'},
            'X-Frame-Options': {'severity': 'Low', 'desc': 'X-Frame-Options'},
            'X-XSS-Protection': {'severity': 'Low', 'desc': 'X-XSS-Protection'},
            'Referrer-Policy': {'severity': 'Low', 'desc': 'Referrer-Policy'},
            'Permissions-Policy': {'severity': 'Low', 'desc': 'Permissions-Policy'},
            'Cache-Control': {'severity': 'Low', 'desc': 'Cache-Control'},
        }

    def test_url(self, url, method='GET'):
        self.logger.debug(f"Testing security headers for {url}")
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            for header, info in self.security_headers.items():
                if header not in headers:
                    self.logger.warning(f"Missing security header: {header} on {url}")
                    self.vulnerabilities_found.append({
                        "type": "Missing Security Header",
                        "header": header,
                        "url": url,
                        "severity": info['severity']
                    })
            return len(self.vulnerabilities_found) > 0
        except Exception as e:
            self.logger.debug(f"Error checking headers for {url}: {e}")
            return False

    def test_form(self, form):
        # Headers scanner doesn't apply to forms directly
        return False