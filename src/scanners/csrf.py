"""
CSRF Scanner
"""
from src.scanners.base import BaseScanner

class CSRFScanner(BaseScanner):
    def __init__(self, session, logger, verbose=False):
        super().__init__(session, logger, verbose)
        self.csrf_token_names = [
            'csrf_token', 'csrf-token', 'csrf', '_token', 'authenticity_token',
            'csrfmiddlewaretoken', '__RequestVerificationToken', 'xsrf-token',
            'xsrf_token', 'csrf_test_name', 'token', '_csrf', 'csrfkey'
        ]

    def test_url(self, url, method='GET'):
        # CSRF is form-specific; we can ignore URL-only tests
        return False

    def test_form(self, form):
        # Only consider state-changing methods (POST, PUT, DELETE)
        if form['method'].upper() not in ['POST', 'PUT', 'DELETE']:
            return False

        inputs = form.get('inputs', [])
        found_token = any(inp.get('name', '').lower() in self.csrf_token_names for inp in inputs)
        if not found_token:
            self.logger.warning(f"CSRF token missing in form {form['url']} (method {form['method']})")
            self.vulnerabilities_found.append({
                "type": "CSRF (Missing Token)",
                "url": form['url'],
                "method": form['method'],
                "severity": "Medium"
            })
            return True
        return False