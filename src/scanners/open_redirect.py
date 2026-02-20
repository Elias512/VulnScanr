"""
Generic Open Redirect Scanner
"""
from urllib.parse import urljoin
from src.scanners.base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class OpenRedirectScanner(BaseScanner):
    def __init__(self, session, logger, verbose=False):
        super().__init__(session, logger, verbose)
        self.redirect_params = [
            'redirect', 'redirect_uri', 'redirect_url', 'url', 'next', 'return',
            'return_to', 'return_url', 'goto', 'target', 'dest', 'destination',
            'out', 'view', 'dir', 'to', 'location', 'path', 'continue', 'returnPath'
        ]
        self.test_domain = "https://example.com"

    def test_url(self, url, method='GET'):
        self.logger.debug(f"Testing URL for open redirect: {url}")
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}
        if not params:
            return False

        for param in params:
            if param.lower() in self.redirect_params:
                injected_url = self._inject_parameter(url, param, self.test_domain)
                if not injected_url:
                    continue
                try:
                    response = self.session.get(injected_url, allow_redirects=False, timeout=10)
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if self.test_domain in location:
                            self.logger.warning(f"🔀 Open redirect found: {url} param={param}")
                            self.vulnerabilities_found.append({
                                "type": "Open Redirect",
                                "url": url,
                                "parameter": param,
                                "redirects_to": location,
                                "severity": "Medium"
                            })
                            return True
                except Exception as e:
                    self.logger.debug(f"Error testing {param}: {e}")
        return False

    def test_form(self, form):
        # Open redirect can also be in forms (hidden fields, etc.)
        inputs = form.get('inputs', [])
        testable = [i for i in inputs if i.get('name') and i['name'].lower() in self.redirect_params]
        if not testable:
            return False

        for inp in testable:
            param = inp['name']
            data = self._build_form_data(form, param, self.test_domain)
            try:
                if form['method'].upper() == 'POST':
                    response = self.session.post(form['url'], data=data, allow_redirects=False, timeout=10)
                else:
                    response = self.session.get(form['url'], params=data, allow_redirects=False, timeout=10)
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if self.test_domain in location:
                        self.logger.warning(f"🔀 Open redirect found in form {form['url']} param={param}")
                        self.vulnerabilities_found.append({
                            "type": "Open Redirect",
                            "url": form['url'],
                            "parameter": param,
                            "redirects_to": location,
                            "severity": "Medium"
                        })
                        return True
            except Exception as e:
                self.logger.debug(f"Error testing form param {param}: {e}")
        return False