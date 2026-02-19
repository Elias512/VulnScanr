"""
Open Redirect Scanner Module
Detects unvalidated redirects in URL parameters.
Now includes DVWA-specific testing with login.
"""
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from src.utils.logger import setup_logger

class OpenRedirectScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.vulnerabilities_found = []

    def dvwa_login(self):
        """Login to DVWA (reused)"""
        try:
            self.logger.info("🔐 Logging into DVWA for open redirect test...")
            login_url = urljoin(self.target_url, "/login.php")
            get_response = self.session.get(login_url)
            if get_response.status_code != 200:
                return False
            soup = BeautifulSoup(get_response.text, 'html.parser')
            csrf_token_input = soup.find('input', {'name': 'user_token'})
            if not csrf_token_input:
                return False
            csrf_token = csrf_token_input.get('value')
            login_data = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": csrf_token
            }
            post_response = self.session.post(login_url, data=login_data)
            if "PHPSESSID" in self.session.cookies:
                self.logger.info("✅ Logged into DVWA")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Login error: {str(e)}")
            return False

    def test_dvwa_open_redirect(self):
        """Specifically test DVWA's open redirect page."""
        if not self.dvwa_login():
            self.logger.error("Cannot proceed without login")
            return False

        or_url = urljoin(self.target_url, "/vulnerabilities/open_redirect/")
        # Common redirect parameter names in DVWA
        redirect_params = ['redirect', 'url', 'next']
        test_domain = "https://example.com"

        for param in redirect_params:
            test_url = f"{or_url}?{param}={test_domain}"
            try:
                self.logger.debug(f"Testing {test_url}")
                response = self.session.get(test_url, allow_redirects=False, timeout=10)
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if test_domain in location:
                        self.logger.warning(f"⚠️ Open redirect found on DVWA with parameter '{param}'")
                        self.vulnerabilities_found.append({
                            "type": "Open Redirect",
                            "url": test_url,
                            "parameter": param,
                            "redirects_to": location,
                            "severity": "Medium"
                        })
            except Exception as e:
                self.logger.debug(f"Error testing {param}: {str(e)}")

        return len(self.vulnerabilities_found) > 0

    def scan_target(self, use_dvwa_specific=True):
        """
        Scan for open redirects.
        If use_dvwa_specific is True, test DVWA's known vulnerable page.
        """
        self.logger.info("🎯 Scanning for open redirects...")
        self.vulnerabilities_found = []

        if use_dvwa_specific:
            self.test_dvwa_open_redirect()

        # Also run generic tests on common paths (optional)
        paths_to_test = ['', '/login', '/redirect', '/index.php']
        redirect_params = ['redirect', 'url', 'next', 'return']

        for path in paths_to_test:
            url = urljoin(self.target_url, path)
            for param in redirect_params:
                test_url = f"{url}?{param}=https://example.com"
                try:
                    response = self.session.get(test_url, allow_redirects=False, timeout=10)
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'example.com' in location:
                            self.logger.warning(f"⚠️ Open redirect found on {url} with parameter '{param}'")
                            self.vulnerabilities_found.append({
                                "type": "Open Redirect",
                                "url": test_url,
                                "parameter": param,
                                "redirects_to": location,
                                "severity": "Medium"
                            })
                except Exception:
                    pass

        if self.vulnerabilities_found:
            self.logger.warning(f"🎯 Found {len(self.vulnerabilities_found)} open redirect vulnerabilities!")
            return True
        else:
            self.logger.info("✅ No open redirect vulnerabilities detected")
            return False