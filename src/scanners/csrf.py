"""
CSRF (Cross-Site Request Forgery) Scanner Module
Identifies forms that lack CSRF protection tokens.
"""
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from src.utils.logger import setup_logger

class CSRFScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.vulnerabilities_found = []

    def check_form_for_csrf(self, form, page_url):
        """
        Check a single form for CSRF protection.
        Returns (bool, list): (is_vulnerable, reasons)
        """
        # Common CSRF token field names
        csrf_token_names = [
            'csrf_token', 'csrf-token', 'csrf', '_token', 'authenticity_token',
            'csrfmiddlewaretoken', '__RequestVerificationToken', 'xsrf-token',
            'xsrf_token', 'csrf_test_name', 'token', '_csrf', 'csrfkey'
        ]

        # Get all input fields
        inputs = form.find_all('input')
        has_token = False
        token_fields = []

        for inp in inputs:
            name = inp.get('name', '').lower()
            if name in csrf_token_names:
                has_token = True
                token_fields.append(name)

        # Also check for meta tags that might contain CSRF token
        # (some apps put token in meta and JavaScript reads it)
        # Not implemented here for simplicity.

        # Determine vulnerability
        is_vulnerable = not has_token
        reasons = []
        if is_vulnerable:
            reasons.append("No CSRF token field found in form")
        return is_vulnerable, reasons

    def scan_page(self, url):
        """
        Scan a single page for forms vulnerable to CSRF.
        """
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                self.logger.debug(f"  Page returned {response.status_code}, skipping")
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            self.logger.debug(f"  Found {len(forms)} form(s) on {url}")

            for form in forms:
                form_action = form.get('action', '')
                # Resolve absolute URL
                if form_action:
                    form_url = urljoin(url, form_action)
                else:
                    form_url = url  # submits to same page

                method = form.get('method', 'get').upper()
                # Typically CSRF applies to state-changing methods (POST, PUT, DELETE)
                if method not in ['POST', 'PUT', 'DELETE']:
                    continue  # GET forms are usually not vulnerable (but could be)

                is_vuln, reasons = self.check_form_for_csrf(form, url)
                if is_vuln:
                    self.logger.warning(f"  ⚠️ Vulnerable form found: {method} {form_url}")
                    for r in reasons:
                        self.logger.debug(f"     - {r}")
                    self.vulnerabilities_found.append({
                        "type": "CSRF (Missing Token)",
                        "url": form_url,
                        "method": method,
                        "form_action": form_action,
                        "reasons": reasons,
                        "severity": "Medium"
                    })

        except Exception as e:
            self.logger.error(f"  Error scanning {url}: {str(e)}")

    def dvwa_login(self):
        """Login to DVWA (reused)"""
        try:
            self.logger.info("🔐 Attempting to login to DVWA for CSRF scan...")
            login_url = urljoin(self.target_url, "/login.php")
            get_response = self.session.get(login_url)
            if get_response.status_code != 200:
                self.logger.error(f"❌ Failed to access login page. Status: {get_response.status_code}")
                return False
            soup = BeautifulSoup(get_response.text, 'html.parser')
            csrf_token_input = soup.find('input', {'name': 'user_token'})
            if not csrf_token_input:
                self.logger.error("❌ Could not find CSRF token on login page")
                return False
            csrf_token = csrf_token_input.get('value')
            self.logger.debug(f"📋 Found CSRF token: {csrf_token}")
            login_data = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": csrf_token
            }
            post_response = self.session.post(login_url, data=login_data)
            if "Login failed" in post_response.text:
                self.logger.error("❌ Login failed - Incorrect username/password")
                return False
            elif "PHPSESSID" in self.session.cookies:
                self.logger.info("✅ Successfully logged into DVWA")
                self.set_dvwa_security_low()
                return True
            else:
                self.logger.error("❌ Login failed - Unknown reason")
                return False
        except Exception as e:
            self.logger.error(f"💥 Login error: {str(e)}")
            return False

    def set_dvwa_security_low(self):
        """Set DVWA security to low"""
        try:
            security_url = urljoin(self.target_url, "/security.php")
            response = self.session.get(security_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token_input = soup.find('input', {'name': 'user_token'})
            if not csrf_token_input:
                self.logger.warning("⚠️ Could not find CSRF token on security page")
                return
            csrf_token = csrf_token_input.get('value')
            security_data = {
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": csrf_token
            }
            response = self.session.post(security_url, data=security_data)
            if "Security level is currently: low" in response.text:
                self.logger.info("✅ DVWA security level set to LOW")
            else:
                self.logger.warning("⚠️ Could not verify security level change")
        except Exception as e:
            self.logger.warning(f"⚠️ Could not set security level: {str(e)}")

    def scan_dvwa_csrf(self):
        """
        Scan DVWA for CSRF vulnerabilities.
        This targets known pages that might have forms.
        """
        self.logger.info("🎯 Testing DVWA for CSRF vulnerabilities...")
        self.vulnerabilities_found = []

        if not self.dvwa_login():
            self.logger.error("🚫 Cannot proceed without DVWA login")
            return False

        # List of DVWA pages to scan for forms
        pages_to_scan = [
            "/vulnerabilities/csrf/",         # CSRF change password
            "/vulnerabilities/exec/",          # Command Injection (has form)
            "/vulnerabilities/sqli/",          # SQL Injection (has form)
            "/vulnerabilities/xss_r/",         # XSS reflected (has form)
            "/vulnerabilities/xss_s/",         # XSS stored (has form)
            "/vulnerabilities/fi/",            # File Inclusion (has form)
            "/security.php",                    # Security settings (has form)
            "/setup.php",                        # Setup (has form)
        ]

        for page in pages_to_scan:
            url = urljoin(self.target_url, page)
            self.logger.info(f"🔍 Scanning {url}")
            self.scan_page(url)

        if self.vulnerabilities_found:
            self.logger.warning(f"🎯 Found {len(self.vulnerabilities_found)} CSRF vulnerable forms!")
            return True
        else:
            self.logger.info("✅ No CSRF vulnerabilities detected")
            return False