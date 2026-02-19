"""
Brute Force Scanner Module
Tests login pages for weak authentication mechanisms.
"""
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import time
from src.utils.logger import setup_logger

class BruteForceScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.vulnerabilities_found = []

    def dvwa_login(self):
        """Login to DVWA to access pages (reused)"""
        try:
            self.logger.info("🔐 Logging into DVWA for brute force test...")
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
                self.logger.info("✅ Logged in")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Login error: {str(e)}")
            return False

    def test_dvwa_bruteforce(self):
        """
        Test DVWA's Brute Force page for weak authentication.
        Attempts a few common passwords to see if any succeed.
        """
        self.logger.info("🎯 Testing DVWA Brute Force page...")
        self.vulnerabilities_found = []

        if not self.dvwa_login():
            self.logger.error("Cannot proceed without login")
            return False

        bf_url = urljoin(self.target_url, "/vulnerabilities/brute/")
        # Common test passwords
        test_passwords = ["password", "123456", "admin", "letmein", "qwerty"]
        success_count = 0

        for pwd in test_passwords:
            try:
                self.logger.debug(f"🧪 Testing password: {pwd}")
                params = {"username": "admin", "password": pwd, "Login": "Login"}
                response = self.session.get(bf_url, params=params)

                # Check if login succeeded (look for "Welcome" or absence of error)
                if "Welcome to the password protected area" in response.text:
                    self.logger.warning(f"🔓 Successful login with password: {pwd}")
                    self.vulnerabilities_found.append({
                        "type": "Weak Password (Brute Force)",
                        "username": "admin",
                        "password": pwd,
                        "url": bf_url,
                        "severity": "High"
                    })
                    success_count += 1
                    # Stop after first success to avoid excessive requests
                    break

                # Also check for rate limiting or lockout
                if "Too many failures" in response.text or "locked" in response.text:
                    self.logger.info("✅ Rate limiting/lockout detected")
                    self.vulnerabilities_found.append({
                        "type": "Rate Limiting Detected",
                        "info": "Application appears to have protections against brute force",
                        "url": bf_url,
                        "severity": "Info"
                    })
                    break

                # Small delay to avoid hammering
                time.sleep(1)

            except Exception as e:
                self.logger.error(f"Error testing {pwd}: {str(e)}")

        if success_count > 0:
            self.logger.warning(f"🎯 Found {success_count} weak credentials!")
            return True
        else:
            self.logger.info("✅ No weak credentials found (or protected)")
            return False