"""
Generic Brute Force Scanner (weak password testing)
"""
import time
from src.scanners.base import BaseScanner

class BruteForceScanner(BaseScanner):
    def __init__(self, session, logger, verbose=False):
        super().__init__(session, logger, verbose)
        self.common_passwords = ["password", "123456", "admin", "letmein", "qwerty", "root", "toor"]

    def test_url(self, url, method='GET'):
        # Brute force is form-specific; ignore URL-only
        return False

    def test_form(self, form):
        # Identify likely login form: has password input
        inputs = form.get('inputs', [])
        username_field = None
        password_field = None
        for inp in inputs:
            if inp.get('type') == 'password':
                password_field = inp.get('name')
            elif inp.get('type') in ['text', 'email']:
                username_field = inp.get('name')

        if not password_field:
            return False  # Not a login form

        # Try common passwords with a fixed username (admin)
        test_username = username_field if username_field else 'username'
        for pwd in self.common_passwords:
            data = {}
            for inp in inputs:
                name = inp.get('name')
                if name == username_field:
                    data[name] = 'admin'
                elif name == password_field:
                    data[name] = pwd
                else:
                    data[name] = inp.get('value', '')

            try:
                if form['method'].upper() == 'POST':
                    response = self.session.post(form['url'], data=data, timeout=10)
                else:
                    response = self.session.get(form['url'], params=data, timeout=10)

                # Check for success indicators (e.g., "Welcome", "Logout")
                if "Welcome" in response.text or "logout" in response.text.lower() or "dashboard" in response.text.lower():
                    self.logger.warning(f"🔓 Weak password found: {pwd} on {form['url']}")
                    self.vulnerabilities_found.append({
                        "type": "Weak Password (Brute Force)",
                        "url": form['url'],
                        "username": "admin",
                        "password": pwd,
                        "severity": "High"
                    })
                    return True

                # Small delay to avoid lockout
                time.sleep(0.5)
            except Exception as e:
                self.logger.debug(f"Error testing password {pwd}: {e}")
        return False