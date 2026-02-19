"""
Security Headers Scanner Module
Checks for missing or misconfigured security headers
"""
from urllib.parse import urljoin
from src.utils.logger import setup_logger

class SecurityHeadersScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.vulnerabilities_found = []
        self.headers_checked = []

    def scan_headers(self):
        """
        Scan the target URL for security headers
        Returns: Boolean - True if any issues found
        """
        self.logger.info("🔒 Scanning security headers...")
        self.vulnerabilities_found = []
        self.headers_checked = []

        try:
            # Send a GET request to the target
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers

            # Define security headers to check
            security_headers = {
                'Strict-Transport-Security': {
                    'description': 'HTTP Strict Transport Security (HSTS)',
                    'severity': 'Medium',
                    'recommendation': 'Implement HSTS to enforce HTTPS connections. Example: Strict-Transport-Security: max-age=31536000; includeSubDomains'
                },
                'Content-Security-Policy': {
                    'description': 'Content Security Policy (CSP)',
                    'severity': 'Medium',
                    'recommendation': 'Implement CSP to mitigate XSS and data injection attacks. Example: Content-Security-Policy: default-src "self"'
                },
                'X-Content-Type-Options': {
                    'description': 'X-Content-Type-Options',
                    'severity': 'Low',
                    'recommendation': 'Set X-Content-Type-Options: nosniff to prevent MIME type sniffing'
                },
                'X-Frame-Options': {
                    'description': 'X-Frame-Options',
                    'severity': 'Low',
                    'recommendation': 'Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking'
                },
                'X-XSS-Protection': {
                    'description': 'X-XSS-Protection',
                    'severity': 'Low',
                    'recommendation': 'Set X-XSS-Protection: 1; mode=block to enable browser XSS filtering (though modern browsers use CSP)'
                },
                'Referrer-Policy': {
                    'description': 'Referrer Policy',
                    'severity': 'Low',
                    'recommendation': 'Set Referrer-Policy to control referrer information. Example: Referrer-Policy: same-origin'
                },
                'Permissions-Policy': {
                    'description': 'Permissions Policy (formerly Feature-Policy)',
                    'severity': 'Low',
                    'recommendation': 'Implement Permissions-Policy to restrict browser features. Example: Permissions-Policy: geolocation=(), camera=()'
                },
                'Cache-Control': {
                    'description': 'Cache-Control',
                    'severity': 'Low',
                    'recommendation': 'Set Cache-Control: no-cache, no-store, must-revalidate for sensitive pages'
                },
                'Clear-Site-Data': {
                    'description': 'Clear-Site-Data',
                    'severity': 'Info',
                    'recommendation': 'Consider using Clear-Site-Data header for logout functionality'
                }
            }

            # Check each header
            for header, info in security_headers.items():
                present = header in headers
                value = headers.get(header, '')
                self.headers_checked.append({
                    'header': header,
                    'present': present,
                    'value': value
                })

                if not present:
                    self.logger.debug(f"⚠️ Missing header: {header}")
                    self.vulnerabilities_found.append({
                        "type": "Missing Security Header",
                        "header": header,
                        "description": info['description'],
                        "severity": info['severity'],
                        "recommendation": info['recommendation'],
                        "url": self.target_url
                    })
                else:
                    self.logger.debug(f"✅ Found header: {header} = {value}")

            # Special checks for CSP (if present)
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                    self.logger.warning("⚠️ CSP allows unsafe-inline or unsafe-eval")
                    self.vulnerabilities_found.append({
                        "type": "Weak Content Security Policy",
                        "header": "Content-Security-Policy",
                        "description": "CSP allows unsafe-inline or unsafe-eval, which weakens XSS protection",
                        "severity": "Medium",
                        "recommendation": "Avoid using 'unsafe-inline' and 'unsafe-eval' in CSP. Use nonces or hashes instead.",
                        "url": self.target_url
                    })

            # Report summary
            if self.vulnerabilities_found:
                self.logger.warning(f"🎯 Found {len(self.vulnerabilities_found)} security header issues")
                return True
            else:
                self.logger.info("✅ All recommended security headers are present")
                return False

        except Exception as e:
            self.logger.error(f"❌ Error scanning headers: {str(e)}")
            return False