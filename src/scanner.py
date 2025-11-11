"""
Main vulnerability scanner class
"""
import requests
import argparse
import sys
import os
from urllib.parse import urljoin



# Import our custom modules
from src.utils.logger import setup_logger
from src.core.config import SCANNER_CONFIG, SUSPICIOUS_STATUS_CODES
from src.scanners.sql_injection import SQLInjectionScanner
from src.scanners.xss import XSSScanner
from src.utils.reporter import ReportGenerator

class VulnScanr:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.session = requests.Session()
        
        # Set up session with configured settings
        self.session.headers.update({
            'User-Agent': SCANNER_CONFIG['user_agent']
        })
        self.timeout = SCANNER_CONFIG['timeout']
        
        # Initialize scanners
        self.sql_scanner = SQLInjectionScanner(self.session, self.target_url, verbose)
        self.xss_scanner = XSSScanner(self.session, self.target_url, verbose) 
        
        # Initialize reporter
        self.reporter = ReportGenerator(target_url, verbose)

        self.logger.info(f"VulnScanr initialized for target: {self.target_url}")
    
    def test_connection(self):
        """Test if we can connect to the target"""
        self.logger.info("Testing connection to target...")
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                self.logger.info("✅ Successfully connected to target")
                return True
            else:
                self.logger.warning(f"Target returned status: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"❌ Connection failed: {e}")
            return False
    
    def run_xss_scan(self):
        """Run XSS vulnerability scan"""
        self.logger.info("🚀 Starting XSS scan...")
        
        vulnerabilities_found = self.xss_scanner.test_dvwa_xss_page()
        
         # Add findings to report - FIXED: Handle tuple format
        for finding in self.xss_scanner.vulnerabilities_found:
            if isinstance(finding, tuple) and len(finding) == 2:
                # Handle tuple format: (payload, url)
                payload, url = finding
                self.reporter.add_finding("XSS", payload, url, "Medium")
            elif isinstance(finding, dict):
                # Handle dictionary format
                self.reporter.add_finding(
                    finding.get("type", "XSS"), 
                    finding.get("payload", ""), 
                    finding.get("url", ""), 
                    "Medium"
                )

        if vulnerabilities_found:
            self.logger.warning("🎯 XSS vulnerabilities detected!")
        else:
            self.logger.info("✅ No XSS vulnerabilities detected")
        
        return vulnerabilities_found

    def run_sql_injection_scan(self):
        """Run SQL injection vulnerability scan"""
        self.logger.info("🚀 Starting SQL injection scan...")
        
        # Use the enhanced DVWA testing
        vulnerabilities_found = self.sql_scanner.test_dvwa_sqli()

        # Add findings to report - FIXED: Handle tuple format
        for finding in self.sql_scanner.vulnerabilities_found:
            if isinstance(finding, tuple) and len(finding) == 2:
                # Handle tuple format: (payload, url)
                payload, url = finding
                self.reporter.add_finding("SQL Injection", payload, url, "High")
            elif isinstance(finding, dict):
                # Handle dictionary format
                self.reporter.add_finding(
                    finding.get("type", "SQL Injection"), 
                    finding.get("payload", ""), 
                    finding.get("url", ""), 
                    "High"
                )

        if vulnerabilities_found:
            self.logger.warning("🎯 SQL injection vulnerabilities detected!")
        else:
            self.logger.info("✅ No SQL injection vulnerabilities detected")
        
        return vulnerabilities_found

    # Update the generate_reports method:
    def generate_reports(self):
        """Generate all reports and show summary"""
        if not self.reporter.findings:
            self.logger.info("📝 No vulnerabilities found to report")
            return
        
        self.logger.info("📄 Generating scan reports...")
        
        # Generate reports
        html_report = self.reporter.generate_html_report()
        json_report = self.reporter.generate_json_report()
        
        # Show text summary
        summary = self.reporter.generate_text_summary()
        self.logger.info(summary)
        
        if html_report and json_report:
            self.logger.info("✅ Reports generated successfully!")
        else:
            self.logger.error("❌ Some reports failed to generate")

def main():
    """Main entry point for the scanner"""
    banner = """
    ╦   ╦ ╦╔═╗╔╗╔╔═╗╔╦╗╔═╗╦═╗
    ║   ║ ║╠═╣║║║╠═╣ ║ ╠═╣╠╦╝
    ╩   ╚═╝╩ ╩╝╚╝╩ ╩ ╩ ╩ ╩╩╚═
    Simple Web Vulnerability Scanner
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description='VulnScanr - Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan (e.g., http://localhost)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--sql', action='store_true', help='Run SQL injection scan')
    parser.add_argument('--xss', action='store_true', help='Run XSS scan')  # NEW
    parser.add_argument('--full', action='store_true', help='Run all scans')  # NEW
    
    args = parser.parse_args()
    
    # Initialize the scanner
    scanner = VulnScanr(args.url, verbose=args.verbose)
    
    # Test connection first
    if not scanner.test_connection():
        scanner.logger.error("Cannot proceed without a valid connection to the target.")
        sys.exit(1)
    
    # Run scans based on arguments
    if args.full:
        scanner.logger.info("🔍 Running FULL security scan...")
        scanner.run_sql_injection_scan()
        scanner.run_xss_scan()
        scanner.generate_reports()  # This now includes the summary
    elif args.sql:
        scanner.run_sql_injection_scan()
        scanner.generate_reports()
    elif args.xss:
        scanner.run_xss_scan()
        scanner.generate_reports()
    else:
        scanner.logger.info("Ready to start scanning! Use --sql, --xss, or --full to run scans")

if __name__ == "__main__":
    main()
