"""
Main vulnerability scanner class
"""
from html import parser
from json import scanner
from tabnanny import verbose

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
from src.scanners.command_injection import CommandInjectionScanner
from src.scanners.file_inclusion import FileInclusionScanner
from src.scanners.path_traversal import PathTraversalScanner
from src.scanners.headers import SecurityHeadersScanner
from src.scanners.csrf import CSRFScanner
from src.scanners.bruteforce import BruteForceScanner
from src.scanners.open_redirect import OpenRedirectScanner
from src.scanners.directory_listing import DirectoryListingScanner
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
        self.ci_scanner = CommandInjectionScanner(self.session, self.target_url, verbose)
        self.fi_scanner = FileInclusionScanner(self.session, self.target_url, verbose)
        self.pt_scanner = PathTraversalScanner(self.session, self.target_url, verbose)
        self.headers_scanner = SecurityHeadersScanner(self.session, self.target_url, verbose)
        self.csrf_scanner = CSRFScanner(self.session, self.target_url, verbose)
        self.bf_scanner = BruteForceScanner(self.session, self.target_url, verbose)
        self.or_scanner = OpenRedirectScanner(self.session, self.target_url, verbose)
        self.dl_scanner = DirectoryListingScanner(self.session, self.target_url, verbose)
        
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
    
    def run_command_injection_scan(self):
        """Run Command Injection vulnerability scan"""
        self.logger.info("🚀 Starting Command Injection scan...")
        
        vulnerabilities_found = self.ci_scanner.test_dvwa_command_injection_page()
        
        # Add findings to report
        for finding in self.ci_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding.get("type", "Command Injection"), 
                finding.get("payload", ""), 
                finding.get("url", ""), 
                "High"
            )
        
        if vulnerabilities_found:
            self.logger.warning("🎯 Command Injection vulnerabilities detected!")
        else:
            self.logger.info("✅ No Command Injection vulnerabilities detected")
        
        return vulnerabilities_found
    
    def run_file_inclusion_scan(self):
        """Run File Inclusion vulnerability scan (LFI/RFI)"""
        self.logger.info("🚀 Starting File Inclusion scan...")
        
        vulnerabilities_found = self.fi_scanner.test_dvwa_file_inclusion_page()
        
        # Add findings to report
        for finding in self.fi_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding.get("type", "File Inclusion"), 
                finding.get("payload", ""), 
                finding.get("url", ""), 
                "High"  # LFI/RFI are typically high severity
            )
        
        if vulnerabilities_found:
            self.logger.warning("🎯 File Inclusion vulnerabilities detected!")
        else:
            self.logger.info("✅ No File Inclusion vulnerabilities detected")
        
        return vulnerabilities_found
    
    def run_path_traversal_scan(self):
        """Run Path Traversal vulnerability scan"""
        self.logger.info("🚀 Starting Path Traversal scan...")
        
        vulnerabilities_found = self.pt_scanner.test_dvwa_path_traversal_page()
        
        for finding in self.pt_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding.get("type", "Path Traversal"),
                finding.get("payload", ""),
                finding.get("url", ""),
                "High"
            )
        
        if vulnerabilities_found:
            self.logger.warning("🎯 Path Traversal vulnerabilities detected!")
        else:
            self.logger.info("✅ No Path Traversal vulnerabilities detected")
        
        return vulnerabilities_found
    
    def run_headers_scan(self):
        """Run Security Headers scan"""
        self.logger.info("🚀 Starting Security Headers scan...")
        
        vulnerabilities_found = self.headers_scanner.scan_headers()
        
        # Add findings to report (headers scanner uses a different structure)
        for finding in self.headers_scanner.vulnerabilities_found:
            # Convert to our standard format
            self.reporter.add_finding(
                finding.get("type", "Missing Security Header"),
                f"{finding.get('header', '')}: {finding.get('description', '')}",
                finding.get("url", self.target_url),
                finding.get("severity", "Medium")
            )
        
        if vulnerabilities_found:
            self.logger.warning("🎯 Security header issues detected!")
        else:
            self.logger.info("✅ No security header issues detected")
        
        return vulnerabilities_found
    
    def run_csrf_scan(self):
        """Run CSRF vulnerability scan"""
        self.logger.info("🚀 Starting CSRF scan...")
        
        vulnerabilities_found = self.csrf_scanner.scan_dvwa_csrf()
        
        for finding in self.csrf_scanner.vulnerabilities_found:
            payload = f"Method: {finding.get('method', '')} - Form action: {finding.get('form_action', '')}"
            self.reporter.add_finding(
                finding.get("type", "CSRF"),
                payload,
                finding.get("url", self.target_url),
                finding.get("severity", "Medium")
            )
        
        if vulnerabilities_found:
            self.logger.warning("🎯 CSRF vulnerabilities detected!")
        else:
            self.logger.info("✅ No CSRF vulnerabilities detected")
        
        return vulnerabilities_found
    
    def run_bruteforce_scan(self):
        """Run Brute Force scan"""
        self.logger.info("🚀 Starting Brute Force scan...")
        vulnerabilities_found = self.bf_scanner.test_dvwa_bruteforce()

        for finding in self.bf_scanner.vulnerabilities_found:
            payload = f"Username: {finding.get('username', '')} Password: {finding.get('password', '')}"
            self.reporter.add_finding(
                finding.get("type", "Brute Force"),
                payload,
                finding.get("url", self.target_url),
                finding.get("severity", "High")
            )

        if vulnerabilities_found:
            self.logger.warning("🎯 Brute Force vulnerabilities detected!")
        else:
            self.logger.info("✅ No Brute Force vulnerabilities detected")
        return vulnerabilities_found
    
    def run_open_redirect_scan(self):
        """Run Open Redirect vulnerability scan"""
        self.logger.info("🚀 Starting Open Redirect scan...")
        vulnerabilities_found = self.or_scanner.scan_target()
        
        for finding in self.or_scanner.vulnerabilities_found:
            payload = f"Parameter: {finding.get('parameter', '')} -> {finding.get('redirects_to', '')}"
            self.reporter.add_finding(
                finding.get("type", "Open Redirect"),
                payload,
                finding.get("url", self.target_url),
                finding.get("severity", "Medium")
            )
        
        if vulnerabilities_found:
            self.logger.warning("🎯 Open Redirect vulnerabilities detected!")
        else:
            self.logger.info("✅ No Open Redirect vulnerabilities detected")
        return vulnerabilities_found
    
    def run_directory_listing_scan(self):
        """Run Directory Listing scan"""
        self.logger.info("🚀 Starting Directory Listing scan...")
        vulnerabilities_found = self.dl_scanner.scan_common_directories()
        
        for finding in self.dl_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding.get("type", "Directory Listing"),
                f"Indicator: {finding.get('indicator', '')}",
                finding.get("url", self.target_url),
                finding.get("severity", "Low")
            )
        
        if vulnerabilities_found:
            self.logger.warning("🎯 Directory Listing vulnerabilities detected!")
        else:
            self.logger.info("✅ No Directory Listing vulnerabilities detected")
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
    parser.add_argument('--ci', action='store_true', help='Run Command Injection scan') # NEW
    parser.add_argument('--fi', action='store_true', help='Run File Inclusion scan (LFI/RFI)')
    parser.add_argument('--pt', action='store_true', help='Run Path Traversal scan')
    parser.add_argument('--headers', action='store_true', help='Run Security Headers scan')
    parser.add_argument('--csrf', action='store_true', help='Run CSRF scan')
    parser.add_argument('--bf', action='store_true', help='Run Brute Force scan')
    parser.add_argument('--openredirect', action='store_true', help='Run Open Redirect scan')
    parser.add_argument('--dirlisting', action='store_true', help='Run Directory Listing scan')
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
        scanner.run_command_injection_scan()
        scanner.run_file_inclusion_scan()
        scanner.run_path_traversal_scan()
        scanner.run_headers_scan()
        scanner.run_csrf_scan()
        scanner.run_bruteforce_scan()
        scanner.run_open_redirect_scan()      
        scanner.run_directory_listing_scan()
        scanner.generate_reports()  # This now includes the summary
    elif args.sql:
        scanner.run_sql_injection_scan()
        scanner.generate_reports()
    elif args.xss:
        scanner.run_xss_scan()
        scanner.generate_reports()
    elif args.ci:
        scanner.run_command_injection_scan()
        scanner.generate_reports()
    elif args.fi:   
        scanner.run_file_inclusion_scan()
        scanner.generate_reports()
    elif args.pt:
        scanner.run_path_traversal_scan()
        scanner.generate_reports()
    elif args.headers:
        scanner.run_headers_scan()
        scanner.generate_reports()
    elif args.csrf:
        scanner.run_csrf_scan()
        scanner.generate_reports()
    elif args.bf:
        scanner.run_bruteforce_scan()
        scanner.generate_reports()
    elif args.openredirect:
        scanner.run_open_redirect_scan()
        scanner.generate_reports()
    elif args.dirlisting:
        scanner.run_directory_listing_scan()
        scanner.generate_reports()
    else:
        scanner.logger.info("Ready to start scanning! Use --sql, --xss, --ci, --fi, --pt, --headers, --csrf, --bf, --openredirect, --dirlisting, or --full to run scans")

if __name__ == "__main__":
    main()
