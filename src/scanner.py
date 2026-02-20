"""
Main vulnerability scanner class
"""
import requests
import argparse
import sys
import os
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# Import our custom modules
from src.crawler.crawler import WebCrawler
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
        
        # Initialize scanners (generic versions, no target_url needed)
        self.sql_scanner = SQLInjectionScanner(self.session, self.logger, verbose)
        self.xss_scanner = XSSScanner(self.session, self.logger, verbose)
        self.ci_scanner = CommandInjectionScanner(self.session, self.logger, verbose)
        self.fi_scanner = FileInclusionScanner(self.session, self.logger, verbose)
        self.pt_scanner = PathTraversalScanner(self.session, self.logger, verbose)
        self.headers_scanner = SecurityHeadersScanner(self.session, self.logger, verbose)
        self.csrf_scanner = CSRFScanner(self.session, self.logger, verbose)
        self.bf_scanner = BruteForceScanner(self.session, self.logger, verbose)
        self.or_scanner = OpenRedirectScanner(self.session, self.logger, verbose)
        self.dl_scanner = DirectoryListingScanner(self.session, self.logger, verbose)
        
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
    
    # ----------------------------------------------------------------------
    # Crawler
    # ----------------------------------------------------------------------
    def run_crawler(self):
        """Run web crawler to discover URLs and forms after authenticating with DVWA."""
        self.logger.info("🕷️ Starting web crawler with authentication...")

        # --- Login to DVWA first (if target is DVWA) ---
        try:
            login_url = urljoin(self.target_url, "/login.php")
            self.logger.info("🔐 Logging into DVWA for crawler...")
            
            resp = self.session.get(login_url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'user_token'}).get('value')
            
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            self.session.post(login_url, data=login_data)
            
            # Verify login
            test_url = urljoin(self.target_url, "/index.php")
            test_resp = self.session.get(test_url)
            if "Welcome" in test_resp.text or "Logout" in test_resp.text:
                self.logger.info("✅ Successfully logged into DVWA")
            else:
                self.logger.warning("⚠️ Login may have failed; crawler may have limited access")
        except Exception as e:
            self.logger.error(f"Login failed: {e}")
            self.logger.info("Continuing crawl without authentication...")

        crawler = WebCrawler(
            session=self.session,
            base_url=self.target_url,
            max_pages=100,
            max_depth=5,
            verbose=self.verbose
        )
        
        urls, forms = crawler.crawl()
        crawler.print_summary()

        # Save results to files in reports folder
        try:
            os.makedirs('reports', exist_ok=True)
            
            with open('reports/crawled_urls.txt', 'w') as f:
                for url in urls:
                    f.write(url + '\n')
            
            with open('reports/crawled_forms.txt', 'w') as f:
                for form in forms:
                    f.write(f"URL: {form['url']}\nMethod: {form['method']}\nInputs: {len(form['inputs'])}\nPage: {form['page']}\n\n")
            
            self.logger.info("✅ Crawler results saved to:")
            self.logger.info("   - reports/crawled_urls.txt")
            self.logger.info("   - reports/crawled_forms.txt")
        except Exception as e:
            self.logger.error(f"Failed to save crawler results: {e}")

        self.logger.info(f"✅ Crawler finished. Found {len(urls)} URLs and {len(forms)} forms.")
        return urls, forms

    # ----------------------------------------------------------------------
    # Generic scan on crawled targets
    # ----------------------------------------------------------------------
    def run_scans_on_crawled_targets(self, urls, forms):
        """
        Run all applicable scanners on the discovered targets.
        """
        self.logger.info("🔍 Running vulnerability scans on discovered targets...")
        all_targets = urls + forms  # URLs are strings, forms are dicts

        # SQL Injection
        self.logger.info("🚀 Running SQL Injection scanner...")
        self.sql_scanner.test_targets(all_targets)
        for finding in self.sql_scanner.vulnerabilities_found:
            # finding keys: type, url, parameter, payload, severity
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )

        # XSS
        self.logger.info("🚀 Running XSS scanner...")
        self.xss_scanner.test_targets(all_targets)
        for finding in self.xss_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )

        # Command Injection
        self.logger.info("🚀 Running Command Injection scanner...")
        self.ci_scanner.test_targets(all_targets)
        for finding in self.ci_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )

        # File Inclusion
        self.logger.info("🚀 Running File Inclusion scanner...")
        self.fi_scanner.test_targets(all_targets)
        for finding in self.fi_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )

        # Path Traversal
        self.logger.info("🚀 Running Path Traversal scanner...")
        self.pt_scanner.test_targets(all_targets)
        for finding in self.pt_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )

        # Security Headers (only on URLs)
        self.logger.info("🚀 Running Security Headers scanner...")
        for url in urls:
            self.headers_scanner.test_url(url)
        for finding in self.headers_scanner.vulnerabilities_found:
            # finding keys: type, header, url, severity, etc.
            self.reporter.add_finding(
                finding['type'],
                finding.get('header', ''),
                finding['url'],
                finding['severity']
            )

        # CSRF (only on forms)
        self.logger.info("🚀 Running CSRF scanner...")
        for form in forms:
            self.csrf_scanner.test_form(form)
        for finding in self.csrf_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"Method: {finding.get('method', '')}",
                finding['url'],
                finding['severity']
            )

        # Brute Force (only on login forms)
        self.logger.info("🚀 Running Brute Force scanner...")
        for form in forms:
            self.bf_scanner.test_form(form)
        for finding in self.bf_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"Username: {finding.get('username', '')} Password: {finding.get('password', '')}",
                finding['url'],
                finding['severity']
            )

        # Open Redirect (URLs and forms)
        self.logger.info("🚀 Running Open Redirect scanner...")
        self.or_scanner.test_targets(all_targets)
        for finding in self.or_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"Parameter: {finding.get('parameter', '')} -> {finding.get('redirects_to', '')}",
                finding['url'],
                finding['severity']
            )

        # Directory Listing (only on URLs)
        self.logger.info("🚀 Running Directory Listing scanner...")
        for url in urls:
            self.dl_scanner.test_url(url)
        for finding in self.dl_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                finding.get('indicator', ''),
                finding['url'],
                finding['severity']
            )

        self.logger.info("✅ All scans on crawled targets completed.")
        return True

    def run_crawl_and_scan(self):
        """Crawl the target and then scan all discovered URLs and forms."""
        urls, forms = self.run_crawler()
        self.run_scans_on_crawled_targets(urls, forms)
        self.generate_reports()

    # ----------------------------------------------------------------------
    # Legacy DVWA-specific scan methods (maintained for backward compatibility)
    # ----------------------------------------------------------------------
    def _get_dvwa_targets(self):
        """Return a list of hardcoded DVWA URLs and forms for legacy scans."""
        # This is a simple fallback; the new --crawl-and-scan is preferred.
        base = self.target_url
        urls = [
            base + "/vulnerabilities/sqli/",
            base + "/vulnerabilities/xss_r/",
            base + "/vulnerabilities/exec/",
            base + "/vulnerabilities/fi/",
            base + "/vulnerabilities/csrf/",
            base + "/vulnerabilities/brute/",
            base + "/security.php",
            base + "/setup.php",
        ]
        # Forms are not easily hardcoded, so we'll rely on the scanners' ability
        # to extract forms from these pages if needed. But for simplicity,
        # we'll just return URLs and let the scanners handle form extraction.
        return urls, []

    def run_sql_injection_scan(self):
        """Run SQL injection vulnerability scan (legacy)"""
        self.logger.info("🚀 Starting SQL injection scan...")
        urls, _ = self._get_dvwa_targets()
        
        # First, test each URL (if it has parameters)
        for url in urls:
            self.sql_scanner.test_url(url)
        
        # Also, try to extract forms from each page and test them
        for url in urls:
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = []
                    for form in soup.find_all('form'):
                        method = form.get('method', 'get').upper()
                        action = form.get('action', '')
                        form_url = urljoin(url, action) if action else url
                        inputs = []
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name:
                                inputs.append({'name': name, 'type': inp.get('type', 'text'), 'value': inp.get('value', '')})
                        forms.append({'url': form_url, 'method': method, 'inputs': inputs, 'page': url})
                    self.sql_scanner.test_targets(forms)
            except Exception:
                pass

        for finding in self.sql_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ SQL injection scan completed.")
        return len(self.sql_scanner.vulnerabilities_found) > 0

    def run_xss_scan(self):
        """Run XSS vulnerability scan (legacy)"""
        self.logger.info("🚀 Starting XSS scan...")
        urls, _ = self._get_dvwa_targets()
        
        for url in urls:
            self.xss_scanner.test_url(url)
            # Extract forms and test
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = []
                    for form in soup.find_all('form'):
                        method = form.get('method', 'get').upper()
                        action = form.get('action', '')
                        form_url = urljoin(url, action) if action else url
                        inputs = []
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name:
                                inputs.append({'name': name, 'type': inp.get('type', 'text'), 'value': inp.get('value', '')})
                        forms.append({'url': form_url, 'method': method, 'inputs': inputs, 'page': url})
                    self.xss_scanner.test_targets(forms)
            except Exception:
                pass

        for finding in self.xss_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ XSS scan completed.")
        return len(self.xss_scanner.vulnerabilities_found) > 0

    def run_command_injection_scan(self):
        """Run Command Injection scan (legacy)"""
        self.logger.info("🚀 Starting Command Injection scan...")
        urls, _ = self._get_dvwa_targets()
        
        for url in urls:
            self.ci_scanner.test_url(url)
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = []
                    for form in soup.find_all('form'):
                        method = form.get('method', 'get').upper()
                        action = form.get('action', '')
                        form_url = urljoin(url, action) if action else url
                        inputs = []
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name:
                                inputs.append({'name': name, 'type': inp.get('type', 'text'), 'value': inp.get('value', '')})
                        forms.append({'url': form_url, 'method': method, 'inputs': inputs, 'page': url})
                    self.ci_scanner.test_targets(forms)
            except Exception:
                pass

        for finding in self.ci_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ Command Injection scan completed.")
        return len(self.ci_scanner.vulnerabilities_found) > 0

    def run_file_inclusion_scan(self):
        """Run File Inclusion scan (legacy)"""
        self.logger.info("🚀 Starting File Inclusion scan...")
        urls, _ = self._get_dvwa_targets()
        
        for url in urls:
            self.fi_scanner.test_url(url)
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = []
                    for form in soup.find_all('form'):
                        method = form.get('method', 'get').upper()
                        action = form.get('action', '')
                        form_url = urljoin(url, action) if action else url
                        inputs = []
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name:
                                inputs.append({'name': name, 'type': inp.get('type', 'text'), 'value': inp.get('value', '')})
                        forms.append({'url': form_url, 'method': method, 'inputs': inputs, 'page': url})
                    self.fi_scanner.test_targets(forms)
            except Exception:
                pass

        for finding in self.fi_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"{finding.get('parameter', '')}={finding.get('payload', '')}",
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ File Inclusion scan completed.")
        return len(self.fi_scanner.vulnerabilities_found) > 0

    def run_path_traversal_scan(self):
        urls, _ = self._get_dvwa_targets()
        self.pt_scanner.test_targets(urls)
        for finding in self.pt_scanner.vulnerabilities_found:
            self.reporter.add_finding(**finding)
        self.logger.info("✅ Path Traversal scan completed.")
        return len(self.pt_scanner.vulnerabilities_found) > 0

    def run_headers_scan(self):
        """Run Security Headers scan (legacy)"""
        self.logger.info("🚀 Starting Security Headers scan...")
        urls, _ = self._get_dvwa_targets()
        
        for url in urls:
            self.headers_scanner.test_url(url)
        
        for finding in self.headers_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                finding.get('header', ''),
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ Security Headers scan completed.")
        return len(self.headers_scanner.vulnerabilities_found) > 0

    def run_csrf_scan(self):
        """Run CSRF scan (legacy)"""
        self.logger.info("🚀 Starting CSRF scan...")
        urls, _ = self._get_dvwa_targets()
        
        # Extract forms from each page
        for url in urls:
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for form in soup.find_all('form'):
                        method = form.get('method', 'get').upper()
                        action = form.get('action', '')
                        form_url = urljoin(url, action) if action else url
                        inputs = []
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name:
                                inputs.append({'name': name, 'type': inp.get('type', 'text'), 'value': inp.get('value', '')})
                        form_dict = {'url': form_url, 'method': method, 'inputs': inputs, 'page': url}
                        self.csrf_scanner.test_form(form_dict)
            except Exception:
                pass
        
        for finding in self.csrf_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"Method: {finding.get('method', '')}",
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ CSRF scan completed.")
        return len(self.csrf_scanner.vulnerabilities_found) > 0

    def run_bruteforce_scan(self):
        """Run Brute Force scan (legacy)"""
        self.logger.info("🚀 Starting Brute Force scan...")
        urls, _ = self._get_dvwa_targets()
        
        # Focus on login pages: /login.php and /userinfo.php
        login_urls = [u for u in urls if 'login' in u or 'user' in u]
        for url in login_urls:
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for form in soup.find_all('form'):
                        method = form.get('method', 'get').upper()
                        action = form.get('action', '')
                        form_url = urljoin(url, action) if action else url
                        inputs = []
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name:
                                inputs.append({'name': name, 'type': inp.get('type', 'text'), 'value': inp.get('value', '')})
                        form_dict = {'url': form_url, 'method': method, 'inputs': inputs, 'page': url}
                        self.bf_scanner.test_form(form_dict)
            except Exception:
                pass
        
        for finding in self.bf_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"Username: {finding.get('username', '')} Password: {finding.get('password', '')}",
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ Brute Force scan completed.")
        return len(self.bf_scanner.vulnerabilities_found) > 0

    def run_open_redirect_scan(self):
        """Run Open Redirect scan (legacy)"""
        self.logger.info("🚀 Starting Open Redirect scan...")
        urls, _ = self._get_dvwa_targets()
        
        for url in urls:
            self.or_scanner.test_url(url)
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for form in soup.find_all('form'):
                        method = form.get('method', 'get').upper()
                        action = form.get('action', '')
                        form_url = urljoin(url, action) if action else url
                        inputs = []
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name:
                                inputs.append({'name': name, 'type': inp.get('type', 'text'), 'value': inp.get('value', '')})
                        form_dict = {'url': form_url, 'method': method, 'inputs': inputs, 'page': url}
                        self.or_scanner.test_form(form_dict)
            except Exception:
                pass
        
        for finding in self.or_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                f"Parameter: {finding.get('parameter', '')} -> {finding.get('redirects_to', '')}",
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ Open Redirect scan completed.")
        return len(self.or_scanner.vulnerabilities_found) > 0

    def run_directory_listing_scan(self):
        """Run Directory Listing scan (legacy)"""
        self.logger.info("🚀 Starting Directory Listing scan...")
        urls, _ = self._get_dvwa_targets()
        
        for url in urls:
            self.dl_scanner.test_url(url)
        
        for finding in self.dl_scanner.vulnerabilities_found:
            self.reporter.add_finding(
                finding['type'],
                finding.get('indicator', ''),
                finding['url'],
                finding['severity']
            )
        self.logger.info("✅ Directory Listing scan completed.")
        return len(self.dl_scanner.vulnerabilities_found) > 0

    # ----------------------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------------------
    def generate_reports(self):
        if not self.reporter.findings:
            self.logger.info("📝 No vulnerabilities found to report")
            return
        
        self.logger.info("📄 Generating scan reports...")
        html_report = self.reporter.generate_html_report()
        json_report = self.reporter.generate_json_report()
        summary = self.reporter.generate_text_summary()
        self.logger.info(summary)
        
        if html_report and json_report:
            self.logger.info("✅ Reports generated successfully!")
        else:
            self.logger.error("❌ Some reports failed to generate")

def main(args=None):
    """Main entry point for the scanner"""
    banner = """
    ╦   ╦ ╦╔═╗╔╗╔╔═╗╔╦╗╔═╗╦═╗
    ║   ║ ║╠═╣║║║╠═╣ ║ ╠═╣╠╦╝
    ╩   ╚═╝╩ ╩╝╚╝╩ ╩ ╩ ╩ ╩╩╚═
    Simple Web Vulnerability Scanner
    """
    print(banner)
    
    if args is None:
        parser = argparse.ArgumentParser(description='VulnScanr - Web Vulnerability Scanner')
        parser.add_argument('url', help='Target URL to scan (e.g., http://localhost)')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        parser.add_argument('--sql', action='store_true', help='Run SQL injection scan (legacy)')
        parser.add_argument('--xss', action='store_true', help='Run XSS scan (legacy)')
        parser.add_argument('--ci', action='store_true', help='Run Command Injection scan (legacy)')
        parser.add_argument('--fi', action='store_true', help='Run File Inclusion scan (legacy)')
        parser.add_argument('--pt', action='store_true', help='Run Path Traversal scan (legacy)')
        parser.add_argument('--headers', action='store_true', help='Run Security Headers scan (legacy)')
        parser.add_argument('--csrf', action='store_true', help='Run CSRF scan (legacy)')
        parser.add_argument('--bf', action='store_true', help='Run Brute Force scan (legacy)')
        parser.add_argument('--openredirect', action='store_true', help='Run Open Redirect scan (legacy)')
        parser.add_argument('--dirlisting', action='store_true', help='Run Directory Listing scan (legacy)')
        parser.add_argument('--crawl', action='store_true', help='Run web crawler only')
        parser.add_argument('--crawl-and-scan', action='store_true', help='Crawl and scan discovered targets (recommended)')
        parser.add_argument('--full', action='store_true', help='Run all legacy scans (use --crawl-and-scan instead)')
        
        args = parser.parse_args()
    # else args is already parsed from __main__
    
    scanner = VulnScanr(args.url, verbose=args.verbose)
    
    if not scanner.test_connection():
        scanner.logger.error("Cannot proceed without a valid connection to the target.")
        sys.exit(1)
    
    # New recommended mode
    if getattr(args, 'crawl_and_scan', False):
        scanner.run_crawl_and_scan()
    elif getattr(args, 'crawl', False):
        scanner.run_crawler()
    elif args.full:
        scanner.logger.info("🔍 Running FULL legacy security scan (may be limited)...")
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
        scanner.generate_reports()
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
        parser.print_help()

if __name__ == "__main__":
    main()