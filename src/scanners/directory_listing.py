"""
Directory Listing Scanner Module
Checks for exposed directory listings on web servers.
"""
from urllib.parse import urljoin
from src.utils.logger import setup_logger

class DirectoryListingScanner:
    def __init__(self, session, target_url, verbose=False):
        self.session = session
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.vulnerabilities_found = []

    def check_directory(self, directory_path):
        """
        Request a directory and check for directory listing indicators.
        """
        url = urljoin(self.target_url, directory_path)
        try:
            response = self.session.get(url, timeout=10)

            # Common directory listing indicators
            listing_indicators = [
                "Index of /",
                "Directory listing for",
                "<title>Index of",
                "Parent Directory</a>",
                "[To Parent Directory]",
                "Last modified</a>",
                "Name</a>",
                "Size</a>",
                "Description</a>",
                "..</a>",  # Parent directory link
            ]

            # Also check if response content-type is text/html and contains file listing patterns
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type:
                for indicator in listing_indicators:
                    if indicator in response.text:
                        self.logger.warning(f"📁 Directory listing exposed at {url}")
                        self.logger.debug(f"   Indicator: {indicator}")
                        self.vulnerabilities_found.append({
                            "type": "Directory Listing",
                            "url": url,
                            "indicator": indicator,
                            "severity": "Low"
                        })
                        return True

            return False
        except Exception as e:
            self.logger.debug(f"Error checking {url}: {str(e)}")
            return False

    def scan_common_directories(self):
        """
        Scan a list of common directories that might have listing enabled.
        """
        self.logger.info("📂 Scanning for exposed directory listings...")
        self.vulnerabilities_found = []

        common_dirs = [
            'images', 'img', 'css', 'js', 'uploads', 'files', 'downloads',
            'backup', 'backups', 'old', 'temp', 'tmp', 'logs', 'log',
            'includes', 'inc', 'pages', 'assets', 'static', 'public',
            'admin', 'user', 'data', 'database', 'sql', 'sqlite',
            'phpmyadmin', 'pma', 'mysql', 'db', 'database',
            'wp-content', 'wp-includes', 'themes', 'plugins', 'uploads',
            'vendor', 'node_modules', 'bower_components', 'composer',
            'git', '.git', 'svn', '.svn', 'env', '.env',
            'config', 'configuration', 'settings',
            'test', 'tests', 'testing', 'demo', 'examples',
            'doc', 'docs', 'documentation', 'manual',
            'cgi-bin', 'cgi', 'cgi-bin/',
            'server-status', 'server-info', 'status',
        ]

        for directory in common_dirs:
            # Add trailing slash if missing
            if not directory.endswith('/'):
                directory += '/'
            self.check_directory(directory)

        if self.vulnerabilities_found:
            self.logger.warning(f"🎯 Found {len(self.vulnerabilities_found)} exposed directory listings!")
            return True
        else:
            self.logger.info("✅ No directory listings detected")
            return False