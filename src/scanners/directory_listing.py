"""
Generic Directory Listing Scanner
"""
from urllib.parse import urljoin
from src.scanners.base import BaseScanner

class DirectoryListingScanner(BaseScanner):
    def __init__(self, session, logger, verbose=False):
        super().__init__(session, logger, verbose)
        self.common_dirs = [
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
        self.listing_indicators = [
            "Index of /",
            "Directory listing for",
            "<title>Index of",
            "Parent Directory</a>",
            "[To Parent Directory]",
            "Last modified</a>",
            "Name</a>",
            "Size</a>",
            "Description</a>",
            "..</a>",
        ]

    def test_url(self, url, method='GET'):
        # Directory listing is per-directory; we'll check each common dir
        # But since this scanner is called with a target list, we need to adapt.
        # For generic scanning, we'll check common directories relative to base.
        # However, the base scanner's test_url is called with each discovered URL.
        # So we'll just check if the current URL is a directory and shows listing.
        self.logger.debug(f"Testing URL for directory listing: {url}")
        try:
            response = self.session.get(url, timeout=10)
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type:
                for indicator in self.listing_indicators:
                    if indicator in response.text:
                        self.logger.warning(f"📁 Directory listing exposed at {url}")
                        self.vulnerabilities_found.append({
                            "type": "Directory Listing",
                            "url": url,
                            "severity": "Low"
                        })
                        return True
        except Exception:
            pass
        return False

    def test_form(self, form):
        # Forms not relevant
        return False