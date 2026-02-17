"""
Configuration settings for VulnScanr
"""

# Scanner configuration
SCANNER_CONFIG = {
    'timeout': 10,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'max_redirects': 5,
    'threads': 5
}

# HTTP status codes to consider as potential vulnerabilities
SUSPICIOUS_STATUS_CODES = [500, 403, 401]

# Common file extensions to ignore during crawling
IGNORED_EXTENSIONS = ['.jpg', '.png', '.css', '.js', '.pdf', '.doc', '.docx']