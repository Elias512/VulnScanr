# src/__main__.py
"""
Main entry point for VulnScanr package
"""
import argparse
import sys
from .scanner import main as scanner_main

def main():
    parser = argparse.ArgumentParser(description='VulnScanr - Web Vulnerability Scanner')
    parser.add_argument('url', nargs='?', help='Target URL to scan (e.g., http://localhost)')
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
    parser.add_argument('--gui', action='store_true', help='Launch GUI application')
    
    args = parser.parse_args()
    
    if args.gui:
        # Launch GUI
        from .gui.main_window import main as gui_main
        gui_main()
    elif args.url:
        # Run command line scan – pass the whole args namespace to scanner_main
        # We need to modify scanner_main to accept args, which we already did.
        scanner_main(args)
    else:
        # No arguments - show help
        parser.print_help()

if __name__ == "__main__":
    main()