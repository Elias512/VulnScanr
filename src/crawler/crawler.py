"""
Web Crawler Module for VulnScanr
Discovers URLs, forms, and parameters on a target website.
"""
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from src.utils.logger import setup_logger

class WebCrawler:
    def __init__(self, session, base_url, max_pages=50, max_depth=3, verbose=False):
        """
        Initialize the crawler.
        
        :param session: requests Session object
        :param base_url: starting URL (e.g., http://example.com)
        :param max_pages: maximum number of pages to crawl
        :param max_depth: maximum link depth from start
        :param verbose: enable verbose logging
        """
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.logger = setup_logger(verbose)
        
        self.visited = set()          # URLs already crawled
        self.to_visit = []            # Queue of (url, depth)
        self.discovered_urls = set()  # All discovered URLs (for output)
        self.discovered_forms = []    # List of form details
    
    def normalize_url(self, url, base):
        """Convert relative URL to absolute and remove fragments."""
        full = urljoin(base, url)
        # Remove fragment
        parsed = urlparse(full)
        normalized = parsed._replace(fragment='').geturl()
        return normalized
    
    def is_same_domain(self, url):
        """Check if URL belongs to the same domain as base_url."""
        base_domain = urlparse(self.base_url).netloc
        target_domain = urlparse(url).netloc
        return target_domain == base_domain or target_domain == ''
    
    def extract_links(self, soup, base):
        """Extract all links from a BeautifulSoup object."""
        links = set()
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                full_url = self.normalize_url(href, base)
                if self.is_same_domain(full_url):
                    links.add(full_url)
        return links
    
    def extract_forms(self, soup, page_url):
        """Extract form details from a page."""
        forms = []
        for form in soup.find_all('form'):
            method = form.get('method', 'get').upper()
            action = form.get('action', '')
            if action:
                form_url = self.normalize_url(action, page_url)
            else:
                form_url = page_url  # submits to same page
            
            # Extract input fields
            inputs = []
            for inp in form.find_all('input'):
                name = inp.get('name')
                if name:
                    inp_type = inp.get('type', 'text')
                    inputs.append({
                        'name': name,
                        'type': inp_type,
                        'value': inp.get('value', '')
                    })
            # Also include textareas, selects if needed (optional)
            forms.append({
                'url': form_url,
                'method': method,
                'inputs': inputs,
                'page': page_url
            })
        return forms
    
    def crawl_page(self, url, depth):
        """Crawl a single page: fetch, parse, extract links and forms."""
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        
        self.logger.debug(f"Crawling: {url} (depth {depth})")
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return
            # Check content type (only parse HTML)
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links for further crawling
            links = self.extract_links(soup, url)
            new_links = links - self.visited
            for link in new_links:
                if link not in self.to_visit and len(self.visited) + len(self.to_visit) < self.max_pages:
                    self.to_visit.append((link, depth + 1))
            
            # Extract forms
            forms = self.extract_forms(soup, url)
            self.discovered_forms.extend(forms)
            
            # Record discovered URL
            self.discovered_urls.add(url)
            
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {str(e)}")
    
    def crawl(self):
        """
        Start crawling from base_url.
        Returns: (discovered_urls, discovered_forms)
        """
        self.logger.info(f"🌐 Starting crawl of {self.base_url} (max pages: {self.max_pages}, max depth: {self.max_depth})")
        self.visited = set()
        self.to_visit = [(self.base_url, 0)]
        self.discovered_urls = set()
        self.discovered_forms = []
        
        while self.to_visit and len(self.visited) < self.max_pages:
            url, depth = self.to_visit.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            self.crawl_page(url, depth)
        
        self.logger.info(f"✅ Crawl completed. Discovered {len(self.discovered_urls)} URLs and {len(self.discovered_forms)} forms.")
        return list(self.discovered_urls), self.discovered_forms
    
    def print_summary(self):
        """Print a summary of discovered items."""
        print(f"\n📋 Crawl Summary:")
        print(f"   Total URLs: {len(self.discovered_urls)}")
        print(f"   Total Forms: {len(self.discovered_forms)}")
        if self.discovered_forms:
            print(f"\n📝 Forms Found:")
            for i, form in enumerate(self.discovered_forms, 1):
                print(f"   {i}. {form['method']} {form['url']} (inputs: {len(form['inputs'])})")