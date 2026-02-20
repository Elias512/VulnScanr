"""
Base class for all vulnerability scanners.
Provides common methods for testing URLs and forms.
"""
from abc import ABC, abstractmethod
import copy
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class BaseScanner(ABC):
    def __init__(self, session, logger, verbose=False):
        self.session = session
        self.logger = logger
        self.verbose = verbose
        self.vulnerabilities_found = []

    @abstractmethod
    def test_url(self, url, method='GET'):
        """
        Test a single URL (including query parameters) for vulnerabilities.
        Should return True if vulnerable, False otherwise.
        """
        pass

    @abstractmethod
    def test_form(self, form):
        """
        Test a single form (dict with keys: url, method, inputs) for vulnerabilities.
        Should return True if vulnerable, False otherwise.
        """
        pass

    def test_targets(self, targets):
        """
        Test a list of targets (mix of URLs and form dicts).
        Returns list of vulnerabilities found.
        """
        for target in targets:
            if isinstance(target, str):
                self.test_url(target)
            elif isinstance(target, dict) and 'method' in target:
                self.test_form(target)
        return self.vulnerabilities_found

    def _inject_parameter(self, url, param, payload):
        """Inject payload into a URL parameter and return new URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}
        if param not in params:
            return None
        new_params = copy.deepcopy(params)
        new_params[param] = [payload]
        new_query = urlencode(new_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _build_form_data(self, form, target_param, payload):
        """
        Build data dictionary for form submission, injecting payload into target_param.
        """
        inputs = form.get('inputs', [])
        data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                if name == target_param:
                    data[name] = payload
                else:
                    data[name] = inp.get('value', '')
        return data