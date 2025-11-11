"""
Logging utilities for VulnScanr
"""
import logging
import colorama
from colorama import Fore, Style

colorama.init()

def setup_logger(verbose=False):
    """Set up colored console logging"""
    logger = logging.getLogger('VulnScanr')
    
    # Clear any existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()
    
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    # Create console handler with colored formatter
    console_handler = logging.StreamHandler()
    
    class ColoredFormatter(logging.Formatter):
        """Custom formatter for colored output"""
        def format(self, record):
            message = super().format(record)
            if record.levelno == logging.ERROR:
                return f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}"
            elif record.levelno == logging.WARNING:
                return f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}"
            elif record.levelno == logging.INFO:
                return f"{Fore.CYAN}[INFO] {message}{Style.RESET_ALL}"
            elif record.levelno == logging.DEBUG:
                return f"{Fore.GREEN}[DEBUG] {message}{Style.RESET_ALL}"
            elif record.levelno == logging.CRITICAL:
                return f"{Fore.RED}{Style.BRIGHT}[CRITICAL] {message}{Style.RESET_ALL}"
            return f"[INFO] {message}"
    
    formatter = ColoredFormatter('%(message)s')
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    # Prevent propagation to root logger (which causes duplicates)
    logger.propagate = False
    
    return logger
