"""
PhishRadar Core Package
Advanced phishing detection system

This package provides comprehensive URL analysis through multiple security layers:
- URL pattern analysis and parsing
- WHOIS and domain age verification
- SSL/TLS certificate validation
- Brand impersonation detection
- TLD reputation analysis
- DNS and IP intelligence
- Multi-factor risk scoring
"""

__version__ = '1.0.0'
__author__ = 'PhishRadar Security Team'
__license__ = 'MIT'

# Import main components for easy access
from .analyzer import PhishRadarAnalyzer
from .url_parser import URLParser
from .whois_lookup import WHOISLookup
from .ssl_checker import SSLChecker
from .brand_detector import BrandDetector
from .tld_checker import TLDChecker
from .dns_info import DNSInfo
from .score_engine import ScoreEngine
from .utils import (
    logger,
    url_validator,
    data_manager,
    security_utils,
    report_generator
)

# Define public API
__all__ = [
    # Main analyzer
    'PhishRadarAnalyzer',
    
    # Analysis modules
    'URLParser',
    'WHOISLookup',
    'SSLChecker',
    'BrandDetector',
    'TLDChecker',
    'DNSInfo',
    'ScoreEngine',
    
    # Utilities
    'logger',
    'setup_logging',
    'url_validator',
    'data_manager',
    'security_utils',
    'report_generator',
]

# Package metadata
PACKAGE_INFO = {
    'name': 'PhishRadar',
    'version': __version__,
    'description': 'Advanced URL phishing detection system',
    'author': __author__,
    'license': __license__,
    'modules': [
        'url_parser',
        'whois_lookup',
        'ssl_checker',
        'brand_detector',
        'tld_checker',
        'dns_info',
        'score_engine',
        'analyzer'
    ]
}

def get_version():
    """Get package version"""
    return __version__

def get_info():
    """Get package information"""
    return PACKAGE_INFO.copy()

# Initialize logging on package import
logger.info(f"PhishRadar v{__version__} initialized")
logger.info(f"Available modules: {', '.join(PACKAGE_INFO['modules'])}")