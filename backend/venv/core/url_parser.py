"""
PhishRadar URL Parser - Advanced URL parsing and normalization
Extracts components and detects anomalies
"""

import re
import tldextract
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Optional, List, Tuple
from .utils import logger, timing_decorator, safe_execute, url_validator

class URLParser:
    """Advanced URL parsing with phishing detection features"""
    
    def __init__(self):
        self.tld_extractor = tldextract.TLDExtract(cache_dir='.tld_cache')
        logger.info("URLParser initialized")
    
    @timing_decorator
    def parse(self, url: str) -> Dict:
        """
        Comprehensive URL parsing and analysis
        Returns detailed breakdown of URL components
        """
        if not url_validator.is_valid_url(url):
            logger.warning(f"Invalid URL format: {url}")
            return self._empty_result(url, "Invalid URL format")
        
        try:
            # Normalize URL
            normalized_url = self._normalize_url(url)
            
            # Parse using urllib
            parsed = urlparse(normalized_url)
            
            # Extract TLD components
            tld_parts = self.tld_extractor(normalized_url)
            
            # Build comprehensive result
            result = {
                'original_url': url,
                'normalized_url': normalized_url,
                'scheme': parsed.scheme,
                'subdomain': tld_parts.subdomain,
                'domain': tld_parts.domain,
                'suffix': tld_parts.suffix,
                'registered_domain': tld_parts.registered_domain,
                'fqdn': tld_parts.fqdn,
                'port': parsed.port,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'params': parse_qs(parsed.query),
                'path_depth': self._calculate_path_depth(parsed.path),
                'subdomain_count': len(tld_parts.subdomain.split('.')) if tld_parts.subdomain else 0,
                'suspicious_indicators': self._detect_suspicious_indicators(parsed, tld_parts),
                'url_length': len(url),
                'domain_length': len(tld_parts.domain),
                'entropy': self._calculate_url_entropy(url),
                'has_unicode': self._has_unicode(url),
                'encoded_chars': self._count_encoded_chars(url),
                'special_chars': self._count_special_chars(url),
                'is_valid': True,
                'error': None
            }
            
            logger.debug(f"Successfully parsed: {url}")
            return result
            
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}", exc_info=True)
            return self._empty_result(url, str(e))
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent parsing"""
        url = url.strip()
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Decode percent-encoded characters
        url = unquote(url)
        
        # Convert to lowercase (except path)
        parsed = urlparse(url)
        normalized = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower()
        )
        
        return normalized.geturl()
    
    def _calculate_path_depth(self, path: str) -> int:
        """Calculate URL path depth"""
        if not path or path == '/':
            return 0
        return len([p for p in path.split('/') if p])
    
    def _detect_suspicious_indicators(self, parsed, tld_parts) -> Dict[str, bool]:
        """Detect various suspicious URL indicators"""
        url = parsed.geturl()
        
        indicators = {
            'has_ip_in_domain': self._has_ip_address(parsed.netloc),
            'excessive_dots': parsed.netloc.count('.') > 4,
            'excessive_hyphens': parsed.netloc.count('-') > 3,
            'has_at_symbol': '@' in url,
            'suspicious_port': self._has_suspicious_port(parsed.port),
            'double_extension': self._has_double_extension(parsed.path),
            'url_shortener': self._is_url_shortener(tld_parts.registered_domain),
            'suspicious_keywords': self._has_suspicious_keywords(url),
            'mixed_charset': self._has_mixed_charset(url),
            'suspicious_tld': self._is_suspicious_tld(tld_parts.suffix),
            'long_subdomain': len(tld_parts.subdomain) > 30 if tld_parts.subdomain else False,
            'numeric_domain': self._has_excessive_numbers(tld_parts.domain),
            'typosquatting_pattern': self._detect_typosquatting(tld_parts.domain)
        }
        
        return indicators
    
    def _has_ip_address(self, netloc: str) -> bool:
        """Check if netloc contains IP address"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, netloc))
    
    def _has_suspicious_port(self, port: Optional[int]) -> bool:
        """Check for suspicious port numbers"""
        suspicious_ports = {8080, 8888, 3000, 4444, 5555, 8000, 8443}
        return port in suspicious_ports if port else False
    
    def _has_double_extension(self, path: str) -> bool:
        """Detect double file extensions (e.g., .pdf.exe)"""
        pattern = r'\.\w{2,4}\.\w{2,4}$'
        return bool(re.search(pattern, path))
    
    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a URL shortener"""
        shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'buff.ly', 'adf.ly', 'bit.do', 'short.link', 'tiny.cc'
        }
        return domain in shorteners
    
    def _has_suspicious_keywords(self, url: str) -> bool:
        """Detect suspicious keywords in URL"""
        keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'confirm', 'banking', 'paypal', 'ebay', 'amazon', 'apple',
            'microsoft', 'google', 'facebook', 'twitter', 'suspended',
            'locked', 'unusual', 'activity', 'click', 'here'
        ]
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in keywords)
    
    def _has_mixed_charset(self, url: str) -> bool:
        """Detect mixed character sets (potential homograph attack)"""
        # Check for Cyrillic, Greek, or other non-ASCII in domain
        try:
            url.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True
    
    def _is_suspicious_tld(self, tld: str) -> bool:
        """Check if TLD is commonly used in phishing"""
        suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
            'click', 'link', 'bid', 'download', 'stream', 'racing'
        }
        return tld.lower() in suspicious_tlds
    
    def _has_excessive_numbers(self, domain: str) -> bool:
        """Check if domain has excessive numbers"""
        if not domain:
            return False
        digit_ratio = sum(c.isdigit() for c in domain) / len(domain)
        return digit_ratio > 0.3
    
    def _detect_typosquatting(self, domain: str) -> bool:
        """Detect potential typosquatting patterns"""
        # Common character substitutions
        substitutions = {
            'o': '0', 'i': '1', 'l': '1', 's': '5', 
            'e': '3', 'a': '4', 't': '7'
        }
        
        for char, substitute in substitutions.items():
            if substitute in domain and char not in domain:
                return True
        
        return False
    
    def _calculate_url_entropy(self, url: str) -> float:
        """Calculate Shannon entropy of URL"""
        if not url:
            return 0.0
        
        import math
        entropy = 0
        length = len(url)
        
        # Count character frequencies
        freq = {}
        for char in url:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _has_unicode(self, url: str) -> bool:
        """Check for Unicode characters"""
        try:
            url.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True
    
    def _count_encoded_chars(self, url: str) -> int:
        """Count percent-encoded characters"""
        return len(re.findall(r'%[0-9A-Fa-f]{2}', url))
    
    def _count_special_chars(self, url: str) -> int:
        """Count special characters"""
        special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
        return sum(1 for char in url if char in special_chars)
    
    def _empty_result(self, url: str, error: str) -> Dict:
        """Return empty result structure for invalid URLs"""
        return {
            'original_url': url,
            'normalized_url': None,
            'is_valid': False,
            'error': error,
            'scheme': None,
            'subdomain': None,
            'domain': None,
            'suffix': None,
            'registered_domain': None,
            'suspicious_indicators': {}
        }
    
    def extract_domains_from_text(self, text: str) -> List[str]:
        """Extract all URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def compare_domains(self, domain1: str, domain2: str) -> Dict:
        """Compare two domains for similarity"""
        from .utils import security_utils
        
        similarity = security_utils.calculate_similarity(domain1, domain2)
        distance = security_utils.levenshtein_distance(domain1, domain2)
        
        return {
            'domain1': domain1,
            'domain2': domain2,
            'similarity_score': similarity,
            'edit_distance': distance,
            'likely_typosquatting': similarity > 0.7 and distance > 0
        }