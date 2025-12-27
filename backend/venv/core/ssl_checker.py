"""
PhishRadar SSL Checker - SSL/TLS certificate analysis
Validates certificates and detects suspicious configurations
Handles both HTTP and HTTPS URLs with intelligent detection
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .utils import logger, timing_decorator, safe_execute

class SSLChecker:
    """SSL/TLS certificate analysis and validation"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.cache = {}
        logger.info("SSLChecker initialized")
    
    @timing_decorator
    def check(self, url: str, port: int = None) -> Dict:
        """
        Comprehensive SSL certificate check with HTTP/HTTPS detection
        Args:
            url: Full URL or domain (with or without scheme)
            port: Optional port override
        Returns:
            Dictionary with certificate details and security assessment
        """
        # Parse and normalize URL
        parsed_url = self._parse_url(url)
        domain = parsed_url['domain']
        scheme = parsed_url['scheme']
        detected_port = port or parsed_url['port']
        
        cache_key = f"{domain}:{detected_port}:{scheme}"
        if cache_key in self.cache:
            logger.debug(f"Using cached SSL data for {domain}")
            return self.cache[cache_key]
        
        # Check if HTTP (no SSL)
        if scheme == 'http':
            logger.info(f"{domain} is HTTP - no SSL certificate")
            return self._http_result(domain, url)
        
        # HTTPS - perform SSL check
        try:
            logger.info(f"Checking SSL certificate for {domain}:{detected_port} (HTTPS)")
            
            # Get certificate
            cert_pem, cert_dict = self._get_certificate(domain, detected_port)
            
            if not cert_pem:
                return self._error_result(domain, url, "Failed to retrieve certificate")
            
            # Parse certificate
            cert_obj = self._parse_certificate(cert_pem)
            
            # Analyze certificate
            result = self._analyze_certificate(domain, url, cert_dict, cert_obj)
            
            # Cache result
            self.cache[cache_key] = result
            
            return result
            
        except ssl.SSLError as e:
            logger.warning(f"SSL error for {domain}: {e}")
            return self._error_result(domain, url, f"SSL Error: {str(e)}")
        except socket.timeout:
            logger.warning(f"Timeout connecting to {domain}")
            return self._error_result(domain, url, "Connection timeout")
        except socket.gaierror as e:
            logger.warning(f"DNS resolution failed for {domain}: {e}")
            return self._error_result(domain, url, f"DNS Error: {str(e)}")
        except ConnectionRefusedError:
            logger.warning(f"Connection refused for {domain}:{detected_port}")
            return self._error_result(domain, url, "Connection refused")
        except Exception as e:
            logger.error(f"Unexpected error checking SSL for {domain}: {e}")
            return self._error_result(domain, url, str(e))
    
    def _parse_url(self, url: str) -> Dict:
        """
        Parse URL and extract domain, scheme, and port
        Handles URLs with or without scheme
        """
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            # Try HTTPS first (most common for legitimate sites)
            url = 'https://' + url
        
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme or 'https'
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Remove port from domain if present
            if ':' in domain:
                domain, port_str = domain.split(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443 if scheme == 'https' else 80
            else:
                port = 443 if scheme == 'https' else 80
            
            # Clean domain
            domain = domain.strip().lower()
            
            return {
                'domain': domain,
                'scheme': scheme,
                'port': port,
                'original_url': url
            }
        except Exception as e:
            logger.error(f"Failed to parse URL {url}: {e}")
            # Fallback
            domain = url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            return {
                'domain': domain,
                'scheme': 'https',
                'port': 443,
                'original_url': url
            }
    
    def _get_certificate(self, domain: str, port: int) -> Tuple[Optional[bytes], Optional[Dict]]:
        """Retrieve SSL certificate from domain"""
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate in both formats
                cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                
                return cert_der, cert_dict
    
    def _parse_certificate(self, cert_der: bytes):
        """Parse DER certificate to x509 object"""
        try:
            return x509.load_der_x509_certificate(cert_der, default_backend())
        except Exception as e:
            logger.error(f"Failed to parse certificate: {e}")
            return None
    
    def _analyze_certificate(self, domain: str, url: str, cert_dict: Dict, cert_obj) -> Dict:
        """Analyze certificate for security issues"""
        
        # Extract basic info
        issuer = self._extract_issuer(cert_dict)
        subject = self._extract_subject(cert_dict)
        
        # Extract dates
        not_before = cert_dict.get('notBefore')
        not_after = cert_dict.get('notAfter')
        
        valid_from = self._parse_ssl_date(not_before)
        valid_until = self._parse_ssl_date(not_after)
        
        # Calculate validity
        days_remaining = self._calculate_days_remaining(valid_until)
        cert_age_days = self._calculate_cert_age(valid_from)
        
        # Extract SANs (Subject Alternative Names)
        san_list = self._extract_san(cert_dict)
        
        # Check certificate type and issuer
        is_self_signed = self._is_self_signed(issuer, subject)
        is_free_cert = self._is_free_certificate(issuer)
        
        # Domain validation
        domain_matches = self._validate_domain(domain, subject.get('commonName'), san_list)
        
        # Assess risk
        risk_indicators = self._assess_ssl_risk(
            is_self_signed, is_free_cert, days_remaining, 
            cert_age_days, domain_matches
        )
        
        result = {
            'url': url,
            'domain': domain,
            'scheme': 'https',
            'protocol': 'HTTPS',
            'success': True,
            'has_ssl': True,
            'ssl_enabled': True,
            'issuer': issuer,
            'issuer_organization': issuer.get('organizationName', 'Unknown'),
            'issuer_common_name': issuer.get('commonName', 'Unknown'),
            'subject': subject,
            'subject_common_name': subject.get('commonName', 'Unknown'),
            'valid_from': valid_from.isoformat() if valid_from else None,
            'valid_until': valid_until.isoformat() if valid_until else None,
            'days_remaining': days_remaining,
            'cert_age_days': cert_age_days,
            'is_expired': days_remaining is not None and days_remaining < 0,
            'expires_soon': days_remaining is not None and 0 <= days_remaining < 30,
            'san_list': san_list,
            'san_count': len(san_list),
            'is_self_signed': is_self_signed,
            'is_free_cert': is_free_cert,
            'domain_matches': domain_matches,
            'signature_algorithm': self._get_signature_algorithm(cert_obj),
            'serial_number': cert_dict.get('serialNumber'),
            'version': cert_dict.get('version'),
            'risk_indicators': risk_indicators,
            'risk_score': self._calculate_ssl_risk_score(risk_indicators),
            'certificate_chain_valid': True  # Validated by ssl.create_default_context()
        }
        
        logger.debug(f"SSL analyzed for {domain}: scheme=HTTPS, days_remaining={days_remaining}, matches={domain_matches}")
        return result
    
    def _extract_issuer(self, cert_dict: Dict) -> Dict:
        """Extract issuer information"""
        issuer = cert_dict.get('issuer', ())
        return {key: value for item in issuer for key, value in [item]}
    
    def _extract_subject(self, cert_dict: Dict) -> Dict:
        """Extract subject information"""
        subject = cert_dict.get('subject', ())
        return {key: value for item in subject for key, value in [item]}
    
    def _extract_san(self, cert_dict: Dict) -> list:
        """Extract Subject Alternative Names"""
        san = cert_dict.get('subjectAltName', ())
        return [name for type, name in san if type == 'DNS']
    
    def _parse_ssl_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse SSL date string to datetime"""
        if not date_str:
            return None
        
        try:
            return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
        except Exception:
            return None
    
    def _calculate_days_remaining(self, valid_until: Optional[datetime]) -> Optional[int]:
        """Calculate days until certificate expires"""
        if not valid_until:
            return None
        
        delta = valid_until - datetime.now()
        return delta.days
    
    def _calculate_cert_age(self, valid_from: Optional[datetime]) -> Optional[int]:
        """Calculate certificate age in days"""
        if not valid_from:
            return None
        
        delta = datetime.now() - valid_from
        return delta.days
    
    def _is_self_signed(self, issuer: Dict, subject: Dict) -> bool:
        """Check if certificate is self-signed"""
        return issuer.get('commonName') == subject.get('commonName')
    
    def _is_free_certificate(self, issuer: Dict) -> bool:
        """Check if certificate is from free CA"""
        free_cas = [
            "Let's Encrypt",
            "ZeroSSL",
            "Buypass",
            "CloudFlare",
            "Google Trust Services"
        ]
        
        issuer_cn = issuer.get('commonName', '')
        issuer_org = issuer.get('organizationName', '')
        
        return any(
            ca.lower() in issuer_cn.lower() or ca.lower() in issuer_org.lower()
            for ca in free_cas
        )
    
    def _validate_domain(self, domain: str, cn: Optional[str], san_list: list) -> bool:
        """Validate if certificate matches domain"""
        domain = domain.lower()
        
        # Check Common Name
        if cn and self._match_domain(domain, cn.lower()):
            return True
        
        # Check SANs
        for san in san_list:
            if self._match_domain(domain, san.lower()):
                return True
        
        return False
    
    def _match_domain(self, domain: str, cert_domain: str) -> bool:
        """Match domain against certificate domain (supports wildcards)"""
        if cert_domain == domain:
            return True
        
        # Wildcard support
        if cert_domain.startswith('*.'):
            wildcard_domain = cert_domain[2:]
            if domain.endswith(wildcard_domain):
                # Check it's a direct subdomain
                prefix = domain[:-len(wildcard_domain)]
                return '.' not in prefix.rstrip('.')
        
        return False
    
    def _get_signature_algorithm(self, cert_obj) -> Optional[str]:
        """Extract signature algorithm"""
        try:
            if cert_obj:
                return cert_obj.signature_algorithm_oid._name
        except Exception:
            pass
        return None
    
    def _assess_ssl_risk(
        self,
        is_self_signed: bool,
        is_free_cert: bool,
        days_remaining: Optional[int],
        cert_age_days: Optional[int],
        domain_matches: bool
    ) -> Dict[str, bool]:
        """Assess SSL risk indicators"""
        
        indicators = {
            'self_signed': is_self_signed,
            'free_certificate': is_free_cert,
            'expired': days_remaining is not None and days_remaining < 0,
            'expires_soon': days_remaining is not None and 0 <= days_remaining < 30,
            'very_new_cert': cert_age_days is not None and cert_age_days < 30,
            'short_validity': days_remaining is not None and days_remaining < 90,
            'domain_mismatch': not domain_matches,
            'missing_validity': days_remaining is None
        }
        
        return indicators
    
    def _calculate_ssl_risk_score(self, indicators: Dict[str, bool]) -> float:
        """Calculate SSL risk score (0-100)"""
        weights = {
            'self_signed': 40,
            'free_certificate': 10,
            'expired': 50,
            'expires_soon': 20,
            'very_new_cert': 15,
            'short_validity': 10,
            'domain_mismatch': 45,
            'missing_validity': 25
        }
        
        score = sum(
            weights.get(indicator, 0)
            for indicator, present in indicators.items()
            if present
        )
        
        return min(score, 100)
    
    def _http_result(self, domain: str, url: str) -> Dict:
        """Return result for HTTP (non-SSL) sites"""
        logger.warning(f"{domain} uses HTTP - No SSL/TLS encryption")
        
        return {
            'url': url,
            'domain': domain,
            'scheme': 'http',
            'protocol': 'HTTP',
            'success': True,
            'has_ssl': False,
            'ssl_enabled': False,
            'error': 'Site uses HTTP protocol - No SSL/TLS encryption',
            'warning': 'Unencrypted connection - data transmitted in plain text',
            'issuer': None,
            'issuer_organization': None,
            'issuer_common_name': None,
            'subject': None,
            'subject_common_name': None,
            'valid_from': None,
            'valid_until': None,
            'days_remaining': None,
            'cert_age_days': None,
            'is_expired': False,
            'expires_soon': False,
            'san_list': [],
            'san_count': 0,
            'is_self_signed': False,
            'is_free_cert': False,
            'domain_matches': False,
            'signature_algorithm': None,
            'serial_number': None,
            'version': None,
            'risk_indicators': {
                'no_ssl': True,
                'unencrypted_http': True,
                'insecure_protocol': True
            },
            'risk_score': 85  # Very high risk for HTTP sites
        }
    
    def _error_result(self, domain: str, url: str, error: str) -> Dict:
        """Return error result structure"""
        return {
            'url': url,
            'domain': domain,
            'scheme': 'unknown',
            'protocol': 'UNKNOWN',
            'success': False,
            'has_ssl': False,
            'ssl_enabled': False,
            'error': error,
            'issuer': None,
            'issuer_organization': None,
            'issuer_common_name': None,
            'subject': None,
            'subject_common_name': None,
            'valid_from': None,
            'valid_until': None,
            'days_remaining': None,
            'cert_age_days': None,
            'is_expired': False,
            'expires_soon': False,
            'san_list': [],
            'san_count': 0,
            'is_self_signed': False,
            'is_free_cert': False,
            'domain_matches': False,
            'signature_algorithm': None,
            'serial_number': None,
            'version': None,
            'risk_indicators': {
                'ssl_error': True,
                'connection_failed': True
            },
            'risk_score': 80  # High risk when SSL check fails
        }
    
    def check_multiple(self, urls: list) -> Dict[str, Dict]:
        """
        Check SSL for multiple URLs
        Returns dictionary mapping URL to results
        """
        results = {}
        
        for url in urls:
            try:
                results[url] = self.check(url)
            except Exception as e:
                logger.error(f"Failed to check {url}: {e}")
                results[url] = self._error_result(url, url, str(e))
        
        return results
    
    def get_ssl_summary(self, result: Dict) -> str:
        """
        Generate human-readable SSL summary
        """
        if not result.get('success'):
            return f"❌ SSL Check Failed: {result.get('error', 'Unknown error')}"
        
        if not result.get('has_ssl'):
            return f"⚠️  HTTP Site - No SSL/TLS encryption (Risk: {result.get('risk_score', 0)}/100)"
        
        status_parts = []
        
        # Protocol
        status_parts.append(f"✅ HTTPS Enabled")
        
        # Certificate validity
        if result.get('is_expired'):
            status_parts.append("❌ Certificate EXPIRED")
        elif result.get('expires_soon'):
            status_parts.append(f"⚠️  Expires in {result.get('days_remaining')} days")
        else:
            status_parts.append(f"Valid for {result.get('days_remaining')} days")
        
        # Issuer
        issuer = result.get('issuer_organization') or result.get('issuer_common_name', 'Unknown')
        status_parts.append(f"Issuer: {issuer}")
        
        # Domain match
        if result.get('domain_matches'):
            status_parts.append("✅ Domain Match")
        else:
            status_parts.append("❌ Domain Mismatch")
        
        # Risk score
        risk_score = result.get('risk_score', 0)
        status_parts.append(f"Risk: {risk_score}/100")
        
        return " | ".join(status_parts)
    
    def clear_cache(self):
        """Clear SSL certificate cache"""
        self.cache.clear()
        logger.info("SSL cache cleared")