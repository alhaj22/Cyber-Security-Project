"""
PhishRadar SSL Checker - SSL/TLS certificate analysis
Validates certificates and detects suspicious configurations
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, Optional, Tuple
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
    def check(self, domain: str, port: int = 443) -> Dict:
        """
        Comprehensive SSL certificate check
        Returns certificate details and security assessment
        """
        cache_key = f"{domain}:{port}"
        if cache_key in self.cache:
            logger.debug(f"Using cached SSL data for {domain}")
            return self.cache[cache_key]
        
        try:
            logger.info(f"Checking SSL certificate for {domain}:{port}")
            
            # Get certificate
            cert_pem, cert_dict = self._get_certificate(domain, port)
            
            if not cert_pem:
                return self._error_result(domain, "Failed to retrieve certificate")
            
            # Parse certificate
            cert_obj = self._parse_certificate(cert_pem)
            
            # Analyze certificate
            result = self._analyze_certificate(domain, cert_dict, cert_obj)
            
            # Cache result
            self.cache[cache_key] = result
            
            return result
            
        except ssl.SSLError as e:
            logger.warning(f"SSL error for {domain}: {e}")
            return self._error_result(domain, f"SSL Error: {str(e)}")
        except socket.timeout:
            logger.warning(f"Timeout connecting to {domain}")
            return self._error_result(domain, "Connection timeout")
        except Exception as e:
            logger.error(f"Unexpected error checking SSL for {domain}: {e}")
            return self._error_result(domain, str(e))
    
    def _get_certificate(self, domain: str, port: int) -> Tuple[Optional[bytes], Optional[Dict]]:
        """Retrieve SSL certificate from domain"""
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate in PEM format
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
    
    def _analyze_certificate(self, domain: str, cert_dict: Dict, cert_obj) -> Dict:
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
            'domain': domain,
            'success': True,
            'has_ssl': True,
            'issuer': issuer,
            'subject': subject,
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
            'risk_score': self._calculate_ssl_risk_score(risk_indicators)
        }
        
        logger.debug(f"SSL analyzed for {domain}: days_remaining={days_remaining}")
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
            "CloudFlare"
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
    
    def _error_result(self, domain: str, error: str) -> Dict:
        """Return error result structure"""
        return {
            'domain': domain,
            'success': False,
            'has_ssl': False,
            'error': error,
            'risk_indicators': {'no_ssl': True},
            'risk_score': 80  # High risk when no SSL
        }
    
    def clear_cache(self):
        """Clear SSL certificate cache"""
        self.cache.clear()
        logger.info("SSL cache cleared")