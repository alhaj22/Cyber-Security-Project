"""
PhishRadar WHOIS Lookup - Domain registration and age analysis
Retrieves WHOIS information and calculates domain reputation
"""

import whois
from datetime import datetime, timedelta
from typing import Dict, Optional
from .utils import logger, timing_decorator, safe_execute

class WHOISLookup:
    """WHOIS information retrieval and analysis"""
    
    def __init__(self):
        self.cache = {}
        self.cache_duration = timedelta(hours=24)
        logger.info("WHOISLookup initialized")
    
    @timing_decorator
    def lookup(self, domain: str) -> Dict:
        """
        Perform WHOIS lookup on domain
        Returns registration info, age, and risk indicators
        """
        # Check cache
        if domain in self.cache:
            cached_data, timestamp = self.cache[domain]
            if datetime.now() - timestamp < self.cache_duration:
                logger.debug(f"Using cached WHOIS for {domain}")
                return cached_data
        
        try:
            logger.info(f"Performing WHOIS lookup for {domain}")
            w = whois.whois(domain)
            
            result = self._parse_whois_data(w, domain)
            
            # Cache result
            self.cache[domain] = (result, datetime.now())
            
            return result
            
        except whois.parser.PywhoisError as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return self._error_result(domain, "WHOIS lookup failed")
        except Exception as e:
            logger.error(f"Unexpected error in WHOIS lookup for {domain}: {e}")
            return self._error_result(domain, str(e))
    
    def _parse_whois_data(self, w, domain: str) -> Dict:
        """Parse WHOIS response into structured data"""
        
        # Extract creation date
        creation_date = self._extract_date(w.creation_date)
        expiration_date = self._extract_date(w.expiration_date)
        updated_date = self._extract_date(w.updated_date)
        
        # Calculate domain age
        domain_age_days = self._calculate_age(creation_date) if creation_date else None
        
        # Calculate days until expiration
        days_to_expire = self._calculate_days_to_expire(expiration_date) if expiration_date else None
        
        # Extract registrar info
        registrar = w.registrar if hasattr(w, 'registrar') else None
        
        # Extract nameservers
        name_servers = w.name_servers if hasattr(w, 'name_servers') else []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        
        # Extract registrant info
        registrant_name = w.name if hasattr(w, 'name') else None
        registrant_org = w.org if hasattr(w, 'org') else None
        registrant_country = w.country if hasattr(w, 'country') else None
        
        # Assess risk factors
        risk_indicators = self._assess_whois_risk(
            domain_age_days, days_to_expire, registrar, name_servers
        )
        
        result = {
            'domain': domain,
            'success': True,
            'creation_date': creation_date.isoformat() if creation_date else None,
            'expiration_date': expiration_date.isoformat() if expiration_date else None,
            'updated_date': updated_date.isoformat() if updated_date else None,
            'domain_age_days': domain_age_days,
            'domain_age_years': round(domain_age_days / 365, 2) if domain_age_days else None,
            'days_to_expire': days_to_expire,
            'registrar': registrar,
            'name_servers': name_servers,
            'registrant_name': registrant_name,
            'registrant_org': registrant_org,
            'registrant_country': registrant_country,
            'risk_indicators': risk_indicators,
            'risk_score': self._calculate_whois_risk_score(risk_indicators),
            'status': w.status if hasattr(w, 'status') else None
        }
        
        logger.debug(f"WHOIS parsed for {domain}: age={domain_age_days} days")
        return result
    
    def _extract_date(self, date_field) -> Optional[datetime]:
        """Extract datetime from WHOIS date field"""
        if date_field is None:
            return None
        
        # WHOIS returns list sometimes
        if isinstance(date_field, list):
            date_field = date_field[0]
        
        # Already datetime
        if isinstance(date_field, datetime):
            return date_field
        
        return None
    
    def _calculate_age(self, creation_date: datetime) -> Optional[int]:
        """Calculate domain age in days"""
        if not creation_date:
            return None
        
        try:
            age = datetime.now() - creation_date
            return age.days
        except Exception:
            return None
    
    def _calculate_days_to_expire(self, expiration_date: datetime) -> Optional[int]:
        """Calculate days until domain expires"""
        if not expiration_date:
            return None
        
        try:
            delta = expiration_date - datetime.now()
            return delta.days
        except Exception:
            return None
    
    def _assess_whois_risk(
        self, 
        age_days: Optional[int],
        days_to_expire: Optional[int],
        registrar: Optional[str],
        name_servers: list
    ) -> Dict[str, bool]:
        """Assess risk indicators from WHOIS data"""
        
        # Suspicious registrars (commonly used in phishing)
        suspicious_registrars = [
            'namecheap', 'godaddy', 'tucows', 'enom'
        ]
        
        # Privacy/proxy services
        privacy_keywords = ['privacy', 'proxy', 'whoisguard', 'protected']
        
        indicators = {
            'very_new_domain': age_days is not None and age_days < 30,
            'newly_registered': age_days is not None and age_days < 90,
            'relatively_new': age_days is not None and age_days < 365,
            'expiring_soon': days_to_expire is not None and days_to_expire < 30,
            'short_registration': days_to_expire is not None and days_to_expire < 365,
            'suspicious_registrar': any(
                susp in (registrar or '').lower() 
                for susp in suspicious_registrars
            ),
            'privacy_protected': any(
                keyword in (registrar or '').lower() 
                for keyword in privacy_keywords
            ),
            'no_nameservers': len(name_servers) == 0,
            'few_nameservers': 0 < len(name_servers) < 2,
            'missing_creation_date': age_days is None,
            'missing_expiration_date': days_to_expire is None
        }
        
        return indicators
    
    def _calculate_whois_risk_score(self, indicators: Dict[str, bool]) -> float:
        """Calculate risk score from WHOIS indicators (0-100)"""
        weights = {
            'very_new_domain': 30,
            'newly_registered': 20,
            'relatively_new': 10,
            'expiring_soon': 15,
            'short_registration': 5,
            'suspicious_registrar': 5,
            'privacy_protected': 10,
            'no_nameservers': 20,
            'few_nameservers': 10,
            'missing_creation_date': 15,
            'missing_expiration_date': 10
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
            'error': error,
            'creation_date': None,
            'domain_age_days': None,
            'risk_indicators': {'whois_unavailable': True},
            'risk_score': 50  # Medium risk when WHOIS unavailable
        }
    
    def bulk_lookup(self, domains: list) -> Dict[str, Dict]:
        """Perform WHOIS lookup on multiple domains"""
        results = {}
        
        for domain in domains:
            results[domain] = self.lookup(domain)
        
        return results
    
    def clear_cache(self):
        """Clear WHOIS cache"""
        self.cache.clear()
        logger.info("WHOIS cache cleared")