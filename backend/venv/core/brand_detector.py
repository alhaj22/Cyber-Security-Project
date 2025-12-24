"""
PhishRadar Brand Detector - Detect impersonated brands
Identifies brand names and calculates impersonation risk
"""

import re
from typing import Dict, List, Optional, Tuple
from .utils import logger, timing_decorator, data_manager, security_utils

class BrandDetector:
    """Detect brand impersonation in URLs"""
    
    def __init__(self):
        self.brands = self._load_brands()
        self.high_value_brands = self._load_high_value_brands()
        logger.info(f"BrandDetector initialized with {len(self.brands)} brands")
    
    def _load_brands(self) -> List[str]:
        """Load brand keywords from data file"""
        brands = data_manager.load_text_lines('brand_keywords.txt')
        
        # Default brands if file doesn't exist
        if not brands:
            brands = [
                'paypal', 'amazon', 'microsoft', 'apple', 'google',
                'facebook', 'instagram', 'twitter', 'netflix', 'ebay',
                'walmart', 'target', 'bestbuy', 'chase', 'bankofamerica',
                'wellsfargo', 'citibank', 'americanexpress', 'visa', 'mastercard',
                'dropbox', 'adobe', 'linkedin', 'spotify', 'zoom',
                'slack', 'github', 'gitlab', 'stackoverflow', 'reddit'
            ]
        
        return [b.lower() for b in brands]
    
    def _load_high_value_brands(self) -> List[str]:
        """Load high-value brands (financial, tech giants)"""
        return [
            'paypal', 'chase', 'bankofamerica', 'wellsfargo', 'citibank',
            'americanexpress', 'visa', 'mastercard', 'discover',
            'apple', 'microsoft', 'google', 'amazon', 'meta', 'facebook'
        ]
    
    @timing_decorator
    def detect(self, url: str, domain: str, path: str = '') -> Dict:
        """
        Detect brand mentions and assess impersonation risk
        """
        url_lower = url.lower()
        domain_lower = domain.lower()
        path_lower = path.lower()
        
        # Find all brand mentions
        detected_brands = self._find_brands(url_lower)
        domain_brands = self._find_brands(domain_lower)
        path_brands = self._find_brands(path_lower)
        
        # Check if domain legitimately belongs to brand
        legitimate_brand = self._check_legitimate_domain(domain_lower, detected_brands)
        
        # Detect typosquatting
        typosquat_results = self._detect_typosquatting(domain_lower)
        
        # Detect brand in subdomain (suspicious)
        subdomain_brand = self._detect_subdomain_brand(url_lower, detected_brands)
        
        # Check for brand + suspicious TLD
        suspicious_brand_tld = self._check_suspicious_brand_tld(domain_lower, detected_brands)
        
        # Assess impersonation risk
        risk_indicators = self._assess_brand_risk(
            detected_brands, domain_brands, path_brands,
            legitimate_brand, typosquat_results, subdomain_brand,
            suspicious_brand_tld
        )
        
        result = {
            'detected_brands': list(detected_brands),
            'brand_count': len(detected_brands),
            'domain_brands': list(domain_brands),
            'path_brands': list(path_brands),
            'legitimate_brand': legitimate_brand,
            'typosquatting': typosquat_results,
            'subdomain_brand': subdomain_brand,
            'suspicious_brand_tld': suspicious_brand_tld,
            'high_value_target': any(b in self.high_value_brands for b in detected_brands),
            'risk_indicators': risk_indicators,
            'risk_score': self._calculate_brand_risk_score(risk_indicators),
            'impersonation_likely': self._is_impersonation_likely(risk_indicators)
        }
        
        if detected_brands:
            logger.info(f"Brands detected: {detected_brands}")
        
        return result
    
    def _find_brands(self, text: str) -> set:
        """Find all brand mentions in text"""
        found = set()
        
        for brand in self.brands:
            # Exact word match
            if re.search(rf'\b{re.escape(brand)}\b', text):
                found.add(brand)
            # Brand with numbers/hyphens (e.g., paypal123, pay-pal)
            elif re.search(rf'{re.escape(brand)}[\d-]', text):
                found.add(brand)
        
        return found
    
    def _check_legitimate_domain(self, domain: str, brands: set) -> Optional[str]:
        """Check if domain legitimately belongs to a brand"""
        for brand in brands:
            # Direct match
            if domain == f"{brand}.com" or domain == f"www.{brand}.com":
                return brand
            
            # Known legitimate pattern (brand.tld)
            if domain.startswith(f"{brand}.") and not domain.count('.') > 2:
                return brand
        
        return None
    
    def _detect_typosquatting(self, domain: str) -> List[Dict]:
        """Detect potential typosquatting of brands"""
        results = []
        
        for brand in self.brands:
            # Calculate similarity
            similarity = security_utils.calculate_similarity(brand, domain)
            
            # High similarity but not exact match = potential typosquat
            if 0.7 < similarity < 1.0:
                distance = security_utils.levenshtein_distance(brand, domain)
                results.append({
                    'brand': brand,
                    'similarity': round(similarity, 3),
                    'edit_distance': distance,
                    'likely_typosquat': similarity > 0.85
                })
        
        return sorted(results, key=lambda x: x['similarity'], reverse=True)
    
    def _detect_subdomain_brand(self, url: str, brands: set) -> Optional[Dict]:
        """Detect brand name in subdomain (often suspicious)"""
        # Extract subdomain part
        match = re.search(r'https?://([^/]+)', url)
        if not match:
            return None
        
        full_domain = match.group(1)
        parts = full_domain.split('.')
        
        # Check if brand is in subdomain but not the main domain
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])
            main_domain = parts[-2]
            
            for brand in brands:
                if brand in subdomain.lower() and brand not in main_domain.lower():
                    return {
                        'brand': brand,
                        'subdomain': subdomain,
                        'main_domain': main_domain,
                        'suspicious': True
                    }
        
        return None
    
    def _check_suspicious_brand_tld(self, domain: str, brands: set) -> bool:
        """Check if brand + suspicious TLD combination"""
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
        
        for brand in brands:
            for tld in suspicious_tlds:
                if f"{brand}.{tld}" in domain:
                    return True
        
        return False
    
    def _assess_brand_risk(
        self,
        detected_brands: set,
        domain_brands: set,
        path_brands: set,
        legitimate_brand: Optional[str],
        typosquat_results: List[Dict],
        subdomain_brand: Optional[Dict],
        suspicious_brand_tld: bool
    ) -> Dict[str, bool]:
        """Assess brand impersonation risk indicators"""
        
        indicators = {
            'has_brand_mention': len(detected_brands) > 0,
            'multiple_brands': len(detected_brands) > 1,
            'brand_in_domain': len(domain_brands) > 0,
            'brand_in_path_only': len(path_brands) > 0 and len(domain_brands) == 0,
            'not_legitimate': legitimate_brand is None and len(domain_brands) > 0,
            'typosquatting_detected': len(typosquat_results) > 0,
            'high_similarity_typosquat': any(
                t['similarity'] > 0.85 for t in typosquat_results
            ),
            'brand_in_subdomain': subdomain_brand is not None,
            'suspicious_brand_tld': suspicious_brand_tld,
            'high_value_brand': any(b in self.high_value_brands for b in detected_brands)
        }
        
        return indicators
    
    def _calculate_brand_risk_score(self, indicators: Dict[str, bool]) -> float:
        """Calculate brand impersonation risk score (0-100)"""
        weights = {
            'has_brand_mention': 5,
            'multiple_brands': 10,
            'brand_in_domain': 15,
            'brand_in_path_only': 20,
            'not_legitimate': 35,
            'typosquatting_detected': 30,
            'high_similarity_typosquat': 40,
            'brand_in_subdomain': 35,
            'suspicious_brand_tld': 25,
            'high_value_brand': 15
        }
        
        score = sum(
            weights.get(indicator, 0)
            for indicator, present in indicators.items()
            if present
        )
        
        return min(score, 100)
    
    def _is_impersonation_likely(self, indicators: Dict[str, bool]) -> bool:
        """Determine if brand impersonation is likely"""
        # High confidence impersonation indicators
        strong_indicators = [
            'not_legitimate',
            'high_similarity_typosquat',
            'brand_in_subdomain'
        ]
        
        return any(indicators.get(ind, False) for ind in strong_indicators)
    
    def add_brand(self, brand: str):
        """Add a new brand to detection list"""
        brand_lower = brand.lower()
        if brand_lower not in self.brands:
            self.brands.append(brand_lower)
            logger.info(f"Added brand: {brand}")
    
    def get_brand_list(self) -> List[str]:
        """Get list of all tracked brands"""
        return sorted(self.brands)