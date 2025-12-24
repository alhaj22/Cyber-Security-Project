"""
PhishRadar TLD Checker - Top-Level Domain risk analysis
Assesses TLD reputation and phishing association
"""

from typing import Dict, Optional
from .utils import logger, data_manager

class TLDChecker:
    """TLD reputation and risk assessment"""
    
    def __init__(self):
        self.suspicious_tlds = self._load_suspicious_tlds()
        self.tld_stats = self._load_tld_statistics()
        logger.info(f"TLDChecker initialized with {len(self.suspicious_tlds)} suspicious TLDs")
    
    def _load_suspicious_tlds(self) -> Dict[str, int]:
        """Load suspicious TLDs with risk levels"""
        data = data_manager.load_json('suspicious_tlds.json')
        
        # Default data if file doesn't exist
        if not data:
            data = {
                # Free/Freemium TLDs (high risk)
                'tk': 95, 'ml': 95, 'ga': 95, 'cf': 95, 'gq': 95,
                
                # Generic TLDs often abused
                'xyz': 70, 'top': 75, 'work': 70, 'click': 80,
                'link': 75, 'bid': 70, 'download': 85, 'stream': 70,
                'racing': 65, 'review': 60, 'faith': 65, 'loan': 75,
                'win': 70, 'date': 65, 'science': 60, 'party': 65,
                
                # Country codes sometimes abused
                'ru': 40, 'cn': 35, 'pw': 60, 'cc': 50,
                
                # Newer TLDs with less oversight
                'zip': 65, 'mov': 60, 'icu': 55, 'buzz': 50,
                
                # Medium risk
                'info': 30, 'biz': 35, 'online': 40, 'site': 45,
                'website': 40, 'space': 45, 'tech': 35,
                
                # Lower risk but still monitored
                'club': 25, 'live': 30, 'pro': 25, 'store': 30
            }
        
        return data
    
    def _load_tld_statistics(self) -> Dict:
        """Load TLD usage statistics and metadata"""
        return {
            'trusted': ['com', 'org', 'net', 'edu', 'gov', 'mil'],
            'country_codes': [
                'us', 'uk', 'de', 'fr', 'jp', 'ca', 'au', 'br',
                'in', 'it', 'es', 'mx', 'nl', 'se', 'no', 'ch'
            ],
            'new_gtlds': [
                'app', 'dev', 'page', 'blog', 'shop', 'cloud',
                'ai', 'io', 'tech', 'digital', 'online'
            ]
        }
    
    def check(self, tld: str) -> Dict:
        """
        Check TLD reputation and risk
        Returns comprehensive TLD analysis
        """
        tld_lower = tld.lower().strip('.')
        
        # Get base risk score
        base_risk = self.suspicious_tlds.get(tld_lower, 0)
        
        # Categorize TLD
        category = self._categorize_tld(tld_lower)
        
        # Check if TLD is commonly used in phishing
        phishing_associated = base_risk >= 60
        
        # Assess reputation
        reputation = self._assess_reputation(base_risk, category)
        
        # Additional risk factors
        risk_indicators = {
            'is_suspicious': base_risk > 50,
            'high_risk': base_risk >= 70,
            'critical_risk': base_risk >= 90,
            'free_tld': base_risk >= 90,
            'new_tld': category == 'new_gtld',
            'country_code': category == 'country_code',
            'trusted_tld': category == 'trusted',
            'phishing_associated': phishing_associated
        }
        
        result = {
            'tld': tld_lower,
            'category': category,
            'base_risk_score': base_risk,
            'reputation': reputation,
            'risk_indicators': risk_indicators,
            'risk_score': self._calculate_tld_risk_score(base_risk, risk_indicators),
            'recommendation': self._get_recommendation(base_risk, category)
        }
        
        if base_risk > 50:
            logger.info(f"Suspicious TLD detected: {tld_lower} (risk: {base_risk})")
        
        return result
    
    def _categorize_tld(self, tld: str) -> str:
        """Categorize TLD type"""
        if tld in self.tld_stats['trusted']:
            return 'trusted'
        elif tld in self.tld_stats['country_codes']:
            return 'country_code'
        elif tld in self.tld_stats['new_gtlds']:
            return 'new_gtld'
        elif tld in self.suspicious_tlds and self.suspicious_tlds[tld] >= 90:
            return 'free_tld'
        elif tld in self.suspicious_tlds:
            return 'suspicious'
        else:
            return 'unknown'
    
    def _assess_reputation(self, base_risk: int, category: str) -> str:
        """Assess TLD reputation"""
        if category == 'trusted':
            return 'EXCELLENT'
        elif category == 'country_code':
            return 'GOOD'
        elif base_risk == 0:
            return 'NEUTRAL'
        elif base_risk < 40:
            return 'MODERATE'
        elif base_risk < 70:
            return 'POOR'
        else:
            return 'VERY_POOR'
    
    def _calculate_tld_risk_score(self, base_risk: int, indicators: Dict[str, bool]) -> float:
        """Calculate comprehensive TLD risk score (0-100)"""
        # Start with base risk
        score = base_risk
        
        # Adjustments based on indicators
        if indicators['trusted_tld']:
            score = max(0, score - 20)
        
        if indicators['critical_risk']:
            score = min(100, score + 5)
        
        if indicators['phishing_associated']:
            score = min(100, score + 10)
        
        return score
    
    def _get_recommendation(self, base_risk: int, category: str) -> str:
        """Get security recommendation based on TLD"""
        if category == 'trusted':
            return "Generally safe - standard TLD"
        elif category == 'country_code':
            return "Verify legitimacy - country code TLD"
        elif base_risk >= 90:
            return "HIGH RISK - Free TLD commonly used in phishing"
        elif base_risk >= 70:
            return "CAUTION - TLD associated with malicious activity"
        elif base_risk >= 50:
            return "VERIFY - TLD requires additional verification"
        elif base_risk >= 30:
            return "Monitor - TLD has moderate risk"
        else:
            return "Low risk - proceed with normal caution"
    
    def compare_tlds(self, tld1: str, tld2: str) -> Dict:
        """Compare two TLDs"""
        result1 = self.check(tld1)
        result2 = self.check(tld2)
        
        return {
            'tld1': result1,
            'tld2': result2,
            'safer_choice': tld1 if result1['risk_score'] < result2['risk_score'] else tld2,
            'risk_difference': abs(result1['risk_score'] - result2['risk_score'])
        }
    
    def get_suspicious_tlds(self, min_risk: int = 60) -> Dict[str, int]:
        """Get all TLDs above a risk threshold"""
        return {
            tld: risk 
            for tld, risk in self.suspicious_tlds.items() 
            if risk >= min_risk
        }
    
    def is_suspicious(self, tld: str) -> bool:
        """Quick check if TLD is suspicious"""
        tld_lower = tld.lower().strip('.')
        return self.suspicious_tlds.get(tld_lower, 0) >= 60