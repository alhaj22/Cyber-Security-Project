"""Enhanced path-based phishing detection"""

import re
from typing import Dict

def analyze_url_path(url: str, domain: str, path: str) -> Dict:
    """Detect phishing attempts hidden in URL path"""
    
    brands = [
        'paypal', 'amazon', 'skype', 'ebay', 'netflix', 'apple', 'microsoft',
        'google', 'facebook', 'instagram', 'linkedin', 'twitter', 'chase',
        'bankofamerica', 'wellsfargo', 'citibank', 'hsbc', 'barclays',
        'outlook', 'office', 'live', 'hotmail', 'yahoo', 'gmail', 'protonmail',
        'dropbox', 'adobe', 'spotify', 'steam', 'discord', 'roblox'
    ]
    
    risk_score = 0
    warnings = []
    brands_found = []
    
    if not path or path in ['/', '']:
        return {
            'risk_score': 0,
            'warnings': [],
            'brands_found': [],
            'is_suspicious': False
        }
    
    path_lower = path.lower()
    
    # 1. Brand in path
    for brand in brands:
        if brand in path_lower and brand not in domain.lower():
            brands_found.append(brand)
            risk_score += 28
            warnings.append(f"Brand '{brand}' found in path (not in domain)")
    
    # 2. Fake domain pattern in path
    if re.search(r'[a-zA-Z0-9-]+\.(com|net|org|co\.uk|ru|cn|info|biz|xyz)', path_lower):
        risk_score += 35
        warnings.append("Fake domain pattern in path (e.g., paypal.com/)")
    
    # 3. Login keywords
    if any(kw in path_lower for kw in ['login', 'signin', 'verify', 'account', 'secure', 'update']):
        risk_score += 18
        warnings.append("Login/authentication keywords in path")
    
    # 4. Suspicious patterns
    if any(p in path_lower for p in ['webscr', 'cgi-bin', 'cmd', 'sessionid', 'auth', 'security-check']):
        risk_score += 15
        warnings.append("Known phishing script patterns detected")
    
    is_suspicious = risk_score >= 30
    
    return {
        'risk_score': min(risk_score, 100),
        'warnings': warnings,
        'brands_found': brands_found,
        'is_suspicious': is_suspicious
    }