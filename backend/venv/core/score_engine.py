"""
PhishRadar Score Engine - Weighted risk calculation
Combines all analysis modules into final risk assessment
"""

from typing import Dict, List
from .utils import logger

class ScoreEngine:
    """Calculate comprehensive phishing risk score"""
    
    def __init__(self):
        # Module weights (total = 1.0)
        self.weights = {
            'url_analysis': 0.15,
            'whois': 0.20,
            'ssl': 0.20,
            'brand': 0.25,
            'tld': 0.15,
            'dns': 0.05
        }
        
        # Risk level thresholds
        self.thresholds = {
            'safe': 25,
            'low': 40,
            'medium': 60,
            'high': 75,
            'critical': 90
        }
        
        logger.info("ScoreEngine initialized")
    
    def calculate(self, analysis_results: Dict) -> Dict:
        """
        Calculate weighted risk score from all analysis modules
        Returns comprehensive risk assessment
        """
        # Extract individual scores
        scores = {
            'url_analysis': self._extract_score(analysis_results, 'url_analysis'),
            'whois': self._extract_score(analysis_results, 'whois'),
            'ssl': self._extract_score(analysis_results, 'ssl'),
            'brand': self._extract_score(analysis_results, 'brand'),
            'tld': self._extract_score(analysis_results, 'tld'),
            'dns': self._extract_score(analysis_results, 'dns')
        }
        
        # Calculate weighted score
        weighted_score = sum(
            scores[module] * self.weights[module]
            for module in scores
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(weighted_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(analysis_results)
        
        # Identify critical indicators
        critical_indicators = self._identify_critical_indicators(analysis_results)
        
        # Generate threat summary
        threat_summary = self._generate_threat_summary(
            scores, critical_indicators, risk_level
        )
        
        result = {
            'overall_risk_score': round(weighted_score, 2),
            'risk_level': risk_level,
            'confidence': round(confidence, 2),
            'module_scores': {k: round(v, 2) for k, v in scores.items()},
            'weighted_contributions': {
                k: round(v * self.weights[k], 2) for k, v in scores.items()
            },
            'critical_indicators': critical_indicators,
            'threat_summary': threat_summary,
            'recommendation': self._get_recommendation(risk_level, confidence)
        }
        
        logger.info(f"Risk score calculated: {weighted_score:.2f} ({risk_level})")
        return result
    
    def _extract_score(self, analysis_results: Dict, module: str) -> float:
        """Extract risk score from module results"""
        module_data = analysis_results.get(module, {})
        
        # Try direct risk_score field
        if 'risk_score' in module_data:
            return float(module_data['risk_score'])
        
        # Fallback: calculate from indicators
        indicators = module_data.get('risk_indicators', {})
        if indicators:
            # Count positive indicators
            positive_count = sum(1 for v in indicators.values() if v)
            total_count = len(indicators)
            return (positive_count / total_count * 100) if total_count > 0 else 0
        
        # Default: medium risk if no data
        return 50.0
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= self.thresholds['critical']:
            return 'CRITICAL'
        elif score >= self.thresholds['high']:
            return 'HIGH'
        elif score >= self.thresholds['medium']:
            return 'MEDIUM'
        elif score >= self.thresholds['low']:
            return 'LOW'
        else:
            return 'SAFE'
    
    def _calculate_confidence(self, analysis_results: Dict) -> float:
        """Calculate confidence in the assessment"""
        # Base confidence
        confidence = 100.0
        
        # Reduce confidence for missing data
        for module in self.weights:
            module_data = analysis_results.get(module, {})
            
            if not module_data or not module_data.get('success', True):
                confidence -= 15
            elif module_data.get('error'):
                confidence -= 10
        
        # Boost confidence for strong indicators
        brand_data = analysis_results.get('brand', {})
        if brand_data.get('impersonation_likely'):
            confidence = min(100, confidence + 20)
        
        return max(0, confidence)
    
    def _identify_critical_indicators(self, analysis_results: Dict) -> List[Dict]:
        """Identify critical risk indicators across all modules"""
        critical = []
        
        # URL Analysis
        url_data = analysis_results.get('url_analysis', {})
        url_indicators = url_data.get('suspicious_indicators', {})
        
        if url_indicators.get('has_ip_in_domain'):
            critical.append({
                'severity': 'CRITICAL',
                'category': 'URL',
                'description': 'Domain uses IP address instead of domain name',
                'impact': 'Strong indicator of phishing'
            })
        
        if url_indicators.get('url_shortener'):
            critical.append({
                'severity': 'HIGH',
                'category': 'URL',
                'description': 'URL shortener detected',
                'impact': 'Obscures true destination'
            })
        
        # WHOIS
        whois_data = analysis_results.get('whois', {})
        whois_indicators = whois_data.get('risk_indicators', {})
        
        if whois_indicators.get('very_new_domain'):
            critical.append({
                'severity': 'HIGH',
                'category': 'WHOIS',
                'description': f"Domain registered recently ({whois_data.get('domain_age_days')} days old)",
                'impact': 'Newly registered domains often used in phishing'
            })
        
        # SSL
        ssl_data = analysis_results.get('ssl', {})
        if not ssl_data.get('has_ssl'):
            critical.append({
                'severity': 'CRITICAL',
                'category': 'SSL',
                'description': '',
                'impact': 'Insecure connection, data at risk'
            })
        elif ssl_data.get('risk_indicators', {}).get('domain_mismatch'):
            critical.append({
                'severity': 'CRITICAL',
                'category': 'SSL',
                'description': 'SSL certificate does not match domain',
                'impact': 'Strong indicator of impersonation'
            })
        elif ssl_data.get('risk_indicators', {}).get('self_signed'):
            critical.append({
                'severity': 'HIGH',
                'category': 'SSL',
                'description': 'Self-signed SSL certificate',
                'impact': 'Not trusted by certificate authority'
            })
        
        # Brand
        brand_data = analysis_results.get('brand', {})
        if brand_data.get('impersonation_likely'):
            brands = brand_data.get('detected_brands', [])
            critical.append({
                'severity': 'CRITICAL',
                'category': 'BRAND',
                'description': f"Likely brand impersonation: {', '.join(brands)}",
                'impact': 'Attempting to impersonate legitimate brand'
            })
        
        typosquats = brand_data.get('typosquatting', [])
        for typo in typosquats:
            if typo.get('likely_typosquat'):
                critical.append({
                    'severity': 'HIGH',
                    'category': 'BRAND',
                    'description': f"Typosquatting detected: similar to '{typo['brand']}'",
                    'impact': 'Domain designed to trick users'
                })
        
        # TLD
        tld_data = analysis_results.get('tld', {})
        if tld_data.get('risk_indicators', {}).get('critical_risk'):
            critical.append({
                'severity': 'HIGH',
                'category': 'TLD',
                'description': f"High-risk TLD: .{tld_data.get('tld')}",
                'impact': 'TLD commonly associated with phishing'
            })
        
        return sorted(critical, key=lambda x: 
                     {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x['severity'], 4))
    
    def _generate_threat_summary(
        self,
        scores: Dict[str, float],
        critical_indicators: List[Dict],
        risk_level: str
    ) -> str:
        """Generate human-readable threat summary"""
        if risk_level == 'CRITICAL':
            base = "⚠️ CRITICAL THREAT DETECTED - Do not interact with this URL. "
        elif risk_level == 'HIGH':
            base = "⚠️ HIGH RISK - Exercise extreme caution. "
        elif risk_level == 'MEDIUM':
            base = "⚡ MEDIUM RISK - Additional verification recommended. "
        elif risk_level == 'LOW':
            base = "ℹ️ LOW RISK - Proceed with normal caution. "
        else:
            base = "✅ SAFE - No significant threats detected. "
        
        # Add top concern
        if critical_indicators:
            top_concern = critical_indicators[0]
            base += f" {top_concern['description']}. "
        
        # Add module highlights
        high_risk_modules = [k for k, v in scores.items() if v > 70]
        if high_risk_modules:
            base += f"  {', '.join(high_risk_modules).replace('_', ' ')}."
        
        return base
    
    def _get_recommendation(self, risk_level: str, confidence: float) -> str:
        """Get security recommendation"""
        recommendations = {
            'CRITICAL': (
                "DO NOT VISIT THIS SITE. Report as phishing immediately. "
                "Block this URL in your security systems. "
                "Warn others who may have received this link."
            ),
            'HIGH': (
                "Avoid this site unless you can verify its legitimacy through independent means. "
                "Do not enter any personal information or credentials. "
                "Contact the brand directly through official channels if uncertain."
            ),
            'MEDIUM': (
                "Verify the URL carefully before proceeding. "
                "Check for official communication from the brand. "
                "Use caution when entering sensitive information."
            ),
            'LOW': (
                "Proceed with standard security precautions. "
                "Verify SSL certificate. "
                "Ensure you intended to visit this specific domain."
            ),
            'SAFE': (
                "Site appears legitimate. "
                "Always maintain standard security practices. "
                "Verify you're on the correct site for sensitive transactions."
            )
        }
        
        recommendation = recommendations.get(risk_level, "Exercise caution.")
        
        if confidence < 70:
            recommendation += " Note: Limited data available for full assessment."
        
        return recommendation
    
    def adjust_weights(self, new_weights: Dict[str, float]):
        """Adjust module weights (for customization)"""
        if abs(sum(new_weights.values()) - 1.0) > 0.01:
            logger.error("Weights must sum to 1.0")
            return False
        
        self.weights.update(new_weights)
        logger.info(f"Weights updated: {self.weights}")
        return True
    
    def get_weights(self) -> Dict[str, float]:
        """Get current module weights"""
        return self.weights.copy()