"""
PhishRadar Score Engine - BALANCED Weighted risk calculation
Accurately detects phishing while avoiding false positives on legitimate sites
"""

from typing import Dict, List
from .utils import logger

class ScoreEngine:
    """Calculate comprehensive phishing risk score with balanced detection"""
    
    def __init__(self):
        # Module weights (total = 1.0) - BALANCED
        self.weights = {
            'url_analysis': 0.18,
            'whois': 0.20,
            'ssl': 0.20,
            'brand': 0.28,      # Brand impersonation most important
            'tld': 0.10,
            'dns': 0.04
        }
        
        # Risk level thresholds - BALANCED to avoid false positives
        self.thresholds = {
            'safe': 30,         # More room for legitimate sites
            'low': 45,
            'medium': 60,
            'high': 75,
            'critical': 88      # Only truly dangerous sites
        }
        
        # Critical boost amounts (not multipliers - additive)
        self.critical_boosts = {
            'no_ssl_http': 45,              # HTTP site - major boost
            'ssl_domain_mismatch': 40,      # Certificate doesn't match
            'ip_in_domain': 38,             # IP as domain
            'newly_registered_7days': 35,   # Less than week old
            'newly_registered_30days': 25,  # Less than month old
            'brand_impersonation': 42,      # Brand in URL but not legitimate
            'path_phishing': 35,            # Phishing in path
            'url_shortener': 28,            # Hidden destination
            'self_signed_ssl': 32,          # Self-signed certificate
            'typosquatting_confirmed': 38,  # Confirmed typosquatting
            'ssl_expired': 40,              # Expired certificate
            'high_risk_tld': 20             # Dangerous TLD
        }
        
        logger.info("ScoreEngine initialized with balanced detection")
    
    def calculate(self, analysis_results: Dict) -> Dict:
        """
        Calculate weighted risk score from all analysis modules
        BALANCED: Detects phishing while respecting legitimate sites
        """
        # Extract individual scores with PROPER handling
        scores = {
            'url_analysis': self._extract_url_score(analysis_results),
            'whois': self._extract_whois_score(analysis_results),
            'ssl': self._extract_ssl_score(analysis_results),
            'brand': self._extract_brand_score(analysis_results),
            'tld': self._extract_tld_score(analysis_results),
            'dns': self._extract_dns_score(analysis_results)
        }
        
        logger.info(f"📊 Module scores: {scores}")
        
        # Calculate base weighted score
        base_score = sum(
            scores[module] * self.weights[module]
            for module in scores
        )
        
        # Apply critical boosts (additive, not multiplicative)
        final_score = self._apply_critical_boosts(base_score, analysis_results)
        
        # Cap at 100
        final_score = min(final_score, 100.0)
        
        # Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(analysis_results, scores)
        
        # Identify critical indicators
        critical_indicators = self._identify_critical_indicators(analysis_results)
        
        # Generate threat summary
        threat_summary = self._generate_threat_summary(
            scores, critical_indicators, risk_level
        )
        
        result = {
            'overall_risk_score': round(final_score, 2),
            'base_score': round(base_score, 2),
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
        
        logger.warning(f"🎯 FINAL VERDICT: {final_score:.2f}/100 ({risk_level}) - Confidence: {confidence:.0f}%")
        return result
    
    def _extract_url_score(self, analysis_results: Dict) -> float:
        """Extract URL analysis score with proper handling"""
        url_data = analysis_results.get('url_analysis', {})
        
        if not url_data:
            return 50.0  # Medium risk if failed
        
        base_score = url_data.get('risk_score', 0)
        indicators = url_data.get('suspicious_indicators', {})
        
        # Moderate boosts for URL issues
        risk_boost = 0
        
        if indicators.get('has_ip_in_domain'):
            risk_boost += 25  # IP in domain is bad
        
        if indicators.get('url_shortener'):
            risk_boost += 18  # URL shorteners suspicious
        
        if indicators.get('suspicious_path'):
            path_data = url_data.get('path_phishing', {})
            path_risk = path_data.get('risk_score', 0)
            if path_risk > 70:  # Only if high confidence
                risk_boost += min(path_risk * 0.5, 25)
        
        if indicators.get('excessive_subdomains'):
            subdomain_count = url_data.get('subdomain_count', 0)
            if subdomain_count > 3:  # More than 3 is suspicious
                risk_boost += 12
        
        if indicators.get('has_unicode'):
            risk_boost += 15  # IDN attacks
        
        final_score = min(base_score + risk_boost, 100)
        
        logger.info(f"🔗 URL Score: {base_score:.1f} + {risk_boost} boost = {final_score:.1f}")
        return final_score
    
    def _extract_whois_score(self, analysis_results: Dict) -> float:
        """Extract WHOIS score - BALANCED domain age assessment"""
        whois_data = analysis_results.get('whois', {})
        
        if not whois_data or not whois_data.get('success'):
            return 45.0  # Medium risk if unavailable
        
        base_score = whois_data.get('risk_score', 0)
        domain_age_days = whois_data.get('domain_age_days', 999)
        
        # Age-based risk (more nuanced)
        age_risk = 0
        if domain_age_days < 7:
            age_risk = 30  # Very new
        elif domain_age_days < 30:
            age_risk = 20  # New
        elif domain_age_days < 90:
            age_risk = 12  # Fairly new
        elif domain_age_days < 180:
            age_risk = 5   # Recent but okay
        # else: 0 - established domain
        
        # Privacy protection adds minor risk
        privacy_risk = 0
        if whois_data.get('risk_indicators', {}).get('privacy_protected'):
            privacy_risk = 5  # Minor concern only
        
        final_score = min(base_score + age_risk + privacy_risk, 100)
        
        logger.info(f"📅 WHOIS Score: {base_score:.1f} + age({age_risk}) + privacy({privacy_risk}) = {final_score:.1f} (age: {domain_age_days} days)")
        return final_score
    
    def _extract_ssl_score(self, analysis_results: Dict) -> float:
        """Extract SSL score - BALANCED to handle legitimate sites"""
        ssl_data = analysis_results.get('ssl', {})
        
        if not ssl_data:
            return 55.0  # Medium-high if check failed
        
        # Check if HTTP (no SSL) - MAJOR issue
        has_ssl = ssl_data.get('has_ssl', True)
        if not has_ssl:
            logger.critical(f"🚨 HTTP SITE DETECTED - NO SSL ENCRYPTION")
            return 85.0  # Very high risk for HTTP
        
        # Has HTTPS - now check certificate quality
        base_score = ssl_data.get('risk_score', 0)
        cert_risk = 0
        
        # Critical SSL issues
        if not ssl_data.get('domain_matches', True):
            cert_risk += 35  # Domain mismatch = very bad
        
        if ssl_data.get('is_self_signed'):
            cert_risk += 28  # Self-signed = suspicious
        
        if ssl_data.get('is_expired'):
            cert_risk += 35  # Expired = major issue
        
        # Minor SSL issues
        if ssl_data.get('expires_soon'):
            cert_risk += 8  # Expiring soon = minor concern
        
        # NEW certificates on new domains are suspicious
        cert_age = ssl_data.get('cert_age_days', 999)
        whois_data = analysis_results.get('whois', {})
        domain_age = whois_data.get('domain_age_days', 999)
        
        if cert_age < 7 and domain_age < 30:
            cert_risk += 15  # Brand new cert on new domain
        
        # DON'T penalize free certificates from legitimate CAs
        # Let's Encrypt, ZeroSSL are used by many legitimate sites
        # is_free_cert check removed from risk calculation
        
        final_score = min(base_score + cert_risk, 100)
        
        logger.info(f"🔒 SSL Score: {base_score:.1f} + {cert_risk} issues = {final_score:.1f} (has_ssl={has_ssl})")
        return final_score
    
    def _extract_brand_score(self, analysis_results: Dict) -> float:
        """Extract brand impersonation score - PRIMARY phishing indicator"""
        brand_data = analysis_results.get('brand', {})
        
        if not brand_data:
            return 30.0  # Low-medium risk if check failed
        
        base_score = brand_data.get('risk_score', 0)
        brand_risk = 0
        
        # CRITICAL: Brand impersonation detected
        if brand_data.get('impersonation_likely'):
            brand_risk += 45  # HUGE red flag
            logger.critical(f"🚨 BRAND IMPERSONATION DETECTED")
        
        # Typosquatting detection
        typosquats = brand_data.get('typosquatting', [])
        high_confidence_typo = any(
            typo.get('likely_typosquat') and typo.get('similarity', 0) > 0.8
            for typo in typosquats
        )
        if high_confidence_typo:
            brand_risk += 35  # High confidence typosquatting
        elif typosquats:
            brand_risk += 15  # Possible typosquatting
        
        # High value target (banks, payment processors)
        if brand_data.get('high_value_target') and brand_risk > 0:
            brand_risk += 10  # Extra concern for valuable brands
        
        final_score = min(base_score + brand_risk, 100)
        
        logger.info(f"🏢 Brand Score: {base_score:.1f} + {brand_risk} = {final_score:.1f}")
        return final_score
    
    def _extract_tld_score(self, analysis_results: Dict) -> float:
        """Extract TLD reputation score"""
        tld_data = analysis_results.get('tld', {})
        
        if not tld_data:
            return 35.0
        
        score = tld_data.get('risk_score', 0)
        
        # Boost only for truly dangerous TLDs
        reputation = tld_data.get('reputation', 'NEUTRAL')
        if reputation == 'HIGH_RISK':
            score = min(score + 20, 100)
        elif reputation == 'SUSPICIOUS':
            score = min(score + 10, 100)
        
        logger.info(f"🌐 TLD Score: {score:.1f} (reputation: {reputation})")
        return score
    
    def _extract_dns_score(self, analysis_results: Dict) -> float:
        """Extract DNS score"""
        dns_data = analysis_results.get('dns', {})
        
        if not dns_data or not dns_data.get('success'):
            return 40.0
        
        score = dns_data.get('risk_score', 0)
        
        logger.info(f"🌍 DNS Score: {score:.1f}")
        return score
    
    def _apply_critical_boosts(self, base_score: float, analysis_results: Dict) -> float:
        """Apply additive boosts for critical security issues"""
        
        total_boost = 0
        applied_boosts = []
        
        # === SSL/HTTP CHECKS ===
        ssl_data = analysis_results.get('ssl', {})
        
        # HTTP site (no encryption)
        if not ssl_data.get('has_ssl', True):
            total_boost += self.critical_boosts['no_ssl_http']
            applied_boosts.append(f"HTTP_NO_SSL(+{self.critical_boosts['no_ssl_http']})")
        
        # SSL certificate domain mismatch
        elif not ssl_data.get('domain_matches', True):
            total_boost += self.critical_boosts['ssl_domain_mismatch']
            applied_boosts.append(f"SSL_MISMATCH(+{self.critical_boosts['ssl_domain_mismatch']})")
        
        # Self-signed certificate
        if ssl_data.get('is_self_signed'):
            total_boost += self.critical_boosts['self_signed_ssl']
            applied_boosts.append(f"SELF_SIGNED(+{self.critical_boosts['self_signed_ssl']})")
        
        # Expired certificate
        if ssl_data.get('is_expired'):
            total_boost += self.critical_boosts['ssl_expired']
            applied_boosts.append(f"EXPIRED_SSL(+{self.critical_boosts['ssl_expired']})")
        
        # === URL PATTERN CHECKS ===
        url_data = analysis_results.get('url_analysis', {})
        indicators = url_data.get('suspicious_indicators', {})
        
        # IP address as domain
        if indicators.get('has_ip_in_domain'):
            total_boost += self.critical_boosts['ip_in_domain']
            applied_boosts.append(f"IP_DOMAIN(+{self.critical_boosts['ip_in_domain']})")
        
        # Path-based phishing (high confidence only)
        if indicators.get('suspicious_path'):
            path_data = url_data.get('path_phishing', {})
            if path_data.get('risk_score', 0) > 70:
                total_boost += self.critical_boosts['path_phishing']
                applied_boosts.append(f"PATH_PHISH(+{self.critical_boosts['path_phishing']})")
        
        # URL shortener
        if indicators.get('url_shortener'):
            total_boost += self.critical_boosts['url_shortener']
            applied_boosts.append(f"SHORTENER(+{self.critical_boosts['url_shortener']})")
        
        # === WHOIS/DOMAIN AGE CHECKS ===
        whois_data = analysis_results.get('whois', {})
        domain_age = whois_data.get('domain_age_days', 999)
        
        # Very new domain (less than 7 days)
        if domain_age < 7:
            total_boost += self.critical_boosts['newly_registered_7days']
            applied_boosts.append(f"NEW_7D(+{self.critical_boosts['newly_registered_7days']})")
        # New domain (less than 30 days) - only if other risks present
        elif domain_age < 30 and base_score > 40:
            total_boost += self.critical_boosts['newly_registered_30days']
            applied_boosts.append(f"NEW_30D(+{self.critical_boosts['newly_registered_30days']})")
        
        # === BRAND IMPERSONATION CHECKS ===
        brand_data = analysis_results.get('brand', {})
        
        # Confirmed brand impersonation
        if brand_data.get('impersonation_likely'):
            total_boost += self.critical_boosts['brand_impersonation']
            applied_boosts.append(f"BRAND_IMPERSON(+{self.critical_boosts['brand_impersonation']})")
        
        # High-confidence typosquatting
        typosquats = brand_data.get('typosquatting', [])
        high_conf_typo = any(
            typo.get('likely_typosquat') and typo.get('similarity', 0) > 0.85
            for typo in typosquats
        )
        if high_conf_typo:
            total_boost += self.critical_boosts['typosquatting_confirmed']
            applied_boosts.append(f"TYPOSQUAT(+{self.critical_boosts['typosquatting_confirmed']})")
        
        # === TLD CHECKS ===
        tld_data = analysis_results.get('tld', {})
        if tld_data.get('reputation') == 'HIGH_RISK':
            total_boost += self.critical_boosts['high_risk_tld']
            applied_boosts.append(f"BAD_TLD(+{self.critical_boosts['high_risk_tld']})")
        
        final_score = base_score + total_boost
        
        if applied_boosts:
            logger.warning(f"⚠️ CRITICAL BOOSTS: {', '.join(applied_boosts)}")
            logger.warning(f"📈 Score: {base_score:.1f} + {total_boost} = {final_score:.1f}")
        
        return final_score
    
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
    
    def _calculate_confidence(self, analysis_results: Dict, scores: Dict) -> float:
        """Calculate confidence in the assessment"""
        confidence = 100.0
        
        # Reduce for missing modules
        modules_checked = sum(1 for module in self.weights 
                            if analysis_results.get(module, {}).get('success', False))
        modules_total = len(self.weights)
        
        if modules_checked < modules_total:
            confidence -= (modules_total - modules_checked) * 10
        
        # Boost for strong evidence
        critical_count = sum(1 for score in scores.values() if score > 75)
        if critical_count >= 2:
            confidence = min(100, confidence + 15)
        
        # High confidence for obvious threats
        ssl_data = analysis_results.get('ssl', {})
        if not ssl_data.get('has_ssl', True):
            confidence = min(100, confidence + 20)
        
        brand_data = analysis_results.get('brand', {})
        if brand_data.get('impersonation_likely'):
            confidence = min(100, confidence + 15)
        
        return max(60, confidence)
    
    def _identify_critical_indicators(self, analysis_results: Dict) -> List[Dict]:
        """Identify critical risk indicators across all modules"""
        critical = []
        
        # === SSL/HTTPS CHECKS ===
        ssl_data = analysis_results.get('ssl', {})
        
        if not ssl_data.get('has_ssl', True):
            critical.append({
                'severity': 'CRITICAL',
                'category': 'SSL',
                'description': 'No HTTPS - Site uses unencrypted HTTP',
                'impact': 'All data transmitted in plain text. Passwords and sensitive data at risk.'
            })
        
        if ssl_data.get('has_ssl') and not ssl_data.get('domain_matches', True):
            critical.append({
                'severity': 'CRITICAL',
                'category': 'SSL',
                'description': 'SSL certificate does not match domain',
                'impact': 'Certificate issued for different website. Strong sign of impersonation.'
            })
        
        if ssl_data.get('is_self_signed'):
            critical.append({
                'severity': 'HIGH',
                'category': 'SSL',
                'description': 'Self-signed SSL certificate',
                'impact': 'Certificate not validated by trusted authority. Cannot verify identity.'
            })
        
        if ssl_data.get('is_expired'):
            critical.append({
                'severity': 'HIGH',
                'category': 'SSL',
                'description': 'SSL certificate has expired',
                'impact': 'Website owner failed to renew certificate. Poor security practices.'
            })
        
        # === URL ANALYSIS ===
        url_data = analysis_results.get('url_analysis', {})
        indicators = url_data.get('suspicious_indicators', {})
        
        if indicators.get('has_ip_in_domain'):
            critical.append({
                'severity': 'CRITICAL',
                'category': 'URL',
                'description': 'IP address used instead of domain name',
                'impact': 'Legitimate sites use domain names. IP usage hides identity.'
            })
        
        if indicators.get('url_shortener'):
            critical.append({
                'severity': 'MEDIUM',
                'category': 'URL',
                'description': 'URL shortening service detected',
                'impact': 'Real destination hidden. Verify before clicking.'
            })
        
        if indicators.get('suspicious_path'):
            path_data = url_data.get('path_phishing', {})
            if path_data.get('risk_score', 0) > 70:
                brands = path_data.get('brands_found', [])
                brand_text = f" ({', '.join(brands[:2])})" if brands else ""
                critical.append({
                    'severity': 'CRITICAL',
                    'category': 'URL',
                    'description': f"Brand name in URL path{brand_text}",
                    'impact': 'Fake login page. Path mimics legitimate brand URL structure.'
                })
        
        # === WHOIS/DOMAIN AGE ===
        whois_data = analysis_results.get('whois', {})
        domain_age = whois_data.get('domain_age_days', 999)
        
        if domain_age < 30:
            severity = 'HIGH' if domain_age < 7 else 'MEDIUM'
            critical.append({
                'severity': severity,
                'category': 'DOMAIN',
                'description': f"Domain registered only {domain_age} days ago",
                'impact': 'New domains frequently used in phishing. Legitimate sites usually older.'
            })
        
        # === BRAND IMPERSONATION ===
        brand_data = analysis_results.get('brand', {})
        
        if brand_data.get('impersonation_likely'):
            brands = brand_data.get('detected_brands', [])[:2]
            critical.append({
                'severity': 'CRITICAL',
                'category': 'BRAND',
                'description': f"Brand impersonation: {', '.join(brands)}",
                'impact': 'Site pretending to be legitimate brand. High phishing risk.'
            })
        
        # Typosquatting
        typosquats = brand_data.get('typosquatting', [])
        for typo in typosquats[:2]:
            if typo.get('likely_typosquat') and typo.get('similarity', 0) > 0.8:
                critical.append({
                    'severity': 'HIGH',
                    'category': 'BRAND',
                    'description': f"Typosquatting: Similar to '{typo['brand']}'",
                    'impact': 'Intentional misspelling to deceive users.'
                })
        
        # === TLD REPUTATION ===
        tld_data = analysis_results.get('tld', {})
        if tld_data.get('reputation') == 'HIGH_RISK':
            critical.append({
                'severity': 'MEDIUM',
                'category': 'TLD',
                'description': f"High-risk domain extension: .{tld_data.get('tld')}",
                'impact': 'This TLD frequently abused in phishing campaigns.'
            })
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        return sorted(critical, key=lambda x: severity_order.get(x['severity'], 4))
    
    def _generate_threat_summary(
        self,
        scores: Dict[str, float],
        critical_indicators: List[Dict],
        risk_level: str
    ) -> str:
        """Generate human-readable threat summary"""
        
        summaries = {
            'CRITICAL': "🚨 CRITICAL THREAT DETECTED",
            'HIGH': "⚠️ HIGH RISK - Avoid this site",
            'MEDIUM': "⚡ SUSPICIOUS - Verify carefully",
            'LOW': "ℹ️ Minor concerns detected",
            'SAFE': "✅ No significant threats detected"
        }
        
        base = summaries.get(risk_level, "Analysis complete")
        
        # Add primary concern
        if critical_indicators:
            top = critical_indicators[0]
            base += f". {top['description']}"
        
        # Mention number of issues if multiple
        if len(critical_indicators) > 1:
            base += f" ({len(critical_indicators)} issues found)"
        
        return base
    
    def _get_recommendation(self, risk_level: str, confidence: float) -> str:
        """Get security recommendation"""
        
        recommendations = {
            'CRITICAL': (
                "🛑 DO NOT VISIT THIS WEBSITE. Multiple critical security issues detected. "
                "If you received this link via email or message, report it as phishing. "
                "Do not enter any credentials or personal information."
            ),
            'HIGH': (
                "⛔ AVOID THIS SITE. High probability of phishing or malicious intent. "
                "Verify through official channels if you believe this should be legitimate. "
                "Never enter passwords or payment information."
            ),
            'MEDIUM': (
                "⚠️ PROCEED WITH CAUTION. Suspicious patterns detected. "
                "Independently verify this is the correct website before proceeding. "
                "Check URL spelling and SSL certificate carefully."
            ),
            'LOW': (
                "ℹ️ Minor concerns detected. Verify SSL certificate and domain carefully. "
                "Use standard security practices when entering information."
            ),
            'SAFE': (
                "✅ Site appears legitimate based on security checks. "
                "Always verify domain for sensitive transactions. "
                "Maintain standard security awareness."
            )
        }
        
        rec = recommendations.get(risk_level, "Exercise caution and verify site legitimacy.")
        
        if confidence < 75:
            rec += " (Note: Analysis based on limited data.)"
        
        return rec
    
    def adjust_weights(self, new_weights: Dict[str, float]) -> bool:
        """Adjust module weights"""
        if abs(sum(new_weights.values()) - 1.0) > 0.01:
            logger.error("Weights must sum to 1.0")
            return False
        
        self.weights.update(new_weights)
        logger.info(f"Weights updated: {self.weights}")
        return True
    
    def get_weights(self) -> Dict[str, float]:
        """Get current module weights"""
        return self.weights.copy()
    
    def get_thresholds(self) -> Dict[str, float]:
        """Get risk level thresholds"""
        return self.thresholds.copy()