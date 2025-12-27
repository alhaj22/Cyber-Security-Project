"""
PhishRadar Analyzer - Expert Main Analysis Engine
Coordinates all modules with comprehensive error handling and graceful degradation
"""

from datetime import datetime
from typing import Dict, Optional
import traceback

try:
    from .url_parser import URLParser
    from .whois_lookup import WHOISLookup
    from .ssl_checker import SSLChecker
    from .brand_detector import BrandDetector
    from .tld_checker import TLDChecker
    from .dns_info import DNSInfo
    from .score_engine import ScoreEngine
    from .utils import logger, timing_decorator, url_validator, report_generator
    
    IMPORTS_SUCCESS = True
    logger.info("✓ All core modules imported successfully")
except ImportError as e:
    logger.error(f"✗ Failed to import core modules: {e}")
    IMPORTS_SUCCESS = False
    # Fallback for basic functionality
    logger = None
    timing_decorator = lambda f: f


class PhishRadarAnalyzer:
    """
    Main phishing detection analyzer with graceful degradation
    
    Features:
    - Multi-layer security analysis
    - Graceful module failure handling
    - Comprehensive error recovery
    - Detailed logging and reporting
    """

    def __init__(self):
        """Initialize all analysis modules with error handling"""
        
        if not IMPORTS_SUCCESS:
            raise RuntimeError("Core modules failed to import. Check dependencies.")
        
        self.modules_status = {}
        self.initialized_modules = {}
        
        # Initialize URL Parser (Required - Most critical)
        try:
            self.url_parser = URLParser()
            self.modules_status['url_parser'] = 'OK'
            self.initialized_modules['url_parser'] = self.url_parser
            logger.info("✓ URL Parser initialized")
        except Exception as e:
            logger.error(f"✗ URL Parser failed: {e}")
            self.modules_status['url_parser'] = f'FAILED: {str(e)}'
            raise RuntimeError("URL Parser is required but failed to initialize")
        
        # Initialize WHOIS Lookup (Important)
        try:
            self.whois_lookup = WHOISLookup()
            self.modules_status['whois_lookup'] = 'OK'
            self.initialized_modules['whois'] = self.whois_lookup
            logger.info("✓ WHOIS Lookup initialized")
        except Exception as e:
            logger.warning(f"⚠ WHOIS Lookup failed: {e}")
            self.modules_status['whois_lookup'] = f'FAILED: {str(e)}'
            self.whois_lookup = None
        
        # Initialize SSL Checker (Important)
        try:
            self.ssl_checker = SSLChecker()
            self.modules_status['ssl_checker'] = 'OK'
            self.initialized_modules['ssl'] = self.ssl_checker
            logger.info("✓ SSL Checker initialized")
        except Exception as e:
            logger.warning(f"⚠ SSL Checker failed: {e}")
            self.modules_status['ssl_checker'] = f'FAILED: {str(e)}'
            self.ssl_checker = None
        
        # Initialize Brand Detector (Critical for phishing detection)
        try:
            self.brand_detector = BrandDetector()
            self.modules_status['brand_detector'] = 'OK'
            self.initialized_modules['brand'] = self.brand_detector
            logger.info("✓ Brand Detector initialized")
        except Exception as e:
            logger.warning(f"⚠ Brand Detector failed: {e}")
            self.modules_status['brand_detector'] = f'FAILED: {str(e)}'
            self.brand_detector = None
        
        # Initialize TLD Checker (Important)
        try:
            self.tld_checker = TLDChecker()
            self.modules_status['tld_checker'] = 'OK'
            self.initialized_modules['tld'] = self.tld_checker
            logger.info("✓ TLD Checker initialized")
        except Exception as e:
            logger.warning(f"⚠ TLD Checker failed: {e}")
            self.modules_status['tld_checker'] = f'FAILED: {str(e)}'
            self.tld_checker = None
        
        # Initialize DNS Info (Optional - can be slow)
        try:
            self.dns_info = DNSInfo()
            self.modules_status['dns_info'] = 'OK'
            self.initialized_modules['dns'] = self.dns_info
            logger.info("✓ DNS Info initialized")
        except Exception as e:
            logger.warning(f"⚠ DNS Info failed: {e}")
            self.modules_status['dns_info'] = f'FAILED: {str(e)}'
            self.dns_info = None
        
        # Initialize Score Engine (Required)
        try:
            self.score_engine = ScoreEngine()
            self.modules_status['score_engine'] = 'OK'
            self.initialized_modules['score'] = self.score_engine
            logger.info("✓ Score Engine initialized")
        except Exception as e:
            logger.error(f"✗ Score Engine failed: {e}")
            self.modules_status['score_engine'] = f'FAILED: {str(e)}'
            raise RuntimeError("Score Engine is required but failed to initialize")
        
        # Log initialization summary
        total_modules = len(self.modules_status)
        successful = sum(1 for s in self.modules_status.values() if s == 'OK')
        
        logger.info("=" * 80)
        logger.info(f"PhishRadar Analyzer Initialized: {successful}/{total_modules} modules OK")
        logger.info("=" * 80)
        
        for module, status in self.modules_status.items():
            if status == 'OK':
                logger.info(f"  ✓ {module}: {status}")
            else:
                logger.warning(f"  ✗ {module}: {status}")
        
        logger.info("=" * 80)

    @timing_decorator
    def analyze(self, url: str, deep_scan: bool = True) -> Dict:
        """
        Perform comprehensive phishing analysis
        
        Args:
            url: URL to analyze
            deep_scan: Enable DNS/IP analysis (slower but thorough)
            
        Returns:
            Comprehensive analysis report dictionary
        """
        
        logger.info("=" * 80)
        logger.info(f"Starting analysis for: {url}")
        logger.info(f"Scan mode: {'DEEP' if deep_scan else 'QUICK'}")
        logger.info("=" * 80)
        
        analysis_start = datetime.now()

        # ==================== PHASE 0: URL VALIDATION ====================
        
        logger.info("Phase 0: URL Validation")
        
        if not url or not isinstance(url, str):
            logger.warning("Invalid input: URL is None or not a string")
            return self._invalid_url_result(url or "", "URL must be a non-empty string")
        
        url = url.strip()
        
        if not url_validator.is_valid_url(url):
            logger.warning(f"URL validation failed: {url}")
            return self._invalid_url_result(url, "Invalid URL format")

        try:
            # ==================== PHASE 1: URL PARSING ====================
            
            logger.info("Phase 1: URL Analysis & Parsing")
            
            
            try:
                url_analysis = self.url_parser.parse(url)
                
                if not url_analysis.get("is_valid"):
                    error_msg = url_analysis.get("error", "URL parsing failed")
                    logger.warning(f"URL parsing failed: {error_msg}")
                    return self._invalid_url_result(url, error_msg)
                
                logger.info(f"✓ URL parsed successfully")
                logger.info(f"  Domain: {url_analysis.get('domain')}")
                logger.info(f"  TLD: {url_analysis.get('suffix')}")
                
            except Exception as e:
                logger.error(f"URL parsing exception: {e}", exc_info=True)
                return self._error_result(url, f"URL parsing failed: {str(e)}")

            # Extract key components
            domain = url_analysis.get("registered_domain") or url_analysis.get("domain")
            tld = url_analysis.get("suffix")
            path = url_analysis.get("path", "")
            
            if not domain:
                logger.warning("No domain extracted from URL")
                return self._invalid_url_result(url, "Unable to extract domain from URL")

            # ==================== PHASE 2: BRAND DETECTION ====================
            
            logger.info("Phase 2: Brand Impersonation Detection")
            
            if self.brand_detector:
                try:
                    brand_analysis = self.brand_detector.detect(url, domain, path)
                    logger.info(f"✓ Brand detection complete")
                    
                    if brand_analysis.get("detected_brands"):
                        brands = brand_analysis.get("detected_brands", [])
                        logger.info(f"  Brands detected: {', '.join(brands)}")
                    
                except Exception as e:
                    logger.warning(f"Brand detection failed: {e}")
                    brand_analysis = {
                        "error": "Brand detection unavailable",
                        "detected_brands": [],
                        "risk_score": 0
                    }
            else:
                logger.warning("Brand detector not available")
                brand_analysis = {
                    "error": "Brand detector not initialized",
                    "detected_brands": [],
                    "risk_score": 0
                }

            # ==================== PHASE 3: TLD ANALYSIS ====================
            
            logger.info("Phase 3: TLD Reputation Analysis")
            
            if self.tld_checker and tld:
                try:
                    tld_analysis = self.tld_checker.check(tld)
                    logger.info(f"✓ TLD analysis complete")
                    logger.info(f"  TLD: .{tld}")
                    logger.info(f"  Risk: {tld_analysis.get('risk_score', 0)}")
                    
                except Exception as e:
                    logger.warning(f"TLD check failed: {e}")
                    tld_analysis = {
                        "tld": tld,
                        "error": "TLD analysis failed",
                        "risk_score": 50  # Medium risk when unavailable
                    }
            else:
                logger.warning("TLD checker not available or no TLD found")
                tld_analysis = {
                    "tld": tld or "unknown",
                    "error": "TLD checker not initialized",
                    "risk_score": 50
                }

            # ==================== PHASE 4: WHOIS LOOKUP ====================
            
            logger.info("Phase 4: WHOIS & Domain Age Analysis")
            
            if self.whois_lookup and domain:
                try:
                    whois_analysis = self.whois_lookup.lookup(domain)
                    logger.info(f"✓ WHOIS lookup complete")
                    
                    if whois_analysis.get("success"):
                        age = whois_analysis.get("domain_age_days")
                        if age:
                            logger.info(f"  Domain age: {age} days ({age/365:.1f} years)")
                    
                except Exception as e:
                    logger.warning(f"WHOIS lookup failed: {e}")
                    whois_analysis = {
                        "domain": domain,
                        "success": False,
                        "error": "WHOIS information unavailable",
                        "domain_age_days": None,
                        "risk_score": 50  # Medium risk when unavailable
                    }
            else:
                logger.warning("WHOIS lookup not available")
                whois_analysis = {
                    "domain": domain,
                    "success": False,
                    "error": "WHOIS lookup not initialized",
                    "domain_age_days": None,
                    "risk_score": 50
                }

            # ==================== PHASE 5: SSL CERTIFICATE CHECK ====================
            
            logger.info("Phase 5: SSL/TLS Certificate Validation")
            
            if self.ssl_checker and domain:
                try:
                    ssl_analysis = self.ssl_checker.check(domain)
                    logger.info(f"✓ SSL check complete")
                    
                    if ssl_analysis.get("success"):
                        has_ssl = ssl_analysis.get("has_ssl", False)
                        logger.info(f"  SSL Status: {'✓ Present' if has_ssl else '✗ Missing'}")
                    
                except Exception as e:
                    logger.warning(f"SSL check failed: {e}")
                    ssl_analysis = {
                        "domain": domain,
                        "success": False,
                        "has_ssl": False,
                        "error": "SSL certificate check failed",
                        "risk_score": 60  # Higher risk when SSL unavailable
                    }
            else:
                logger.warning("SSL checker not available")
                ssl_analysis = {
                    "domain": domain,
                    "success": False,
                    "has_ssl": False,
                    "error": "SSL checker not initialized",
                    "risk_score": 60
                }

            # ==================== PHASE 6: DNS & IP ANALYSIS (OPTIONAL) ====================
            
            dns_analysis = {}
            
            if deep_scan and self.dns_info and domain:
                logger.info("Phase 6: DNS & IP Intelligence (Deep Scan)")
                
                try:
                    dns_analysis = self.dns_info.lookup(domain)
                    logger.info(f"✓ DNS analysis complete")
                    
                    if dns_analysis.get("success"):
                        ip_count = len(dns_analysis.get("ipv4_addresses", []))
                        logger.info(f"  IP addresses: {ip_count}")
                    
                except Exception as e:
                    logger.warning(f"DNS lookup failed: {e}")
                    dns_analysis = {
                        "domain": domain,
                        "success": False,
                        "error": "DNS resolution failed",
                        "risk_score": 40
                    }
            else:
                if not deep_scan:
                    logger.info("Phase 6: DNS Analysis skipped (quick scan mode)")
                else:
                    logger.warning("Phase 6: DNS analysis not available")
                
                dns_analysis = {
                    "domain": domain,
                    "success": False,
                    "error": "DNS analysis not performed",
                    "risk_score": 30  # Low penalty for skipping
                }

            # ==================== PHASE 7: COMBINE & SCORE ====================
            
            logger.info("Phase 7: Risk Score Calculation")
            
            # Compile all analysis results
            analysis_results = {
                "url_analysis": url_analysis,
                "brand": brand_analysis,
                "tld": tld_analysis,
                "whois": whois_analysis,
                "ssl": ssl_analysis,
                "dns": dns_analysis,
            }
            
            # Calculate comprehensive risk score
            try:
                risk_assessment = self.score_engine.calculate(analysis_results)
                logger.info(f"✓ Risk calculation complete")
                logger.info(f"  Overall Score: {risk_assessment['overall_risk_score']:.2f}/100")
                logger.info(f"  Risk Level: {risk_assessment['risk_level']}")
                logger.info(f"  Confidence: {risk_assessment['confidence']:.1f}%")
                
            except Exception as e:
                logger.error(f"Risk calculation failed: {e}", exc_info=True)
                risk_assessment = self._fallback_risk_assessment(analysis_results)

            # Calculate analysis duration
            analysis_duration = (datetime.now() - analysis_start).total_seconds()

            # ==================== BUILD FINAL REPORT ====================
            
            report = {
                "url": url,
                "analyzed_at": analysis_start.isoformat(),
                "analysis_duration_seconds": round(analysis_duration, 2),
                "scan_type": "deep" if deep_scan else "quick",
                "verdict": risk_assessment["risk_level"],
                "risk_score": risk_assessment["overall_risk_score"],
                "confidence": risk_assessment["confidence"],
                "threat_summary": risk_assessment["threat_summary"],
                "recommendation": risk_assessment["recommendation"],
                "critical_indicators": risk_assessment["critical_indicators"],
                "module_scores": risk_assessment["module_scores"],
                "weighted_contributions": risk_assessment["weighted_contributions"],
                "detailed_analysis": analysis_results,
                "metadata": {
                    "phishradar_version": "1.0.0",
                    "deep_scan_enabled": deep_scan,
                    "modules_used": list(self.initialized_modules.keys()),
                    "modules_status": self.modules_status
                },
            }

            logger.info("=" * 80)
            logger.info(f"✓ Analysis Complete!")
            logger.info(f"  Verdict: {report['verdict']}")
            logger.info(f"  Risk Score: {report['risk_score']:.2f}/100")
            logger.info(f"  Duration: {analysis_duration:.2f}s")
            logger.info("=" * 80)

            return report

        except Exception as e:
            logger.error("=" * 80)
            logger.error(f"✗ Fatal Analysis Error: {str(e)}")
            logger.error("=" * 80)
            logger.error(traceback.format_exc())
            
            return self._error_result(url, f"Analysis failed: {str(e)}")

    # ==================== HELPER METHODS ====================

    def _invalid_url_result(self, url: str, error: str = "Invalid URL format") -> Dict:
        """Return standardized invalid URL result"""
        logger.warning(f"Returning INVALID result: {error}")
        
        return {
            "url": url,
            "analyzed_at": datetime.now().isoformat(),
            "analysis_duration_seconds": 0,
            "scan_type": "none",
            "verdict": "INVALID",
            "risk_score": 0,
            "confidence": 0,
            "threat_summary": f"Unable to analyze: {error}",
            "recommendation": "Please provide a valid URL starting with http:// or https://",
            "critical_indicators": [],
            "module_scores": {},
            "weighted_contributions": {},
            "detailed_analysis": {},
            "metadata": {
                "phishradar_version": "1.0.0",
                "error": error
            }
        }

    def _error_result(self, url: str, error: str) -> Dict:
        """Return standardized error result"""
        logger.error(f"Returning ERROR result: {error}")
        
        return {
            "url": url,
            "analyzed_at": datetime.now().isoformat(),
            "analysis_duration_seconds": 0,
            "scan_type": "failed",
            "verdict": "ERROR",
            "risk_score": 0,
            "confidence": 0,
            "threat_summary": f"Analysis error: {error}",
            "recommendation": "Unable to complete analysis. Please try again later.",
            "critical_indicators": [],
            "module_scores": {},
            "weighted_contributions": {},
            "detailed_analysis": {},
            "metadata": {
                "phishradar_version": "1.0.0",
                "error": error
            }
        }

    def _fallback_risk_assessment(self, analysis_results: Dict) -> Dict:
        """
        Fallback risk assessment when score engine fails
        Uses simple heuristics
        """
        logger.warning("Using fallback risk assessment")
        
        # Count risk indicators
        risk_factors = 0
        
        # Check URL analysis
        url_suspicious = analysis_results.get("url_analysis", {}).get("suspicious_indicators", {})
        risk_factors += sum(1 for v in url_suspicious.values() if v)
        
        # Check brand detection
        if analysis_results.get("brand", {}).get("impersonation_likely"):
            risk_factors += 3
        
        # Check TLD
        tld_risk = analysis_results.get("tld", {}).get("risk_score", 0)
        if tld_risk > 70:
            risk_factors += 2
        elif tld_risk > 50:
            risk_factors += 1
        
        # Check WHOIS
        whois_data = analysis_results.get("whois", {})
        if whois_data.get("risk_indicators", {}).get("very_new_domain"):
            risk_factors += 2
        
        # Check SSL
        if not analysis_results.get("ssl", {}).get("has_ssl"):
            risk_factors += 2
        
        # Calculate score (rough estimate)
        risk_score = min(risk_factors * 10, 100)
        
        # Determine level
        if risk_score >= 75:
            level = "CRITICAL"
        elif risk_score >= 60:
            level = "HIGH"
        elif risk_score >= 40:
            level = "MEDIUM"
        elif risk_score >= 25:
            level = "LOW"
        else:
            level = "SAFE"
        
        return {
            "overall_risk_score": risk_score,
            "risk_level": level,
            "confidence": 50.0,  # Low confidence for fallback
            "threat_summary": f"Fallback assessment: {risk_factors} risk factors detected",
            "recommendation": "Manual verification recommended due to analysis limitations",
            "critical_indicators": [],
            "module_scores": {},
            "weighted_contributions": {}
        }

    def quick_scan(self, url: str) -> Dict:
        """
        Perform quick scan (no DNS/IP lookup)
        Faster but less comprehensive
        """
        return self.analyze(url, deep_scan=False)

    def batch_analyze(self, urls: list, deep_scan: bool = False) -> Dict[str, Dict]:
        """
        Analyze multiple URLs
        
        Args:
            urls: List of URLs to analyze
            deep_scan: Enable deep scan for all URLs
            
        Returns:
            Dictionary mapping URLs to their analysis results
        """
        logger.info(f"Starting batch analysis of {len(urls)} URLs")
        
        results = {}
        for i, url in enumerate(urls, 1):
            logger.info(f"Analyzing URL {i}/{len(urls)}: {url}")
            results[url] = self.analyze(url, deep_scan=deep_scan)
        
        logger.info(f"Batch analysis complete: {len(results)} URLs processed")
        return results

    def get_statistics(self) -> Dict:
        """Get analyzer statistics and module status"""
        return {
            "modules_active": len([s for s in self.modules_status.values() if s == 'OK']),
            "modules_total": len(self.modules_status),
            "modules_status": self.modules_status,
            "initialized_modules": list(self.initialized_modules.keys()),
            "brands_tracked": len(self.brand_detector.brands) if self.brand_detector else 0,
            "suspicious_tlds": len(self.tld_checker.suspicious_tlds) if self.tld_checker else 0,
            "cache_stats": {
                "whois": len(self.whois_lookup.cache) if self.whois_lookup else 0,
                "ssl": len(self.ssl_checker.cache) if self.ssl_checker else 0,
                "dns": len(self.dns_info.cache) if self.dns_info else 0,
            }
        }

    def clear_all_caches(self):
        """Clear all module caches"""
        if self.whois_lookup:
            self.whois_lookup.clear_cache()
        if self.ssl_checker:
            self.ssl_checker.clear_cache()
        if self.dns_info:
            self.dns_info.clear_cache()
        
        logger.info("All caches cleared")