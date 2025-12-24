"""
PhishRadar Analyzer - Main analysis engine
Coordinates all modules and generates comprehensive reports
"""

from datetime import datetime
from typing import Dict, Optional
from .url_parser import URLParser
from .whois_lookup import WHOISLookup
from .ssl_checker import SSLChecker
from .brand_detector import BrandDetector
from .tld_checker import TLDChecker
from .dns_info import DNSInfo
from .score_engine import ScoreEngine
from .utils import logger, timing_decorator, url_validator, report_generator

class PhishRadarAnalyzer:
    """Main phishing detection analyzer"""
    
    def __init__(self):
        # Initialize all modules
        self.url_parser = URLParser()
        self.whois_lookup = WHOISLookup()
        self.ssl_checker = SSLChecker()
        self.brand_detector = BrandDetector()
        self.tld_checker = TLDChecker()
        self.dns_info = DNSInfo()
        self.score_engine = ScoreEngine()
        
        logger.info("=" * 80)
        logger.info("PhishRadar Analyzer initialized - All modules ready")
        logger.info("=" * 80)
    
    @timing_decorator
    def analyze(self, url: str, deep_scan: bool = True) -> Dict:
        """
        Comprehensive phishing analysis
        
        Args:
            url: URL to analyze
            deep_scan: If True, performs DNS and IP lookups (slower but more thorough)
        
        Returns:
            Comprehensive analysis report
        """
        logger.info(f"Starting analysis for: {url}")
        analysis_start = datetime.now()
        
        # Validate URL
        if not url_validator.is_valid_url(url):
            return self._invalid_url_result(url)
        
        try:
            # 1. URL Parsing and Pattern Analysis
            logger.info("Phase 1: URL Analysis")
            url_analysis = self.url_parser.parse(url)
            
            if not url_analysis.get('is_valid'):
                return self._invalid_url_result(url, url_analysis.get('error'))
            
            # Extract components
            domain = url_analysis.get('registered_domain') or url_analysis.get('domain')
            tld = url_analysis.get('suffix')
            path = url_analysis.get('path', '')
            
            # 2. Brand Detection
            logger.info("Phase 2: Brand Detection")
            brand_analysis = self.brand_detector.detect(url, domain, path)
            
            # 3. TLD Analysis
            logger.info("Phase 3: TLD Analysis")
            tld_analysis = self.tld_checker.check(tld) if tld else {}
            
            # 4. WHOIS Lookup
            logger.info("Phase 4: WHOIS Lookup")
            whois_analysis = self.whois_lookup.lookup(domain) if domain else {}
            
            # 5. SSL Certificate Check
            logger.info("Phase 5: SSL Certificate Check")
            ssl_analysis = self.ssl_checker.check(domain) if domain else {}
            
            # 6. DNS & IP Analysis (optional, can be slow)
            dns_analysis = {}
            if deep_scan and domain:
                logger.info("Phase 6: DNS & IP Analysis")
                dns_analysis = self.dns_info.lookup(domain)
            else:
                logger.info("Phase 6: DNS Analysis skipped (quick scan mode)")
            
            # Compile all analysis results
            analysis_results = {
                'url_analysis': url_analysis,
                'brand': brand_analysis,
                'tld': tld_analysis,
                'whois': whois_analysis,
                'ssl': ssl_analysis,
                'dns': dns_analysis
            }
            
            # 7. Calculate Risk Score
            logger.info("Phase 7: Risk Score Calculation")
            risk_assessment = self.score_engine.calculate(analysis_results)
            
            # Calculate analysis time
            analysis_duration = (datetime.now() - analysis_start).total_seconds()
            
            # Build final report
            report = {
                'url': url,
                'analyzed_at': analysis_start.isoformat(),
                'analysis_duration_seconds': round(analysis_duration, 2),
                'scan_type': 'deep' if deep_scan else 'quick',
                'verdict': risk_assessment['risk_level'],
                'risk_score': risk_assessment['overall_risk_score'],
                'confidence': risk_assessment['confidence'],
                'threat_summary': risk_assessment['threat_summary'],
                'recommendation': risk_assessment['recommendation'],
                'critical_indicators': risk_assessment['critical_indicators'],
                'module_scores': risk_assessment['module_scores'],
                'weighted_contributions': risk_assessment['weighted_contributions'],
                'detailed_analysis': analysis_results,
                'metadata': {
                    'phishradar_version': '1.0.0',
                    'deep_scan_enabled': deep_scan
                }
            }
            
            logger.info(
                f"Analysis complete: {risk_assessment['risk_level']} "
                f"(score: {risk_assessment['overall_risk_score']:.2f}) "
                f"in {analysis_duration:.2f}s"
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Analysis failed for {url}: {e}", exc_info=True)
            return self._error_result(url, str(e))
    
    def quick_scan(self, url: str) -> Dict:
        """
        Quick phishing scan (skips slow DNS/IP lookups)
        Faster but less comprehensive
        """
        return self.analyze(url, deep_scan=False)
    
    def batch_analyze(self, urls: list, deep_scan: bool = False) -> Dict[str, Dict]:
        """
        Analyze multiple URLs
        Returns dict mapping URLs to their analysis results
        """
        logger.info(f"Starting batch analysis of {len(urls)} URLs")
        
        results = {}
        for i, url in enumerate(urls, 1):
            logger.info(f"Analyzing URL {i}/{len(urls)}: {url}")
            results[url] = self.analyze(url, deep_scan=deep_scan)
        
        logger.info(f"Batch analysis complete: {len(results)} URLs processed")
        return results
    
    def export_report(self, analysis_result: Dict, output_dir: str = "reports") -> Optional[str]:
        """Export analysis report to file"""
        return report_generator.save_report(analysis_result, output_dir)
    
    def print_summary(self, analysis_result: Dict):
        """Print formatted analysis summary to console"""
        print(report_generator.format_result(analysis_result))
    
    def _invalid_url_result(self, url: str, error: str = "Invalid URL format") -> Dict:
        """Return result for invalid URL"""
        return {
            'url': url,
            'analyzed_at': datetime.now().isoformat(),
            'verdict': 'INVALID',
            'risk_score': 0,
            'confidence': 0,
            'threat_summary': f"Unable to analyze: {error}",
            'recommendation': "Provide a valid URL starting with http:// or https://",
            'critical_indicators': [],
            'error': error,
            'detailed_analysis': {}
        }
    
    def _error_result(self, url: str, error: str) -> Dict:
        """Return error result"""
        return {
            'url': url,
            'analyzed_at': datetime.now().isoformat(),
            'verdict': 'ERROR',
            'risk_score': 0,
            'confidence': 0,
            'threat_summary': f"Analysis error: {error}",
            'recommendation': "Unable to complete analysis. Try again later.",
            'critical_indicators': [],
            'error': error,
            'detailed_analysis': {}
        }
    
    def clear_all_caches(self):
        """Clear all module caches"""
        self.whois_lookup.clear_cache()
        self.ssl_checker.clear_cache()
        self.dns_info.clear_cache()
        logger.info("All caches cleared")
    
    def get_statistics(self) -> Dict:
        """Get analyzer statistics"""
        return {
            'modules_active': 6,
            'brands_tracked': len(self.brand_detector.brands),
            'suspicious_tlds': len(self.tld_checker.suspicious_tlds),
            'cache_stats': {
                'whois': len(self.whois_lookup.cache),
                'ssl': len(self.ssl_checker.cache),
                'dns': len(self.dns_info.cache)
            }
        }