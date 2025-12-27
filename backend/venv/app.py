"""
PhishRadar Flask Backend - Complete Expert Implementation
Sends ALL analysis details to frontend with proper formatting
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from typing import Dict, Any
import logging
from datetime import datetime
import traceback

from core import PhishRadarAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# CORS configuration
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"],
        "supports_credentials": False
    }
})

# Initialize analyzer
try:
    analyzer = PhishRadarAnalyzer()
    logger.info("✓ PhishRadar Analyzer initialized successfully")
except Exception as e:
    logger.error(f"✗ Failed to initialize analyzer: {e}")
    analyzer = None

# Constants
MAX_URL_LENGTH = 2000


def normalize_for_frontend(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize backend analysis report for frontend with ALL details
    
    Args:
        report: Raw analysis report from PhishRadarAnalyzer
        
    Returns:
        Complete normalized response with all scan details
    """
    
    # Extract basic info
    verdict = report.get("verdict", "ERROR")
    url = report.get("url", "")
    threat_summary = report.get("threat_summary", "")
    risk_score = report.get("risk_score", 0)
    confidence = report.get("confidence", 0)
    
    # Map verdict to frontend status
    status_mapping = {
        "SAFE": "SAFE",
        "LOW": "SAFE",
        "MEDIUM": "SUSPICIOUS",
        "HIGH": "NOT SAFE",
        "CRITICAL": "NOT SAFE",
        "INVALID": "INVALID",
        "ERROR": "ERROR"
    }
    
    status = status_mapping.get(verdict, "SUSPICIOUS")
    
    # Generate user-friendly reason
    if verdict == "INVALID":
        reason = "Invalid or malformed URL provided."
    elif verdict == "ERROR":
        reason = report.get("error", "Analysis failed. Please try again.")
    elif threat_summary:
        reason = threat_summary
    else:
        reason_map = {
            "SAFE": "No significant security threats detected. Website appears legitimate.",
            "LOW": "Minor concerns detected but generally safe. Proceed with normal caution.",
            "MEDIUM": "Suspicious patterns detected. Verify the website's legitimacy before proceeding.",
            "HIGH": "High risk of phishing. Avoid entering sensitive information.",
            "CRITICAL": "Critical threat detected. Do not visit or interact with this website."
        }
        reason = reason_map.get(verdict, "Security analysis completed.")
    
    # Build base response
    response = {
        "url": url,
        "status": status,
        "reason": reason,
        "risk_score": round(risk_score, 2) if risk_score else 0,
        "confidence": round(confidence, 2) if confidence else 0,
        "analysis_timestamp": report.get("analyzed_at", datetime.utcnow().isoformat()),
        "scan_type": report.get("scan_type", "quick"),
        "analysis_duration": report.get("analysis_duration_seconds", 0),
    }
    
    # Add module scores
    module_scores = report.get("module_scores", {})
    if module_scores:
        response["module_scores"] = {
            k: round(v, 2) for k, v in module_scores.items()
        }
    else:
        response["module_scores"] = {}
    
    # Add weighted contributions
    weighted_contributions = report.get("weighted_contributions", {})
    if weighted_contributions:
        response["weighted_contributions"] = {
            k: round(v, 2) for k, v in weighted_contributions.items()
        }
    
    # Add critical indicators
    critical_indicators = report.get("critical_indicators", [])
    if critical_indicators:
        response["critical_indicators"] = [
            {
                "severity": ind.get("severity"),
                "category": ind.get("category"),
                "description": ind.get("description"),
                "impact": ind.get("impact")
            }
            for ind in critical_indicators[:10]  # Limit to top 10
        ]
    else:
        response["critical_indicators"] = []
    
    # Add risk level details
    response["risk_level"] = {
        "verdict": verdict,
        "description": f"Risk Level: {verdict}"
    }
    
    # Add recommendation
    recommendation = report.get("recommendation", "")
    if recommendation:
        response["recommendation"] = recommendation
    else:
        rec_map = {
            "SAFE": "Website appears safe. Always verify you're on the correct domain before entering credentials.",
            "SUSPICIOUS": "Exercise caution. Verify the website through official channels before providing any information.",
            "NOT SAFE": "Do not proceed. This website shows strong indicators of phishing or malicious activity.",
            "INVALID": "Please provide a valid URL starting with http:// or https://",
            "ERROR": "Unable to analyze the website. Try again or contact support if the issue persists."
        }
        response["recommendation"] = rec_map.get(status, "Proceed with caution and verify the website's legitimacy.")
    
    # ==================== DETAILED ANALYSIS ====================
    
    detailed_analysis = report.get("detailed_analysis", {})
    response["detailed_analysis"] = {}
    
    # 1. URL ANALYSIS DETAILS
    url_analysis = detailed_analysis.get("url_analysis", {})
    if url_analysis:
        response["detailed_analysis"]["url"] = {
            "domain": url_analysis.get("domain", "N/A"),
            "subdomain": url_analysis.get("subdomain", "N/A"),
            "tld": url_analysis.get("suffix", "N/A"),
            "path": url_analysis.get("path", "/"),
            "url_length": url_analysis.get("url_length", 0),
            "entropy": round(url_analysis.get("entropy", 0), 2),
            "suspicious_indicators": url_analysis.get("suspicious_indicators", {}),
            "has_unicode": url_analysis.get("has_unicode", False),
            "subdomain_count": url_analysis.get("subdomain_count", 0)
        }
    
    # 2. BRAND DETECTION DETAILS
    brand_analysis = detailed_analysis.get("brand", {})
    if brand_analysis:
        response["detailed_analysis"]["brand"] = {
            "detected_brands": brand_analysis.get("detected_brands", []),
            "brand_count": brand_analysis.get("brand_count", 0),
            "impersonation_likely": brand_analysis.get("impersonation_likely", False),
            "legitimate_brand": brand_analysis.get("legitimate_brand"),
            "typosquatting": brand_analysis.get("typosquatting", []),
            "high_value_target": brand_analysis.get("high_value_target", False)
        }
    
    # 3. TLD ANALYSIS DETAILS
    tld_analysis = detailed_analysis.get("tld", {})
    if tld_analysis:
        response["detailed_analysis"]["tld"] = {
            "tld": tld_analysis.get("tld", "N/A"),
            "category": tld_analysis.get("category", "unknown"),
            "reputation": tld_analysis.get("reputation", "NEUTRAL"),
            "risk_score": round(tld_analysis.get("risk_score", 0), 2),
            "is_suspicious": tld_analysis.get("risk_indicators", {}).get("is_suspicious", False),
            "is_free_tld": tld_analysis.get("risk_indicators", {}).get("free_tld", False)
        }
    
    # 4. WHOIS DETAILS
    whois_analysis = detailed_analysis.get("whois", {})
    if whois_analysis:
        response["detailed_analysis"]["whois"] = {
            "domain_age_days": whois_analysis.get("domain_age_days"),
            "domain_age_years": whois_analysis.get("domain_age_years"),
            "creation_date": whois_analysis.get("creation_date"),
            "expiration_date": whois_analysis.get("expiration_date"),
            "registrar": whois_analysis.get("registrar"),
            "is_new_domain": whois_analysis.get("risk_indicators", {}).get("newly_registered", False),
            "very_new_domain": whois_analysis.get("risk_indicators", {}).get("very_new_domain", False),
            "privacy_protected": whois_analysis.get("risk_indicators", {}).get("privacy_protected", False),
            "success": whois_analysis.get("success", False)
        }
    
    # 5. SSL CERTIFICATE DETAILS
    ssl_analysis = detailed_analysis.get("ssl", {})
    if ssl_analysis:
        response["detailed_analysis"]["ssl"] = {
            "has_ssl": ssl_analysis.get("has_ssl", False),
            "is_valid": ssl_analysis.get("success", False),
            "issuer": ssl_analysis.get("issuer", {}),
            "valid_from": ssl_analysis.get("valid_from"),
            "valid_until": ssl_analysis.get("valid_until"),
            "days_remaining": ssl_analysis.get("days_remaining"),
            "is_expired": ssl_analysis.get("is_expired", False),
            "is_self_signed": ssl_analysis.get("is_self_signed", False),
            "is_free_cert": ssl_analysis.get("is_free_cert", False),
            "domain_matches": ssl_analysis.get("domain_matches", False)
        }
    
    # 6. DNS DETAILS
    dns_analysis = detailed_analysis.get("dns", {})
    if dns_analysis and dns_analysis.get("success"):
        response["detailed_analysis"]["dns"] = {
            "ip_addresses": dns_analysis.get("ipv4_addresses", []),
            "ip_count": dns_analysis.get("ip_count", 0),
            "mx_records": dns_analysis.get("mx_records", []),
            "ns_records": dns_analysis.get("ns_records", []),
            "has_nameservers": len(dns_analysis.get("ns_records", [])) > 0,
            "has_mail_servers": len(dns_analysis.get("mx_records", [])) > 0
        }
    
    # ==================== METADATA ====================
    
    metadata = report.get("metadata", {})
    response["metadata"] = {
        "version": metadata.get("phishradar_version", "1.0.0"),
        "deep_scan": metadata.get("deep_scan_enabled", False),
        "modules_used": metadata.get("modules_used", []),
        "modules_status": metadata.get("modules_status", {})
    }
    
    # ==================== SCAN SUMMARY ====================
    
    # Count positive indicators
    total_indicators = 0
    positive_indicators = 0
    
    if url_analysis:
        suspicious = url_analysis.get("suspicious_indicators", {})
        total_indicators += len(suspicious)
        positive_indicators += sum(1 for v in suspicious.values() if v)
    
    response["scan_summary"] = {
        "total_checks": len(module_scores),
        "checks_passed": sum(1 for v in module_scores.values() if v < 40),
        "checks_warning": sum(1 for v in module_scores.values() if 40 <= v < 70),
        "checks_failed": sum(1 for v in module_scores.values() if v >= 70),
        "suspicious_indicators_found": positive_indicators,
        "critical_issues_found": len(critical_indicators)
    }
    
    return response


def validate_url_request(data: Dict[str, Any]) -> tuple:
    """
    Validate request data
    
    Returns:
        (is_valid, url_or_error)
    """
    if not data:
        return False, "Request body is required"
    
    if "url" not in data:
        return False, "URL parameter is required"
    
    url = data["url"]
    
    if not isinstance(url, str):
        return False, "URL must be a string"
    
    url = url.strip()
    if not url:
        return False, "URL cannot be empty"
    
    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    return True, url


# ==================== ROUTES ====================

@app.route("/", methods=["GET"])
def index():
    """Root endpoint"""
    return jsonify({
        "service": "PhishRadar API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "scan": "POST /scan",
            "health": "GET /health",
            "info": "GET /"
        }
    }), 200


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    
    # Check analyzer status
    analyzer_status = "initialized" if analyzer else "failed"
    
    # Get module statistics if analyzer is available
    module_stats = {}
    if analyzer:
        try:
            stats = analyzer.get_statistics()
            module_stats = {
                "modules_active": stats.get("modules_active", 0),
                "modules_total": stats.get("modules_total", 0),
                "modules_status": stats.get("modules_status", {})
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
    
    return jsonify({
        "status": "healthy" if analyzer else "degraded",
        "service": "PhishRadar API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "analyzer": analyzer_status,
        "modules": module_stats
    }), 200


@app.route("/scan", methods=["POST", "OPTIONS"])
@app.route("/api/scan", methods=["POST", "OPTIONS"])
def scan_url():
    """
    Scan a URL for phishing indicators
    Returns COMPLETE analysis details
    """
    
    # Handle OPTIONS for CORS preflight
    if request.method == "OPTIONS":
        return "", 200
    
    # Check if analyzer is initialized
    if not analyzer:
        logger.error("Analyzer not initialized")
        return jsonify({
            "url": "",
            "status": "ERROR",
            "reason": "Service initialization failed. Please contact support.",
            "risk_score": 0,
            "confidence": 0
        }), 500
    
    try:
        # Parse request
        data = request.get_json(silent=True)
        logger.info(f"📥 Received scan request: {data}")
        
        # Validate request
        is_valid, url_or_error = validate_url_request(data)
        if not is_valid:
            logger.warning(f"⚠️ Invalid request: {url_or_error}")
            return jsonify({
                "url": data.get("url", "") if data else "",
                "status": "INVALID",
                "reason": url_or_error,
                "risk_score": 0,
                "confidence": 0
            }), 400
        
        url = url_or_error
        deep_scan = data.get("deep_scan", False)
        
        logger.info(f"🔍 Scanning URL: {url} (deep_scan={deep_scan})")
        
        # Perform analysis
        try:
            raw_report = analyzer.analyze(url, deep_scan=deep_scan)
            logger.info(f"✅ Analysis completed: {raw_report.get('verdict')} (score: {raw_report.get('risk_score'):.2f})")
        except Exception as e:
            logger.error(f"❌ Analysis failed for {url}: {str(e)}")
            logger.error(traceback.format_exc())
            
            return jsonify({
                "url": url,
                "status": "ERROR",
                "reason": f"Analysis failed: {str(e)}",
                "risk_score": 0,
                "confidence": 0,
                "detailed_analysis": {},
                "metadata": {
                    "error": str(e)
                }
            }), 500
        
        # Normalize response with ALL details
        response = normalize_for_frontend(raw_report)
        logger.info(f"📤 Response prepared: {response['status']}")
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"💥 Unexpected error in scan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        
        return jsonify({
            "url": "",
            "status": "ERROR",
            "reason": "An unexpected error occurred. Please try again.",
            "risk_score": 0,
            "confidence": 0
        }), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get system statistics"""
    try:
        if not analyzer:
            return jsonify({"error": "Service not available"}), 500
        
        stats = analyzer.get_statistics()
        return jsonify({
            "status": "success",
            "data": stats,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "ERROR",
        "reason": "Endpoint not found. Use /scan or /api/scan",
        "timestamp": datetime.utcnow().isoformat()
    }), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        "status": "ERROR",
        "reason": "Internal server error",
        "timestamp": datetime.utcnow().isoformat()
    }), 500


# Main entry point
if __name__ == "__main__":
    print("=" * 80)
    print("🔍 PhishRadar API Server Starting...")
    print("=" * 80)
    print(f"Analyzer Status: {'✓ Initialized' if analyzer else '✗ Failed'}")
    print("\n📡 Available Endpoints:")
    print("  POST /scan          - Scan single URL (COMPLETE DETAILS)")
    print("  POST /api/scan      - Alternative endpoint")
    print("  GET  /health        - Health check with module status")
    print("  GET  /api/stats     - System statistics")
    print("\n⚙️  Server Configuration:")
    print("  Host: 0.0.0.0")
    print("  Port: 5000")
    print("  CORS: Enabled (all origins)")
    print("  Debug: True")
    print("\n📊 Response includes:")
    print("  ✓ Risk score & confidence")
    print("  ✓ Module scores breakdown")
    print("  ✓ Critical indicators")
    print("  ✓ URL analysis details")
    print("  ✓ Brand detection results")
    print("  ✓ TLD reputation")
    print("  ✓ WHOIS information")
    print("  ✓ SSL certificate details")
    print("  ✓ DNS records")
    print("  ✓ Scan summary statistics")
    print("=" * 80)
    
    try:
        app.run(
            host="0.0.0.0",
            port=5000,
            debug=True,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        print(f"\n✗ ERROR: {e}")
        print("\n🔧 Troubleshooting:")
        print("  1. Check if port 5000 is already in use")
        print("  2. Verify all dependencies are installed")
        print("  3. Check if core modules are accessible")
        print("  4. Run: pip install -r requirements.txt")