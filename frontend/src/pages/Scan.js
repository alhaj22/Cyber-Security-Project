/**
 * PhishRadar Scan Component - Complete Expert Implementation
 * Displays ALL analysis details beautifully
 */

import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { scanURL } from "../services/api";


function Scan() {
  const location = useLocation();
  const prefilledURL = location.state?.url || "";

  const [url, setUrl] = useState(prefilledURL);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");

  // Validate URL
  const isValidURL = (value) => {
    try {
      const u = new URL(value.startsWith("http") ? value : `https://${value}`);
      return u.hostname.includes(".");
    } catch {
      return false;
    }
  };

  // Handle scan
  const handleScan = async () => {
    if (!url.trim()) {
      setResult({ 
        status: "INVALID", 
        reason: "URL cannot be empty.",
        verdict: "INVALID"
      });
      return;
    }

    if (!isValidURL(url)) {
      setResult({ 
        status: "INVALID", 
        reason: "Invalid URL format.",
        verdict: "INVALID"
      });
      return;
    }

    try {
      setLoading(true);
      setResult(null);
      setActiveTab("overview");

      const response = await scanURL(url);
      console.log("📊 FULL BACKEND RESPONSE:", response.data);
      setResult(response.data);

    } catch (error) {
      console.error("❌ Scan error:", error);
      setResult({
        status: "ERROR",
        reason: "Backend unavailable or scan failed.",
        verdict: "ERROR"
      });
    } finally {
      setLoading(false);
    }
  };

  // Auto-scan if URL prefilled
  useEffect(() => {
    if (prefilledURL) handleScan();
    // eslint-disable-next-line
  }, []);

  // Get status color
  const getStatusColor = (status) => {
    const colors = {
      "SAFE": "#16a34a",
      "SUSPICIOUS": "#f59e0b",
      "NOT SAFE": "#dc2626",
      "INVALID": "#64748b",
      "ERROR": "#64748b"
    };
    return colors[status] || "#64748b";
  };

  // Get verdict color (for detailed analysis)
  const getVerdictColor = (verdict) => {
    const colors = {
      "SAFE": "#16a34a",
      "LOW": "#84cc16",
      "MEDIUM": "#f59e0b",
      "HIGH": "#f97316",
      "CRITICAL": "#dc2626",
      "INVALID": "#64748b",
      "ERROR": "#64748b"
    };
    return colors[verdict] || "#64748b";
  };

  // Format date
  const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    try {
      return new Date(dateString).toLocaleDateString();
    } catch {
      return dateString;
    }
  };

  // Extract detailed analysis
  const d = result?.detailed_analysis || {};

  return (
    <>
      <Navbar />

      <section className="scan-section">
        <div className="scan-container">
          <h1>🔍 Website Security Scanner</h1>
          <p className="subtitle">Comprehensive phishing and security analysis</p>

          {/* Input Section */}
          <div className="input-group">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleScan()}
              placeholder="Enter URL (e.g., https://example.com)"
              disabled={loading}
              className="url-input"
            />
            <button 
              onClick={handleScan} 
              disabled={loading || !url.trim()}
              className={`scan-button ${loading ? "loading" : ""}`}
            >
              {loading ? (
                <>
                  <span className="spinner"></span>
                  Scanning...
                </>
              ) : (
                <>
                  <span>🔍</span>
                  Scan Website
                </>
              )}
            </button>
          </div>

          {/* Results Section */}
          {result && !loading && (
            <div className="results-container">
              
              {/* Main Verdict Card */}
              <div 
                className="verdict-card"
                style={{ 
                  borderLeftColor: getStatusColor(result.status),
                  backgroundColor: `${getStatusColor(result.status)}10`
                }}
              >
                <div className="verdict-header">
                  <h2 style={{ color: getStatusColor(result.status) }}>
                    {result.status}
                  </h2>
                  {result.risk_score !== undefined && (
                    <div className="risk-badge">
                      Risk: {result.risk_score.toFixed(1)}/100
                    </div>
                  )}
                </div>

                <p className="verdict-reason">{result.reason}</p>

                {result.confidence !== undefined && (
                  <div className="confidence-bar">
                    <span>Confidence: {result.confidence.toFixed(0)}%</span>
                    <div className="progress">
                      <div 
                        className="progress-fill" 
                        style={{ 
                          width: `${result.confidence}%`,
                          backgroundColor: getStatusColor(result.status)
                        }}
                      ></div>
                    </div>
                  </div>
                )}

                {result.recommendation && (
                  <div className="recommendation">
                    <strong>💡 Recommendation:</strong>
                    <p>{result.recommendation}</p>
                  </div>
                )}
              </div>


              {/* Module Scores */}
              {result.module_scores && Object.keys(result.module_scores).length > 0 && (
                <div className="module-scores-card">
                  <h3>📊 Security Check Results</h3>
                  <div className="module-grid">
                    {Object.entries(result.module_scores).map(([module, score]) => {
                      const scoreColor = score >= 70 ? "#dc2626" : 
                                       score >= 50 ? "#f59e0b" : 
                                       score >= 30 ? "#84cc16" : "#16a34a";
                      return (
                        <div key={module} className="module-item">
                          <div className="module-header">
                            <span className="module-name">
                              {module.replace(/_/g, " ").toUpperCase()}
                            </span>
                            <span className="module-score" style={{ color: scoreColor }}>
                              {score.toFixed(1)}
                            </span>
                          </div>
                          <div className="module-bar">
                            <div 
                              className="module-fill" 
                              style={{ 
                                width: `${score}%`,
                                backgroundColor: scoreColor
                              }}
                            ></div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Detailed Analysis Tabs */}
              {d && Object.keys(d).length > 0 && (
                <div className="detailed-analysis">
                  <h3>🔬 Detailed Analysis</h3>
                  
                  {/* Tabs */}
                  <div className="tabs">
                    <button 
                      className={activeTab === "overview" ? "active" : ""} 
                      onClick={() => setActiveTab("overview")}
                    >
                      Overview
                    </button>
                    {d.url && (
                      <button 
                        className={activeTab === "url" ? "active" : ""} 
                        onClick={() => setActiveTab("url")}
                      >
                        URL Analysis
                      </button>
                    )}
                    {d.ssl && (
                      <button 
                        className={activeTab === "ssl" ? "active" : ""} 
                        onClick={() => setActiveTab("ssl")}
                      >
                        SSL/HTTPS
                      </button>
                    )}
                    {d.whois && (
                      <button 
                        className={activeTab === "whois" ? "active" : ""} 
                        onClick={() => setActiveTab("whois")}
                      >
                        WHOIS
                      </button>
                    )}
                    {d.brand && (
                      <button 
                        className={activeTab === "brand" ? "active" : ""} 
                        onClick={() => setActiveTab("brand")}
                      >
                        Brand Detection
                      </button>
                    )}
                    {d.tld && (
                      <button 
                        className={activeTab === "tld" ? "active" : ""} 
                        onClick={() => setActiveTab("tld")}
                      >
                        TLD Check
                      </button>
                    )}
                    {d.dns && (
                      <button 
                        className={activeTab === "dns" ? "active" : ""} 
                        onClick={() => setActiveTab("dns")}
                      >
                        DNS/Hosting
                      </button>
                    )}
                  </div>

                  {/* Tab Content */}
                  <div className="tab-content">
                    
                    {/* Overview Tab */}
                    {activeTab === "overview" && (
                      <div className="tab-panel">
                        <h4>📋 Scan Summary</h4>
                        {result.scan_summary && (
                          <div className="summary-grid">
                            <div className="summary-item">
                              <span className="label">Total Checks:</span>
                              <span className="value">{result.scan_summary.total_checks}</span>
                            </div>
                            <div className="summary-item pass">
                              <span className="label">✓ Passed:</span>
                              <span className="value">{result.scan_summary.checks_passed}</span>
                            </div>
                            <div className="summary-item warning">
                              <span className="label">⚠ Warnings:</span>
                              <span className="value">{result.scan_summary.checks_warning}</span>
                            </div>
                            <div className="summary-item fail">
                              <span className="label">✗ Failed:</span>
                              <span className="value">{result.scan_summary.checks_failed}</span>
                            </div>
                            <div className="summary-item">
                              <span className="label">Suspicious Indicators:</span>
                              <span className="value">{result.scan_summary.suspicious_indicators_found}</span>
                            </div>
                            <div className="summary-item">
                              <span className="label">Critical Issues:</span>
                              <span className="value">{result.scan_summary.critical_issues_found}</span>
                            </div>
                          </div>
                        )}

                        {result.metadata && (
                          <div className="metadata">
                            <h5>System Information</h5>
                            <p><strong>Scan Type:</strong> {result.scan_type}</p>
                            <p><strong>Analysis Duration:</strong> {result.analysis_duration}s</p>
                            <p><strong>Timestamp:</strong> {formatDate(result.analysis_timestamp)}</p>
                            {result.metadata.modules_used && (
                              <p><strong>Modules Used:</strong> {result.metadata.modules_used.join(", ")}</p>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* URL Analysis Tab */}
                    {activeTab === "url" && d.url && (
                      <div className="tab-panel">
                        <h4>🔗 URL Structure</h4>
                        <div className="detail-grid">
                          <div className="detail-item">
                            <strong>Domain:</strong> {d.url.domain || "N/A"}
                          </div>
                          <div className="detail-item">
                            <strong>Subdomain:</strong> {d.url.subdomain || "None"}
                          </div>
                          <div className="detail-item">
                            <strong>TLD:</strong> .{d.url.tld || "N/A"}
                          </div>
                          <div className="detail-item">
                            <strong>Path:</strong> {d.url.path || "/"}
                          </div>
                          <div className="detail-item">
                            <strong>URL Length:</strong> {d.url.url_length} characters
                          </div>
                          <div className="detail-item">
                            <strong>Entropy:</strong> {d.url.entropy?.toFixed(2) || "N/A"}
                          </div>
                          <div className="detail-item">
                            <strong>Subdomain Count:</strong> {d.url.subdomain_count}
                          </div>
                          <div className="detail-item">
                            <strong>Unicode Characters:</strong> {d.url.has_unicode ? "Yes ⚠️" : "No ✓"}
                          </div>
                        </div>

                        {d.url.suspicious_indicators && (
                          <>
                            <h5>🚨 Suspicious Indicators</h5>
                            <div className="indicators-list">
                              {Object.entries(d.url.suspicious_indicators).map(([key, value]) => (
                                <div key={key} className={`indicator-item ${value ? "alert" : "safe"}`}>
                                  <span>{value ? "⚠️" : "✓"}</span>
                                  <span>{key.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}</span>
                                  <span className="status">{value ? "Detected" : "Not Found"}</span>
                                </div>
                              ))}
                            </div>
                          </>
                        )}
                      </div>
                    )}

                    {/* WHOIS Tab */}
                    {activeTab === "whois" && d.whois && (
                      <div className="tab-panel">
                        <h4>🌐 Domain Registration Information</h4>
                        <div className="detail-grid">
                          <div className="detail-item">
                            <strong>Domain Age:</strong> {
                              d.whois.domain_age_days 
                                ? `${d.whois.domain_age_days} days (${d.whois.domain_age_years?.toFixed(2)} years)`
                                : "Unknown"
                            }
                          </div>
                          <div className="detail-item">
                            <strong>Creation Date:</strong> {formatDate(d.whois.creation_date)}
                          </div>
                          <div className="detail-item">
                            <strong>Expiration Date:</strong> {formatDate(d.whois.expiration_date)}
                          </div>
                          <div className="detail-item">
                            <strong>Registrar:</strong> {d.whois.registrar || "Unknown"}
                          </div>
                          <div className="detail-item">
                            <strong>Privacy Protected:</strong> {d.whois.privacy_protected ? "Yes" : "No"}
                          </div>
                          <div className="detail-item">
                            <strong>New Domain:</strong> {d.whois.is_new_domain ? "Yes ⚠️" : "No ✓"}
                          </div>
                          <div className="detail-item">
                            <strong>Very New:</strong> {d.whois.very_new_domain ? "Yes ⚠️" : "No ✓"}
                          </div>
                          <div className="detail-item">
                            <strong>Data Available:</strong> {d.whois.success ? "Yes ✓" : "No ✗"}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Brand Detection Tab */}
                    {activeTab === "brand" && d.brand && (
                      <div className="tab-panel">
                        <h4>🏷️ Brand Impersonation Analysis</h4>
                        
                        {d.brand.detected_brands && d.brand.detected_brands.length > 0 ? (
                          <>
                            <div className="alert warning">
                              <strong>⚠️ Brands Detected:</strong> {d.brand.detected_brands.join(", ")}
                            </div>
                            
                            <div className="detail-grid">
                              <div className="detail-item">
                                <strong>Brand Count:</strong> {d.brand.brand_count}
                              </div>
                              <div className="detail-item">
                                <strong>Impersonation Likely:</strong> {
                                  d.brand.impersonation_likely ? "Yes ⚠️" : "No ✓"
                                }
                              </div>
                              <div className="detail-item">
                                <strong>Legitimate Brand:</strong> {d.brand.legitimate_brand || "None"}
                              </div>
                              <div className="detail-item">
                                <strong>High Value Target:</strong> {
                                  d.brand.high_value_target ? "Yes ⚠️" : "No"
                                }
                              </div>
                            </div>

                            {d.brand.typosquatting && d.brand.typosquatting.length > 0 && (
                              <>
                                <h5>🎯 Typosquatting Detection</h5>
                                {d.brand.typosquatting.map((typo, idx) => (
                                  <div key={idx} className="typosquat-item">
                                    <p><strong>Target Brand:</strong> {typo.brand}</p>
                                    <p><strong>Similarity:</strong> {(typo.similarity * 100).toFixed(1)}%</p>
                                    <p><strong>Edit Distance:</strong> {typo.edit_distance}</p>
                                    <p><strong>Likely Typosquat:</strong> {typo.likely_typosquat ? "Yes ⚠️" : "No"}</p>
                                  </div>
                                ))}
                              </>
                            )}
                          </>
                        ) : (
                          <div className="alert success">
                            <strong>✓ No brand impersonation detected</strong>
                          </div>
                        )}
                      </div>
                    )}

                    {/* TLD Tab */}
                    {activeTab === "tld" && d.tld && (
                      <div className="tab-panel">
                        <h4>🌍 Top-Level Domain Analysis</h4>
                        <div className="detail-grid">
                          <div className="detail-item">
                            <strong>TLD:</strong> .{d.tld.tld}
                          </div>
                          <div className="detail-item">
                            <strong>Category:</strong> {d.tld.category}
                          </div>
                          <div className="detail-item">
                            <strong>Reputation:</strong> {d.tld.reputation}
                          </div>
                          <div className="detail-item">
                            <strong>Risk Score:</strong> {d.tld.risk_score?.toFixed(1) || "N/A"}/100
                          </div>
                          <div className="detail-item">
                            <strong>Suspicious:</strong> {d.tld.is_suspicious ? "Yes ⚠️" : "No ✓"}
                          </div>
                          <div className="detail-item">
                            <strong>Free TLD:</strong> {d.tld.is_free_tld ? "Yes ⚠️" : "No ✓"}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* DNS Tab */}
                    {activeTab === "dns" && d.dns && (
                      <div className="tab-panel">
                        <h4>🧠 DNS & Hosting Information</h4>
                        
                        {d.dns.ip_addresses && d.dns.ip_addresses.length > 0 && (
                          <div className="dns-section">
                            <h5>IP Addresses</h5>
                            <ul>
                              {d.dns.ip_addresses.map((ip, idx) => (
                                <li key={idx}><code>{ip}</code></li>
                              ))}
                            </ul>
                          </div>
                        )}

                        <div className="detail-grid">
                          <div className="detail-item">
                            <strong>IP Count:</strong> {d.dns.ip_count}
                          </div>
                          <div className="detail-item">
                            <strong>Has Nameservers:</strong> {d.dns.has_nameservers ? "Yes ✓" : "No ✗"}
                          </div>
                          <div className="detail-item">
                            <strong>Has Mail Servers:</strong> {d.dns.has_mail_servers ? "Yes ✓" : "No ✗"}
                          </div>
                        </div>

                        {d.dns.ns_records && d.dns.ns_records.length > 0 && (
                          <div className="dns-section">
                            <h5>Nameservers</h5>
                            <ul>
                              {d.dns.ns_records.map((ns, idx) => (
                                <li key={idx}>{ns}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {d.dns.mx_records && d.dns.mx_records.length > 0 && (
                          <div className="dns-section">
                            <h5>Mail Servers</h5>
                            <ul>
                              {d.dns.mx_records.map((mx, idx) => (
                                <li key={idx}>
                                  Priority {mx.priority}: {mx.exchange}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </section>

      <Footer />
    </>
  );
}

export default Scan;