function YesNo({ ok }) {
  return ok ? "✔" : "⚠";
}

export default function SecurityExplanation({ data }) {
  if (!data) return null;

  const { ssl, url_analysis, whois, brand, tld, dns } = data;

  return (
    <div className="explain-grid">

      {/* 🔒 SSL */}
      {ssl && (
        <div className="explain-card">
          <h3>🔒 SSL Security</h3>
          <p>{YesNo(ssl.has_ssl)} HTTPS connection</p>
          <p>{YesNo(ssl.domain_matches)} Certificate matches domain</p>
          <p>{YesNo(!ssl.is_self_signed)} Not self-signed</p>
          {ssl.expires_soon && <p>⚠ Certificate expires soon</p>}
        </div>
      )}

      {/* 🔗 URL */}
      {url_analysis && (
        <div className="explain-card">
          <h3>🔗 URL Analysis</h3>
          <p>{YesNo(!url_analysis.suspicious_indicators?.has_ip_in_domain)} No IP address used</p>
          <p>{YesNo(!url_analysis.suspicious_indicators?.url_shortener)} Not a URL shortener</p>
          <p>{YesNo(!url_analysis.suspicious_indicators?.suspicious_keywords)} No phishing keywords</p>
        </div>
      )}

      {/* 🌐 WHOIS */}
      {whois && (
        <div className="explain-card">
          <h3>🌐 WHOIS Information</h3>
          {whois.domain_age_days
            ? <p>✔ Domain age: {whois.domain_age_days} days</p>
            : <p>⚠ Domain age unavailable</p>}
          <p>{YesNo(!whois.risk_indicators?.very_new_domain)} Not recently created</p>
          <p>Registrar: {whois.registrar || "Unknown"}</p>
        </div>
      )}

      {/* 🏷 BRAND */}
      {brand && (
        <div className="explain-card">
          <h3>🏷 Brand Detection</h3>
          {brand.detected_brands?.length > 0
            ? <p>⚠ Brand mentioned: {brand.detected_brands.join(", ")}</p>
            : <p>✔ No brand impersonation</p>}
          <p>{YesNo(!brand.impersonation_likely)} No impersonation detected</p>
        </div>
      )}

      {/* 🌍 TLD */}
      {tld && (
        <div className="explain-card">
          <h3>🌍 TLD Check</h3>
          <p>TLD: .{tld.tld}</p>
          <p>{YesNo(!tld.risk_indicators?.high_risk)} Trusted TLD</p>
          <p>Reputation: {tld.reputation}</p>
        </div>
      )}

      {/* 🧠 DNS */}
      {dns && (
        <div className="explain-card">
          <h3>🧠 DNS & Hosting</h3>
          <p>{YesNo(dns.ipv4_addresses?.length > 0)} IP address resolved</p>
          {dns.asn_info?.asn_description && (
            <p>Hosting: {dns.asn_info.asn_description}</p>
          )}
          <p>{YesNo(!dns.risk_indicators?.suspicious_asn)} Clean hosting reputation</p>
        </div>
      )}

    </div>
  );
}
