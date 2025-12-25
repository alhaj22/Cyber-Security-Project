// components/AboutPhishing.js
import "../styles/AboutPhishing.css";


function AboutPhishing() {
  return (
    <section className="phishing-section">
      <div className="phishing-container">

        <span className="phishing-tag">CYBER SECURITY AWARENESS</span>

        <h2>
          What is <span>Phishing?</span>
        </h2>

        <p className="phishing-intro">
          Phishing is one of the most common and dangerous cyber attacks where
          attackers create fake websites or messages that look like trusted
          brands in order to steal sensitive user information.
        </p>

        <div className="phishing-grid">

          <div className="phishing-card">
            <h3>🎯 What Attackers Target</h3>
            <ul>
              <li>Login usernames & passwords</li>
              <li>Bank & card details</li>
              <li>OTP & verification codes</li>
              <li>Email & social media accounts</li>
            </ul>
          </div>

          <div className="phishing-card">
            <h3>🧠 How Phishing Works</h3>
            <ul>
              <li>Fake website copies a real brand</li>
              <li>User receives a suspicious link</li>
              <li>User trusts the site and logs in</li>
              <li>Data is secretly sent to attacker</li>
            </ul>
          </div>

          <div className="phishing-card">
            <h3>⚠️ Common Phishing Signs</h3>
            <ul>
              <li>Strange or misspelled domain names</li>
              <li>Urgent warnings like “Account blocked”</li>
              <li>Free or unusual domains (.tk, .xyz)</li>
              <li>Login pages asking for sensitive data</li>
            </ul>
          </div>

          <div className="phishing-card">
            <h3>🛡️ How PhishGuard Protects You</h3>
            <ul>
              <li>Checks domain age & reputation</li>
              <li>Detects brand impersonation</li>
              <li>Analyzes SSL & security signals</li>
              <li>Provides a clear risk verdict</li>
            </ul>
          </div>

        </div>

        <div className="phishing-note">
          <strong>Important:</strong> HTTPS alone does not guarantee a website is safe.
          Always verify the URL and trust security analysis tools.
        </div>

      </div>
    </section>
  );
}

export default AboutPhishing;
