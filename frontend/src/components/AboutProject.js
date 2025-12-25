// components/AboutProject.js
import "../styles/AboutProject.css";

function AboutProject() {
  return (
    <section className="project-section">
      <div className="project-container">

        <span className="project-tag">PROJECT OVERVIEW</span>

        <h2>
          About <span>This Project</span>
        </h2>

        <p className="project-intro">
          This website is an AI-powered phishing detection system designed to
          help users identify whether a website is safe, suspicious, or a
          phishing attempt. The system analyzes a given URL using multiple
          security techniques and provides a clear risk verdict.
        </p>

        <div className="project-grid">

          <div className="project-card">
            <h3>🧠 Problem Statement</h3>
            <p>
              Phishing attacks are increasing rapidly and target users through
              fake websites that impersonate trusted brands. Most users are
              unable to identify such websites just by looking at them, which
              results in data theft, financial loss, and identity compromise.
            </p>
          </div>

          <div className="project-card">
            <h3>⚙️ How This System Works</h3>
            <ul>
              <li>User submits a website URL</li>
              <li>Backend performs deep security analysis</li>
              <li>Multiple modules calculate risk signals</li>
              <li>A final phishing risk score is generated</li>
              <li>User receives a clear verdict and explanation</li>
            </ul>
          </div>

          <div className="project-card">
            <h3>🔍 Security Checks Performed</h3>
            <ul>
              <li>URL structure & pattern analysis</li>
              <li>Domain age and WHOIS verification</li>
              <li>SSL/TLS certificate validation</li>
              <li>Brand impersonation detection</li>
              <li>TLD and DNS reputation analysis</li>
            </ul>
          </div>

          <div className="project-card">
            <h3>🛠️ Technology Stack</h3>
            <ul>
              <li><strong>Frontend:</strong> React.js</li>
              <li><strong>Backend:</strong> Python (Flask)</li>
              <li><strong>Security:</strong> SSL, WHOIS, DNS analysis</li>
              <li><strong>Architecture:</strong> REST API based</li>
            </ul>
          </div>

        </div>

        <div className="project-note">
          <strong>Objective:</strong> The main goal of this project is to spread
          cybersecurity awareness and provide users with a simple tool to
          protect themselves from phishing attacks before visiting unknown
          websites.
        </div>

      </div>
    </section>
  );
}

export default AboutProject;
