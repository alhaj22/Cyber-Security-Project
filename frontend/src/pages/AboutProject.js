import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import "../styles/project.css";


function AboutProject() {
  const features = [
    {
      icon: "⚡",
      title: "Fast Detection",
      description: "Real-time phishing detection using advanced machine learning algorithms"
    },
    {
      icon: "🔒",
      title: "Secure",
      description: "Enterprise-grade security with encrypted data transmission and storage"
    },
    {
      icon: "📊",
      title: "Advanced Analytics",
      description: "Detailed analysis of URLs using multiple security layers and threat intelligence"
    },
    {
      icon: "🌐",
      title: "Multi-Layer Protection",
      description: "SSL certificate verification, domain reputation analysis, and brand detection"
    }
  ];

  const technologies = [
    {
      category: "Frontend",
      items: ["React.js", "JavaScript", "CSS3", "Responsive Design"]
    },
    {
      category: "Backend",
      items: ["Python", "Flask/Django", "Machine Learning", "API Integration"]
    },
    {
      category: "Security",
      items: ["SSL Certificate Analysis", "DNS Verification", "URL Pattern Detection", "Brand Impersonation Detection"]
    },
    {
      category: "Database",
      items: ["Database Management", "Data Encryption", "Threat Database", "Historical Logs"]
    }
  ];

  const stats = [
    {
      number: "99.9%",
      label: "Detection Accuracy"
    },
    {
      number: "0.5s",
      label: "Average Response Time"
    },
    {
      number: "1000+",
      label: "Known Phishing Sites"
    },
    {
      number: "24/7",
      label: "Real-Time Protection"
    }
  ];

  const workflow = [
    {
      step: "1",
      title: "URL Input",
      description: "User submits a URL or receives a suspicious link"
    },
    {
      step: "2",
      title: "Analysis",
      description: "System analyzes the URL using multiple security layers"
    },
    {
      step: "3",
      title: "Verification",
      description: "Cross-checks against threat database and SSL certificates"
    },
    {
      step: "4",
      title: "Assessment",
      description: "Generates risk score and detailed security report"
    },
    {
      step: "5",
      title: "Alert",
      description: "User receives real-time alert with safety recommendations"
    }
  ];

  return (
    <>
      <Navbar />

      <section className="project-section">
        <div className="project-container">
          <span className="project-tag">💼 ABOUT PROJECT</span>
          <h2>PhishRadar - <span>Smart Phishing Detection</span></h2>
          <p className="project-intro">
            PhishRadar is an intelligent phishing detection system built with cutting-edge technology 
            to protect users from cyber threats. Our system combines React frontend with Python backend 
            to deliver real-time phishing analysis and protection.
          </p>

          {/* Features */}
          <h3 className="project-subtitle">Key Features</h3>
          <div className="project-grid">
            {features.map((feature, idx) => (
              <div key={idx} className="project-card">
                <div className="feature-icon">{feature.icon}</div>
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
              </div>
            ))}
          </div>

          {/* Stats */}
          <div className="stats-section">
            <h3 className="project-subtitle">By The Numbers</h3>
            <div className="stats-grid">
              {stats.map((stat, idx) => (
                <div key={idx} className="stat-card">
                  <div className="stat-number">{stat.number}</div>
                  <div className="stat-label">{stat.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Workflow */}
          <div className="workflow-section">
            <h3 className="project-subtitle">How It Works</h3>
            <div className="workflow-grid">
              {workflow.map((item, idx) => (
                <div key={idx} className="workflow-card">
                  <div className="workflow-step">{item.step}</div>
                  <h4>{item.title}</h4>
                  <p>{item.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Technologies */}
          <h3 className="project-subtitle">Technology Stack</h3>
          <div className="tech-grid">
            {technologies.map((tech, idx) => (
              <div key={idx} className="tech-card">
                <h4>{tech.category}</h4>
                <ul>
                  {tech.items.map((item, itemIdx) => (
                    <li key={itemIdx}>{item}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Mission */}
          <div className="project-note">
            🎯 <strong>Our Mission:</strong> To provide users with a reliable, fast, and easy-to-use phishing detection 
            tool that helps them stay safe online. We believe cybersecurity should be accessible to everyone.
          </div>
        </div>
      </section>

      <Footer />
    </>
  );
}

export default AboutProject;