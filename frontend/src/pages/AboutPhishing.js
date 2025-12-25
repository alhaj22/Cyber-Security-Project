import React, { useState } from 'react';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import "../styles/PhishingInfo.css";


function PhishingInfo() {
  const [expandedSections, setExpandedSections] = useState({});

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const types = [
    {
      id: 'email',
      title: 'Email Phishing',
      description: 'The most common type where attackers send fraudulent emails pretending to be from legitimate companies.'
    },
    {
      id: 'spear',
      title: 'Spear Phishing',
      description: 'Targeted attacks directed at specific individuals or organizations with personalized messages.'
    },
    {
      id: 'voice',
      title: 'Voice Phishing (Vishing)',
      description: 'Attackers make phone calls pretending to be from banks or agencies asking for account details.'
    },
    {
      id: 'sms',
      title: 'SMS Phishing (Smishing)',
      description: 'Fraudulent text messages containing malicious links or requests for personal information.'
    },
    {
      id: 'hijacking',
      title: 'Page Hijacking',
      description: 'Attackers redirect users from legitimate websites to fake ones through DNS hijacking.'
    },
    {
      id: 'qr',
      title: 'QR Code Phishing',
      description: 'Malicious QR codes placed on posters or emails that direct users to phishing pages.'
    },
    {
      id: 'mitm',
      title: 'Man-in-the-Middle Phishing',
      description: 'Attackers intercept communication between users and legitimate websites to steal data.'
    }
  ];

  const techniques = [
    {
      id: 'link',
      title: 'Link Manipulation',
      items: [
        'Deceptive URLs (amaz0n.com instead of amazon.com)',
        'URL shorteners to hide destinations',
        'Malicious links embedded in trusted text'
      ]
    },
    {
      id: 'social',
      title: 'Social Engineering',
      items: [
        'Creating urgency ("Your account will be locked!")',
        'Instilling fear ("Unusual activity detected!")',
        'Impersonating authority figures'
      ]
    }
  ];

  const history = [
    {
      period: 'Early History',
      description: 'Phishing attacks emerged in the mid-1990s with AOL users being targeted for passwords and credit card information.'
    },
    {
      period: '2000s',
      description: 'Phishing became widespread with major organizations like eBay and PayPal frequently impersonated.'
    },
    {
      period: '2010s',
      description: 'Mobile phishing increased with smartphones. SMS phishing and phishing apps became common threats.'
    },
    {
      period: '2020s',
      description: 'Advanced phishing with AI-generated content, QR code phishing, and targeted spear phishing campaigns.'
    }
  ];

  const antiPhishing = [
    {
      category: 'User Training',
      items: [
        'Regular security awareness training',
        'Educational campaigns about phishing red flags',
        'Simulated phishing exercises',
        'Public awareness campaigns'
      ]
    },
    {
      category: 'Technical Approaches',
      items: [
        'Email filters using AI and machine learning',
        'Browser phishing detection and warnings',
        'Two-Factor Authentication (2FA)',
        'Hardware security keys',
        'Rapid removal of phishing websites'
      ]
    },
    {
      category: 'Legal Responses',
      items: [
        'Anti-phishing laws and regulations',
        'Prosecution of phishing perpetrators',
        'International cooperation between law enforcement',
        'CAN-SPAM Act and data protection laws'
      ]
    }
  ];

  const protectionTips = [
    {
      icon: '🔍',
      title: 'Verify URLs',
      description: 'Always check the website address before entering sensitive information.'
    },
    {
      icon: '🔐',
      title: 'Use Strong Passwords',
      description: 'Create unique, complex passwords for each account using a password manager.'
    },
    {
      icon: '📱',
      title: 'Enable 2FA',
      description: 'Enable two-factor authentication on all important accounts.'
    },
    {
      icon: '⚠️',
      title: 'Beware of Urgency',
      description: 'Be suspicious of messages creating urgency or requesting immediate action.'
    },
    {
      icon: '🚫',
      title: 'Never Share OTPs',
      description: 'Never share One-Time Passwords, PINs, or security codes with anyone.'
    },
    {
      icon: '🔔',
      title: 'Report Suspicious Activity',
      description: 'Report phishing attempts to your bank immediately.'
    }
  ];

  return (
    <>
      <Navbar />
      
      <section className="phishing-section">
        <div className="phishing-container">
          <span className="phishing-tag">🎣 PHISHING GUIDE</span>
          <h2>Understanding <span>Phishing Attacks</span></h2>
          <p className="phishing-intro">
            Phishing is one of the most common and dangerous cyber attacks used to steal sensitive information. 
            Learn about different types, techniques, and how to protect yourself from these threats.
          </p>

          {/* Types */}
          <h3 className="phishing-subtitle">Types of Phishing Attacks</h3>
          <div className="phishing-grid">
            {types.map(type => (
              <div key={type.id} className="phishing-card">
                <h3>{type.title}</h3>
                <p>{type.description}</p>
              </div>
            ))}
          </div>

          {/* Techniques */}
          <h3 className="phishing-subtitle" style={{marginTop: '60px'}}>Common Techniques</h3>
          <div className="phishing-grid">
            {techniques.map(tech => (
              <div key={tech.id} className="phishing-card">
                <h3>{tech.title}</h3>
                <ul>
                  {tech.items.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* History */}
          <h3 className="phishing-subtitle" style={{marginTop: '60px'}}>History of Phishing</h3>
          <div className="phishing-timeline">
            {history.map((item, idx) => (
              <div key={idx} className="timeline-item">
                <div className="timeline-dot"></div>
                <div className="timeline-content">
                  <h4>{item.period}</h4>
                  <p>{item.description}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Anti-Phishing */}
          <h3 className="phishing-subtitle" style={{marginTop: '60px'}}>Anti-Phishing Measures</h3>
          <div className="phishing-grid">
            {antiPhishing.map((section, idx) => (
              <div key={idx} className="phishing-card">
                <h3>{section.category}</h3>
                <ul>
                  {section.items.map((item, itemIdx) => (
                    <li key={itemIdx}>{item}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Protection Tips */}
          <h3 className="phishing-subtitle" style={{marginTop: '60px'}}>How to Protect Yourself</h3>
          <div className="protection-grid">
            {protectionTips.map((tip, idx) => (
              <div key={idx} className="protection-card">
                <div className="protection-icon">{tip.icon}</div>
                <h4>{tip.title}</h4>
                <p>{tip.description}</p>
              </div>
            ))}
          </div>

          {/* Note */}
          <div className="phishing-note">
            💡 <strong>Important:</strong> PhishRadar is designed to protect you from phishing threats by analyzing URLs 
            using multiple security layers such as SSL certificate checks, domain reputation analysis, and brand impersonation detection.
          </div>
        </div>
      </section>

      <Footer />
    </>
  );
}

export default PhishingInfo;