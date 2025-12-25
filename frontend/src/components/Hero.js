import { useState } from "react";
import { useNavigate } from "react-router-dom";

function Hero() {
  const [url, setUrl] = useState("");
  const navigate = useNavigate();

  const handleScan = () => {
    if (!url.trim()) {
      alert("Please enter a website URL");
      return;
    }

    // 👉 Scan page pe bhej do
    navigate("/scan", {
      state: { url }
    });
  };

  return (
    <section
      className="hero"
      style={{
        backgroundImage: `
          linear-gradient(
            to right,
            rgba(2,6,23,0.97),
            rgba(2,6,23,0.7)
          ),
          url(${process.env.PUBLIC_URL}/hero.png)
        `,
      }}
    >
      <div className="hero-content">
        <span className="hero-tag">AI-Powered Cyber Security</span>

        <h1>
          Detect <span>Phishing</span> <br />
          Websites Instantly
        </h1>

        <p>
          Enter any website URL to instantly check whether it is safe,
          suspicious, or a phishing attempt.
        </p>

        <div className="hero-input">
          <input
            type="text"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button onClick={handleScan}>Scan Website</button>
        </div>

        <small className="hero-note">
          Free phishing check • No login required
        </small>
      </div>
    </section>
  );
}

export default Hero;
