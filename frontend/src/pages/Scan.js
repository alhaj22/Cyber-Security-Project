
import { useState } from "react";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { scanURL } from "../services/api";

/**
 * Ethical Hacker Rules:
 * 1. Invalid input is NEVER safe
 * 2. Backend must prove scan happened
 * 3. Verdict must be explicit
 */

function Scan() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // 🔐 STRICT URL VALIDATOR
  const isValidURL = (value) => {
    try {
      const u = new URL(value.startsWith("http") ? value : `https://${value}`);
      return u.hostname.includes(".");
    } catch {
      return false;
    }
  };

  // 🔐 STRICT VERDICT HANDLER
  const buildVerdict = (data) => {
    // Backend explicitly says invalid
    if (data.status === "INVALID") {
      return {
        status: "INVALID",
        reason: data.reason || "Invalid or unreachable website."
      };
    }

    // Backend explicitly gives verdict
    if (data.status && data.reason) {
      return {
        status: data.status,
        reason: data.reason
      };
    }

    // Backend gives risk_score (fallback, controlled)
    if (typeof data.risk_score === "number") {
      if (data.risk_score >= 70) {
        return {
          status: "NOT SAFE",
          reason: "High-risk phishing indicators detected."
        };
      }
      if (data.risk_score >= 40) {
        return {
          status: "SUSPICIOUS",
          reason: "Website shows suspicious security behaviour."
        };
      }
      return {
        status: "SAFE",
        reason: "No strong phishing indicators found."
      };
    }

    // Anything else = error
    return {
      status: "ERROR",
      reason: "Scan could not be completed."
    };
  };

  const handleScan = async () => {
    if (!url.trim()) {
      setResult({
        status: "INVALID",
        reason: "URL cannot be empty."
      });
      return;
    }

    if (!isValidURL(url)) {
      setResult({
        status: "INVALID",
        reason: "Input is not a valid website URL."
      });
      return;
    }

    try {
      setLoading(true);
      setResult(null);

      const response = await scanURL(url);
      console.log("BACKEND RESPONSE:", response.data);

      const verdict = buildVerdict(response.data);
      setResult(verdict);

    } catch (err) {
      console.error(err);
      setResult({
        status: "ERROR",
        reason: "Backend unavailable or scan failed."
      });
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "SAFE":
        return "#16a34a";
      case "SUSPICIOUS":
        return "#f59e0b";
      case "NOT SAFE":
        return "#dc2626";
      case "INVALID":
        return "#64748b";
      default:
        return "#475569";
    }
  };

  return (
    <>
      <Navbar />

      <section className="scan-section">
        <h1>Website Security Scan</h1>

        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
        />

        <button onClick={handleScan} disabled={loading}>
          {loading ? "Analyzing..." : "Scan Website"}
        </button>

        {result && (
          <div
            className="scan-result"
            style={{ borderLeft: `6px solid ${getStatusColor(result.status)}` }}
          >
            <h2 style={{ color: getStatusColor(result.status) }}>
              {result.status}
            </h2>
            <p>{result.reason}</p>
          </div>
        )}
      </section>

      <Footer />
    </>
  );
}

export default Scan;
