import { useState } from "react";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { scanURL } from "../services/api";

function Scan() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const isValidURL = (value) => {
    try {
      const u = new URL(value.startsWith("http") ? value : `https://${value}`);
      return u.hostname.includes(".");
    } catch {
      return false;
    }
  };

  const handleScan = async () => {
    if (!url.trim()) {
      setResult({ status: "INVALID", reason: "URL cannot be empty." });
      return;
    }

    if (!isValidURL(url)) {
      setResult({ status: "INVALID", reason: "Invalid URL format." });
      return;
    }

    try {
      setLoading(true);
      setResult(null);

      const response = await scanURL(url);
      console.log("FINAL BACKEND RESPONSE:", response.data);
      setResult(response.data);

    } catch {
      setResult({
        status: "ERROR",
        reason: "Backend unavailable or scan failed."
      });
    } finally {
      setLoading(false);
    }
  };

  const getColor = (status) => {
    switch (status) {
      case "SAFE": return "#16a34a";
      case "SUSPICIOUS": return "#f59e0b";
      case "NOT SAFE": return "#dc2626";
      case "INVALID": return "#64748b";
      default: return "#475569";
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
            style={{ borderLeft: `6px solid ${getColor(result.status)}` }}
          >
            <h2 style={{ color: getColor(result.status) }}>
              {result.status}
            </h2>
            <p>{result.reason}</p>

            {result.confidence !== undefined && (
              <p><strong>Confidence:</strong> {result.confidence}%</p>
            )}
          </div>
        )}
      </section>

      <Footer />
    </>
  );
}

export default Scan;
