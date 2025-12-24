import { useState } from "react";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { scanURL } from "../services/api"; // ✅ FIX HERE

function Scan() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!url) return alert("Enter URL");

    try {
      setLoading(true);
      const response = await scanURL(url); // ✅ FIX HERE
      setResult(response.data);            // axios response
    } catch (err) {
      console.error(err);
      alert("Backend error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Navbar />

      <section className="scan-section">
        <h1>Scan Website</h1>

        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
        />

        <button onClick={handleScan}>
          {loading ? "Scanning..." : "Scan"}
        </button>

        {result && (
          <div>
            <p><strong>URL:</strong> {result.url}</p>
            <p><strong>Risk Score:</strong> {result.risk_score}</p>
            <p><strong>Reason:</strong> {result.reason}</p>
          </div>
        )}
      </section>

      <Footer />
    </>
  );
}

export default Scan;
