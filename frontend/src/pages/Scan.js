import { useState } from "react";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { scanURL } from "../services/api";   // 👈 SAME NAME


function Scan() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);

  const handleScan = async () => {
    if (!url) return alert("Enter URL");
    const data = await checkWebsite(url);
    setResult(data);
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

        <button onClick={handleScan}>Scan</button>

        {result && (
          <div>
            <p>Status: {result.risk}</p>
            <p>{result.message}</p>
          </div>
        )}
      </section>

      <Footer />
    </>
  );
}

export default Scan;
