// components/UrlInput.js
import { useState } from "react";
import { checkWebsite } from "../services/api";

function UrlInput() {
  const [url, setUrl] = useState("");

  const handleCheck = async () => {
    const result = await checkWebsite(url);
    alert(result.message); // abhi simple
  };

  return (
    <div>
      <input
        type="text"
        placeholder="https://example.com"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />
      <button onClick={handleCheck}>Check URL</button>
    </div>
  );
}

export default UrlInput;
