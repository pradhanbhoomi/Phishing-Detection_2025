import React, { useState } from "react";
import axios from "axios";
import "../App.css"

export default function PhishingDetector() {
  const [url, setUrl] = useState("");
  const [results, setResults] = useState(null);
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResults(null);
    setError("");

    try {
      const response = await axios.post("http://localhost:8000/scan", { url });
      setResults(response.data);
    } catch (err) {
      setError("Failed to fetch data. Please check your URL or server.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>Phishing Detection System</h1>

      <form onSubmit={handleSubmit}>
        <input
          type="url"
          placeholder="Enter URL (e.g., http://example.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          required
        />
        <div style={{ marginBottom: "15px" }}>
          <input
            type="checkbox"
            id="consent"
            checked={consent}
            onChange={() => setConsent(!consent)}
          />
          <label htmlFor="consent" style={{ marginLeft: "8px" }}>
            I consent to report this URL if found malicious.
          </label>
        </div>
        <button type="submit" disabled={loading}>
          {loading ? "Analyzing..." : "Analyze URL"}
        </button>
      </form>

      {loading && <div className="spinner"></div>}

      {error && <p className="error-msg">{error}</p>}

      {results && (
        <div className="result-box">
          <h3>Scan Results</h3>
          <p><strong>Domain:</strong> {results.domain}</p>
          <p><strong>Typosquatting Detected:</strong> {results.typosquatting.count}</p>
          <p><strong>Registrar:</strong> {results.whois?.registrar || "Unknown"}</p>
          <p><strong>Country:</strong> {results.whois?.country || "Unknown"}</p>
          {results.typosquatting.examples?.length > 0 && (
            <div>
              <p><strong>Examples:</strong></p>
              <ul>
                {results.typosquatting.examples.map((ex, idx) => (
                  <li key={idx}>{ex.domain} → {ex.resolved_to}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
