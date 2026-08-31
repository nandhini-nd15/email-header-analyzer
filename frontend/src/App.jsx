import { useState } from "react";
import { API_BASE_URL } from "./config";
import ResultsDashboard from "./components/ResultsDashboard";
import "./index.css";

function App() {
  const [rawHeaders, setRawHeaders] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const handleAnalyze = async () => {
    setError(null);
    setResult(null);

    if (!file && !rawHeaders.trim()) {
      setError("Paste raw email headers or upload a .eml file first.");
      return;
    }

    setLoading(true);
    try {
      let response;
      if (file) {
        const formData = new FormData();
        formData.append("file", file);
        response = await fetch(`${API_BASE_URL}/api/analyze/upload`, {
          method: "POST",
          body: formData,
        });
      } else {
        response = await fetch(`${API_BASE_URL}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ raw_headers: rawHeaders }),
        });
      }

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new Error(errBody.detail || `Request failed (${response.status})`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(
        err.message === "Failed to fetch"
          ? "Could not reach the backend. Is the FastAPI server running on port 8000?"
          : err.message
      );
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setRawHeaders("");
    setFile(null);
    setResult(null);
    setError(null);
  };

  return (
    <div className="page">
      <header className="page-header">
        <h1>Email Header Analyzer</h1>
        <p className="subtitle">
          Paste raw email headers or upload a .eml file to check SPF/DKIM/DMARC,
          trace the delivery path, and detect spoofing.
        </p>
      </header>

      {!result && (
        <div className="input-card">
          <textarea
            className="header-input"
            placeholder="Paste raw email headers here...
Example: open the email, View original / Show source, copy everything and paste it here."
            value={rawHeaders}
            onChange={(e) => {
              setRawHeaders(e.target.value);
              setFile(null);
            }}
            rows={12}
          />

          <div className="input-row">
            <label className="file-upload">
              <input
                type="file"
                accept=".eml,.txt,.msg"
                onChange={(e) => {
                  setFile(e.target.files[0]);
                  setRawHeaders("");
                }}
              />
              {file ? `File: ${file.name}` : "Or upload a .eml file"}
            </label>

            <button
              className="analyze-btn"
              onClick={handleAnalyze}
              disabled={loading}
            >
              {loading ? "Analyzing..." : "Analyze"}
            </button>
          </div>

          {error && <div className="error-banner">{error}</div>}
        </div>
      )}

      {result && (
        <>
          <ResultsDashboard result={result} />
          <button className="analyze-again-btn" onClick={handleReset}>
            &larr; Analyze another email
          </button>
        </>
      )}
    </div>
  );
}

export default App;