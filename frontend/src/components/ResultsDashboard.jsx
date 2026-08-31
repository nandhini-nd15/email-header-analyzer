import { useState } from "react";
import HopMap from "./HopMap";

function verdictClass(verdict) {
  if (verdict === "Likely Safe") return "verdict-safe";
  if (verdict === "Suspicious") return "verdict-suspicious";
  return "verdict-phishing";
}

function authClass(passed) {
  if (passed === true) return "auth-pass";
  if (passed === false) return "auth-fail";
  return "auth-unknown";
}

function formatTimestamp(ts) {
  if (!ts) return "unknown time";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export default function ResultsDashboard({ result }) {
  const [showRaw, setShowRaw] = useState(false);
  const [showMap, setShowMap] = useState(false);
  const { basic_headers, received_chain, auth_results, risk_assessment, raw_headers, warnings } = result;

  return (
    <div className="dashboard">
      <div className={`risk-card ${verdictClass(risk_assessment.verdict)}`}>
        <div className="risk-score">{risk_assessment.score}</div>
        <div className="risk-info">
          <div className="risk-verdict">{risk_assessment.verdict}</div>
          <div className="risk-scale">Risk score out of 100</div>
        </div>
      </div>

      {risk_assessment.signals.length > 0 && (
        <div className="section">
          <h2>Why this score?</h2>
          <ul className="signal-list">
            {risk_assessment.signals.map((s, i) => (
              <li key={i} className={`signal-item severity-${s.severity}`}>
                <span className="signal-severity">{s.severity}</span>
                <span className="signal-desc">{s.description}</span>
                <span className="signal-weight">+{s.weight}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="section">
        <h2>Sender Details</h2>
        <div className="detail-grid">
          <div><span className="label">From</span>{basic_headers.from_display_name} &lt;{basic_headers.from_address}&gt;</div>
          <div><span className="label">To</span>{basic_headers.to_address || "-"}</div>
          <div><span className="label">Subject</span>{basic_headers.subject || "-"}</div>
          <div><span className="label">Date</span>{basic_headers.date || "-"}</div>
          <div><span className="label">Return-Path</span>{basic_headers.return_path || "-"}</div>
          <div><span className="label">Reply-To</span>{basic_headers.reply_to || "-"}</div>
          <div><span className="label">Message-ID</span>{basic_headers.message_id || "-"}</div>
          <div><span className="label">X-Mailer</span>{basic_headers.x_mailer || "-"}</div>
        </div>
      </div>

      <div className="section">
        <h2>Authentication</h2>
        <div className="auth-badges">
          {auth_results.map((a) => {
            const primaryResult = a.verified_result === "fail" || a.verified_result === "pass"
              ? a.verified_result
              : a.claimed_result || a.verified_result || "no data";
            const mismatch = a.claimed_result && a.verified_result &&
              a.claimed_result !== a.verified_result &&
              (a.verified_result === "pass" || a.verified_result === "fail");

            return (
              <div key={a.mechanism} className={`auth-badge ${authClass(a.passed)}`}>
                <div className="auth-mechanism">{a.mechanism.toUpperCase()}</div>
                <div className="auth-result">{primaryResult}</div>
                {mismatch && (
                  <div className="auth-mismatch-note">
                    Header claimed "{a.claimed_result}" — independent check disagrees
                  </div>
                )}
                <div className="auth-details">{a.details}</div>
              </div>
            );
          })}
        </div>
      </div>

            <div className="section">
        <div className="section-header-row">
          <h2>Delivery Path ({received_chain.length} hop{received_chain.length !== 1 ? "s" : ""})</h2>
          {received_chain.length > 0 && (
            <button className="view-map-btn" onClick={() => setShowMap(!showMap)}>
              {showMap ? "Hide map" : "View on map"}
            </button>
          )}
        </div>
        {showMap && <HopMap receivedChain={received_chain} />}
        {received_chain.length === 0 ? (
          <p className="muted">No routing data available.</p>
        ) : (
          <div className="hop-timeline">
            {received_chain.map((hop) => (
              <div key={hop.hop_index} className={`hop ${hop.delay_flag ? "hop-flagged" : ""}`}>
                <div className="hop-index">{hop.hop_index + 1}</div>
                <div className="hop-content">
                  <div className="hop-host">{hop.from_host || "unknown host"}</div>
                  <div className="hop-meta">
                    {hop.ip_address && <span>IP: {hop.ip_address}</span>}
                    {(hop.geo_city || hop.geo_country) && (
                      <span>📍 {[hop.geo_city, hop.geo_country].filter(Boolean).join(", ")}</span>
                    )}
                    {hop.timestamp && <span>{formatTimestamp(hop.timestamp)}</span>}
                    {hop.delay_seconds !== null && hop.delay_seconds !== undefined && (
                      <span className={hop.delay_flag ? "delay-flagged" : ""}>
                        {hop.delay_seconds}s since previous hop
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {warnings && warnings.length > 0 && (
        <div className="section">
          <h2>Parsing Notes</h2>
          <ul className="warning-list">
            {warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="section">
        <button className="toggle-raw-btn" onClick={() => setShowRaw(!showRaw)}>
          {showRaw ? "Hide raw headers" : "Show raw headers"}
        </button>
        {showRaw && (
          <pre className="raw-headers">
            {JSON.stringify(raw_headers, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}