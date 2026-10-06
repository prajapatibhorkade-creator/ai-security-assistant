import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [loggedIn, setLoggedIn] = useState(
    !!localStorage.getItem("access_token")
  );

  // =========================
  // DASHBOARD
  // =========================

  const [dashboard, setDashboard] = useState({
    total_logs: 0,
    total_alerts: 0,
    risk_score: 0,
    risk_level: "LOW",
    risk_breakdown: {
      ml_anomaly: 0,
      behavior: 0,
      threat_intelligence: 0,
      attack_chain: 0,
      severity: 0,
    },
    ml_anomalies: 0,
  });
  const [analytics, setAnalytics] = useState(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const [analyticsError, setAnalyticsError] = useState("");

  // =========================
  // SECURITY LOGS
  // =========================

  const [logs, setLogs] = useState([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [logsError, setLogsError] = useState("");

  // =========================
  // THREAT ALERTS
  // =========================

  const [alerts, setAlerts] = useState([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alertsError, setAlertsError] = useState("");

  // =========================
  // COPILOT
  // =========================

  const [copilotQuestion, setCopilotQuestion] = useState("");
  const [copilotMessages, setCopilotMessages] = useState([
    {
      role: "assistant",
      text:
        "I can explain recent alerts, investigate a user, review suspicious IPs, summarize activity, or suggest the next analyst action.",
    },
  ]);
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [securityCopilot, setSecurityCopilot] = useState(null);
  const [securityCopilotLoading, setSecurityCopilotLoading] = useState(false);
  const [securityCopilotError, setSecurityCopilotError] = useState("");

  // =========================
  // LOGIN
  // =========================

  const handleLogin = async (e) => {
    e.preventDefault();

    setLoading(true);
    setError("");

    try {
      const formData = new URLSearchParams();

      formData.append("username", username);
      formData.append("password", password);

      const response = await fetch(
        "http://127.0.0.1:8000/login",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/x-www-form-urlencoded",
          },
          body: formData,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Login failed"
        );
      }

      localStorage.setItem(
        "access_token",
        data.access_token
      );

      if (data.refresh_token) {
        localStorage.setItem(
          "refresh_token",
          data.refresh_token
        );
      }

      setLoggedIn(true);
      setPassword("");
      setError("");

    } catch (error) {
      console.error("Login error:", error);

      setError(
        error.message ||
          "Cannot connect to backend"
      );
    } finally {
      setLoading(false);
    }
  };

  // =========================
  // LOGOUT
  // =========================

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");

    setLoggedIn(false);

    setLogs([]);
    setAlerts([]);
  };

  // =========================
  // DASHBOARD DATA
  // =========================

  const fetchDashboard = async () => {
    const token =
      localStorage.getItem("access_token");

    if (!token) {
      return;
    }

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/dashboard/summary",
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        if (response.status === 401) {
          handleLogout();
          return;
        }

        throw new Error(
          "Failed to load dashboard"
        );
      }

      const data = await response.json();

      console.log("DASHBOARD API RESPONSE:", data);

      setDashboard({
        total_logs: data.total_logs ?? 0,
        total_alerts: data.total_alerts ?? 0,
        risk_score: data.risk_score ?? 0,
        risk_level: data.risk_level ?? "LOW",
        risk_breakdown: data.risk_breakdown ?? {},
        ml_anomalies: data.ml_anomalies ?? 0,
      });

    } catch (error) {
      console.error(
        "Dashboard error:",
        error
      );
    }
  };

  const loadAnalytics = async () => {
    setAnalyticsLoading(true);
    setAnalyticsError("");

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/security/analytics"
      );
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Failed to load security analytics");
      }

      setAnalytics(data);
    } catch (error) {
      console.error("Analytics error:", error);
      setAnalyticsError(error.message || "Could not load analytics.");
    } finally {
      setAnalyticsLoading(false);
    }
  };

  // =========================
  // SECURITY LOGS
  // =========================

  const fetchLogs = async () => {
    const token =
      localStorage.getItem("access_token");

    if (!token) {
      return;
    }

    setLogsLoading(true);
    setLogsError("");

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/logs",
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        if (response.status === 401) {
          handleLogout();
          return;
        }

        throw new Error(
          "Failed to load security logs"
        );
      }

      const data = await response.json();

      if (Array.isArray(data)) {
        setLogs(data);
      } else if (
        Array.isArray(data.logs)
      ) {
        setLogs(data.logs);
      } else {
        setLogs([]);
      }

    } catch (error) {
      console.error(
        "Logs error:",
        error
      );

      setLogsError(
        error.message ||
          "Failed to load logs"
      );
    } finally {
      setLogsLoading(false);
    }
  };

  // =========================
  // THREAT ALERTS
  // =========================

  const fetchAlerts = async () => {
    const token =
      localStorage.getItem("access_token");

    if (!token) {
      return;
    }

    setAlertsLoading(true);
    setAlertsError("");

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/alerts",
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        if (response.status === 401) {
          handleLogout();
          return;
        }

        throw new Error(
          "Failed to load threat alerts"
        );
      }

      const data = await response.json();

      if (Array.isArray(data)) {
        setAlerts(data);
      } else if (
        Array.isArray(data.alerts)
      ) {
        setAlerts(data.alerts);
      } else {
        setAlerts([]);
        setAnalytics(null);
      }

    } catch (error) {
      console.error(
        "Alerts error:",
        error
      );

      setAlertsError(
        error.message ||
          "Failed to load threat alerts"
      );
    } finally {
      setAlertsLoading(false);
    }
  };

  // =========================
  // UPDATE ALERT STATUS
  // =========================

  const updateAlertStatus = async (
    alertId,
    newStatus
  ) => {
    const token =
      localStorage.getItem("access_token");

    if (!token) {
      return;
    }

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/alerts/${alertId}/status`,
        {
          method: "PUT",
          headers: {
            "Content-Type":
              "application/json",
            Authorization:
              `Bearer ${token}`,
          },
          body: JSON.stringify({
            status: newStatus,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Failed to update alert status"
        );
      }

      await fetchAlerts();
      await fetchDashboard();

    } catch (error) {
      console.error(
        "Status update error:",
        error
      );

      setAlertsError(
        error.message ||
          "Failed to update alert status"
      );
    }
  };

  const askCopilot = async (e) => {
    e.preventDefault();

    const question = copilotQuestion.trim();
    if (!question || copilotLoading) {
      return;
    }

    const token = localStorage.getItem("access_token");
    if (!token) {
      return;
    }

    setCopilotLoading(true);
    setCopilotMessages((prev) => [
      ...prev,
      { role: "user", text: question },
    ]);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/copilot",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ question }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Copilot request failed"
        );
      }

      setCopilotMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: data.answer || "No answer generated.",
        },
      ]);
      setCopilotQuestion("");
    } catch (error) {
      console.error("Copilot error:", error);
      setCopilotMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: error.message || "The copilot could not answer that request.",
        },
      ]);
    } finally {
      setCopilotLoading(false);
    }
  };

  const runSecurityCopilot = async () => {
    setSecurityCopilotLoading(true);
    setSecurityCopilotError("");

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/security/copilot",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            event_id: 999,
            timestamp: new Date().toISOString(),
            username: username || "praja",
            ip_address: "10.0.0.25",
            event_type: "failed_login",
            message: "Failed login detected",
            severity: "high",
            ml_anomaly_score: 85,
            failed_attempts: 8,
            known_ip: false,
            recent_event_count: 60,
          }),
        }
      );

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Security Copilot analysis failed");
      }

      setSecurityCopilot(data.copilot);
    } catch (error) {
      console.error("Security Copilot error:", error);
      setSecurityCopilotError(error.message || "Could not analyze the event.");
    } finally {
      setSecurityCopilotLoading(false);
    }
  };

  // =========================
  // LOAD DATA AFTER LOGIN
  // =========================

  useEffect(() => {
    if (loggedIn) {
      fetchDashboard();
      fetchLogs();
      fetchAlerts();
      loadAnalytics();
    }
  }, [loggedIn]);

  // =========================
  // LOGIN PAGE
  // =========================

  if (!loggedIn) {
    return (
      <div className="login-page">

        <div className="login-card">

          <div className="logo">
            🛡️
          </div>

          <h1>
            AI Security Assistant
          </h1>

          <p className="subtitle">
            AI-powered cybersecurity monitoring
          </p>

          <form onSubmit={handleLogin}>

            <label>
              Username
            </label>

            <input
              type="text"
              placeholder="Enter username"
              value={username}
              onChange={(e) =>
                setUsername(e.target.value)
              }
              required
            />

            <label>
              Password
            </label>

            <input
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) =>
                setPassword(e.target.value)
              }
              required
            />

            {error && (
              <p
                style={{
                  color: "red",
                  marginTop: "10px",
                }}
              >
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
            >
              {loading
                ? "Logging in..."
                : "Login"}
            </button>

          </form>

          <p className="footer-text">
            Secure • Intelligent • Real-time
          </p>

        </div>
      </div>
    );
  }

  // =========================
  // DASHBOARD PAGE
  // =========================

  return (
    <div className="dashboard-page">

      {/* HEADER */}

      <header className="dashboard-header">

        <div>
          <h1>
            🛡️ AI Security Assistant
          </h1>

          <p>
            AI-powered cybersecurity monitoring
          </p>
        </div>

        <button
          className="logout-button"
          onClick={handleLogout}
        >
          Logout
        </button>

      </header>

      {/* MAIN */}

      <main className="dashboard-container">

        <h2>
          Security Dashboard
        </h2>

        {/* =========================
            DASHBOARD CARDS
        ========================= */}

        <div className="dashboard-cards">

          <div className="dashboard-card">

            <div className="card-icon">
              🔐
            </div>

            <h3>
              Security Logs
            </h3>

            <p>
              Monitor system security logs.
            </p>

            <strong>
              {dashboard.total_logs}
            </strong>

            <span>
              Total Logs
            </span>

          </div>

          <div className="dashboard-card">

            <div className="card-icon">
              🚨
            </div>

            <h3>
              Threat Alerts
            </h3>

            <p>
              Detected security alerts.
            </p>

            <strong>
              {dashboard.total_alerts}
            </strong>

            <span>
              Total Alerts
            </span>

          </div>

          <div className="dashboard-card">

            <div className="card-icon">
              ⚠️
            </div>

            <h3>
              Risk Score
            </h3>

            <p>
              Current security risk.
            </p>

            <strong>
              {dashboard.risk_score}/100
            </strong>

            <span>
              Risk Level: {dashboard.risk_level}
            </span>

            <div className="risk-breakdown">
              <h4>Why this score?</h4>
              {[
                { key: "ml_anomaly", label: "ML Anomaly", max: 25 },
                { key: "behavior", label: "Behavior Risk", max: 20 },
                { key: "threat_intelligence", label: "Threat Intelligence", max: 25 },
                { key: "attack_chain", label: "Attack Chain", max: 15 },
                { key: "severity", label: "Severity", max: 15 },
              ].map((component) => {
                const value = dashboard.risk_breakdown?.[component.key] ?? 0;
                return (
                  <div className="risk-breakdown-row" key={component.key}>
                    <span>{component.label}</span>
                    <div className="risk-bar-track" aria-label={`${component.label}: ${value} points`}>
                      <div
                        className="risk-bar-fill"
                        style={{ width: `${Math.min(100, (value / component.max) * 100)}%` }}
                      />
                    </div>
                    <b>{value}</b>
                  </div>
                );
              })}
            </div>

          </div>

          <div className="dashboard-card">

            <div className="card-icon">
              🤖
            </div>

            <h3>
              ML Analysis
            </h3>

            <p>
              AI-based threat detection.
            </p>

            <strong>
              {dashboard.ml_anomalies}
            </strong>

            <span>
              ML Anomalies
            </span>

          </div>

        </div>

        <section className="analytics-panel" aria-labelledby="analytics-title">
          <div className="analytics-header">
            <div>
              <h2 id="analytics-title">Security Analytics</h2>
              <p>Aggregated activity from stored security logs and alerts.</p>
            </div>
            <button
              className="analytics-refresh-button"
              type="button"
              onClick={loadAnalytics}
              disabled={analyticsLoading}
            >
              {analyticsLoading ? "Loading..." : "Refresh Analytics"}
            </button>
          </div>

          {analyticsError && (
            <p className="analytics-error" role="alert">{analyticsError}</p>
          )}

          {!analytics && analyticsLoading && (
            <p className="analytics-empty">Loading security analytics...</p>
          )}

          {analytics && (
            <>
              <div className="analytics-summary">
                <article className="analytics-card">
                  <h3>Total Events</h3>
                  <p>{analytics.analytics.total_events}</p>
                </article>
                <article className="analytics-card">
                  <h3>Average Risk</h3>
                  <p>{analytics.analytics.average_risk_score}/100</p>
                </article>
              </div>

              <div className="analytics-breakdowns">
                {[
                  { key: "event_types", title: "Event Types" },
                  { key: "risk_levels", title: "Risk Levels" },
                  { key: "severity_distribution", title: "Severity" },
                ].map((group) => {
                  const entries = Object.entries(analytics.analytics[group.key] || {});
                  return (
                    <section className="analytics-breakdown" key={group.key}>
                      <h3>{group.title}</h3>
                      {entries.length > 0 ? entries.map(([name, count]) => (
                        <div className="analytics-row" key={name}>
                          <strong>{name}</strong>
                          <span>{count}</span>
                        </div>
                      )) : <p className="analytics-empty">No data</p>}
                    </section>
                  );
                })}
              </div>
            </>
          )}
        </section>

        {/* =========================
            SECURITY LOGS
        ========================= */}

        <section className="logs-section">

          <div className="section-header">

            <div>
              <h2>
                🔐 Security Logs
              </h2>

              <p>
                Real-time system security activity
              </p>
            </div>

            <button
              onClick={() => {
                fetchDashboard();
                fetchLogs();
                fetchAlerts();
                loadAnalytics();
              }}
            >
              Refresh
            </button>

          </div>

          {logsLoading && (
            <p className="loading-text">
              Loading security logs...
            </p>
          )}

          {logsError && (
            <p
              style={{
                color: "red",
                marginTop: "15px",
              }}
            >
              {logsError}
            </p>
          )}

          {!logsLoading &&
            !logsError &&
            logs.length === 0 && (
              <p className="empty-text">
                No security logs found.
              </p>
            )}

          {!logsLoading &&
            logs.length > 0 && (

              <div className="table-container">

                <table>

                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Username</th>
                      <th>IP Address</th>
                      <th>Event</th>
                      <th>Status</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>

                  <tbody>

                    {logs.map((log) => (

                      <tr key={log.id}>

                        <td>
                          {log.id ?? "-"}
                        </td>

                        <td>
                          {log.username ??
                            log.user ??
                            "-"}
                        </td>

                        <td>
                          {log.ip_address ??
                            log.ip ??
                            "-"}
                        </td>

                        <td>
                          {log.event_type ??
                            log.event ??
                            log.action ??
                            "-"}
                        </td>

                        <td>

                          <span
                            className={
                              log.status ===
                              "success"
                                ? "status-success"
                                : "status-failed"
                            }
                          >
                            {log.status ?? "-"}
                          </span>

                        </td>

                        <td>
                          {log.timestamp
                            ? new Date(
                                log.timestamp
                              ).toLocaleString()
                            : "-"}
                        </td>

                      </tr>

                    ))}

                  </tbody>

                </table>

              </div>

            )}

        </section>

        {/* =========================
            THREAT ALERTS
        ========================= */}

        <section className="logs-section">

          <div className="section-header">

            <div>

              <h2>
                🚨 Threat Alerts
              </h2>

              <p>
                AI-detected security threats
              </p>

            </div>

            <button
              onClick={() => {
                fetchAlerts();
                fetchDashboard();
              }}
            >
              Refresh Alerts
            </button>

          </div>

          {/* LOADING */}

          {alertsLoading && (
            <p className="loading-text">
              Loading threat alerts...
            </p>
          )}

          {/* ERROR */}

          {alertsError && (
            <p
              style={{
                color: "red",
                marginTop: "15px",
              }}
            >
              {alertsError}
            </p>
          )}

          {/* EMPTY */}

          {!alertsLoading &&
            !alertsError &&
            alerts.length === 0 && (
              <p className="empty-text">
                No threat alerts found.
              </p>
            )}

          {/* ALERT TABLE */}

          {!alertsLoading &&
            alerts.length > 0 && (

              <div className="table-container">

                <table>

                  <thead>

                    <tr>
                      <th>Alert ID</th>
                      <th>IP Address</th>
                      <th>Username</th>
                      <th>Threat Type</th>
                      <th>Threat Level</th>
                      <th>Confidence</th>
                      <th>Risk Score</th>
                      <th>ML Anomaly</th>
                      <th>Recommended Action</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>

                  </thead>

                  <tbody>

                    {alerts.map((alert) => (

                      <tr key={alert.id}>

                        {/* ALERT ID */}

                        <td>
                          {alert.id ?? "-"}
                        </td>

                        {/* IP ADDRESS */}

                        <td>
                          {alert.ip_address ?? "-"}
                        </td>

                        {/* USERNAME */}

                        <td>
                          {alert.username ?? "-"}
                        </td>

                        {/* THREAT TYPE */}

                        <td>
                          <strong>
                            {alert.threat_type ?? "-"}
                          </strong>
                        </td>

                        {/* THREAT LEVEL */}

                        <td>

                          <span
                            style={{
                              fontWeight:
                                "bold",
                              textTransform:
                                "capitalize",
                            }}
                          >
                            {alert.threat_level ??
                              "-"}
                          </span>

                        </td>

                        {/* CONFIDENCE */}

                        <td>

                          {alert.confidence !==
                            null &&
                          alert.confidence !==
                            undefined
                            ? `${alert.confidence}%`
                            : "-"}

                        </td>

                        {/* RISK SCORE */}

                        <td>

                          <strong>
                            {alert.risk_score ??
                              0}
                          </strong>

                        </td>

                        {/* ML ANOMALY */}

                        <td>

                          {alert.ml_anomaly ? (
                            <strong>
                              Yes
                            </strong>
                          ) : (
                            <span>
                              No
                            </span>
                          )}

                        </td>

                        {/* RECOMMENDED ACTION */}

                        <td>
                          {alert.recommended_action ??
                            "-"}
                        </td>

                        {/* STATUS */}

                        <td>

                          <span
                            style={{
                              fontWeight:
                                "bold",
                              textTransform:
                                "capitalize",
                            }}
                          >
                            {alert.status ??
                              "open"}
                          </span>

                        </td>

                        {/* ACTION */}

                        <td>

                          {alert.status ===
                            "open" && (

                            <button
                              onClick={() =>
                                updateAlertStatus(
                                  alert.id,
                                  "investigating"
                                )
                              }
                            >
                              Investigate
                            </button>

                          )}

                          {alert.status ===
                            "investigating" && (

                            <button
                              onClick={() =>
                                updateAlertStatus(
                                  alert.id,
                                  "resolved"
                                )
                              }
                            >
                              Resolve
                            </button>

                          )}

                          {alert.status ===
                            "resolved" && (

                            <span>
                              ✓ Resolved
                            </span>

                          )}

                        </td>

                      </tr>

                    ))}

                  </tbody>

                </table>

              </div>

            )}

        </section>

        <section className="logs-section" style={{ marginTop: "30px" }}>
          <div className="section-header">
            <div>
              <h2>🤖 AI Security Copilot</h2>
              <p>Ask about alerts, user behavior, IPs, and recommended actions.</p>
            </div>
            <button
              className="copilot-run-button"
              type="button"
              onClick={runSecurityCopilot}
              disabled={securityCopilotLoading}
            >
              {securityCopilotLoading ? "Analyzing..." : "🤖 Analyze Event"}
            </button>
          </div>

          <div
            style={{
              border: "1px solid #2d3748",
              background: "#0f172a",
              borderRadius: "12px",
              padding: "20px",
              minHeight: "220px",
              display: "flex",
              flexDirection: "column",
              gap: "12px",
            }}
          >
            {copilotMessages.map((message, idx) => (
              <div
                key={idx}
                style={{
                  alignSelf: message.role === "user" ? "flex-end" : "flex-start",
                  maxWidth: "80%",
                  background:
                    message.role === "user" ? "#2563eb" : "#1f2937",
                  color: "#fff",
                  padding: "10px 14px",
                  borderRadius: "12px",
                  lineHeight: 1.5,
                }}
              >
                {message.text}
              </div>
            ))}

            <form onSubmit={askCopilot} style={{ marginTop: "auto" }}>
              <div style={{ display: "flex", gap: "10px" }}>
                <input
                  type="text"
                  value={copilotQuestion}
                  onChange={(e) => setCopilotQuestion(e.target.value)}
                  placeholder="Ask Security Copilot..."
                  style={{
                    flex: 1,
                    padding: "12px 14px",
                    borderRadius: "10px",
                    border: "1px solid #475569",
                    background: "#020817",
                    color: "#fff",
                  }}
                />
                <button type="submit" disabled={copilotLoading}>
                  {copilotLoading ? "Thinking..." : "Ask"}
                </button>
              </div>
            </form>
          </div>

          {securityCopilotError && (
            <p className="security-copilot-error" role="alert">
              {securityCopilotError}
            </p>
          )}

          {securityCopilot && (
            <div className="security-copilot-result" aria-live="polite">
              <div className="security-copilot-result-header">
                <div>
                  <h3>Security Analysis</h3>
                  <p>{securityCopilot.summary}</p>
                </div>
                <span className="security-copilot-level">
                  {securityCopilot.risk_level}
                </span>
              </div>

              <p className="security-copilot-score">
                <strong>Risk</strong>
                <span>{securityCopilot.risk_score}/100</span>
              </p>

              {securityCopilot.detected_patterns?.length > 0 && (
                <div className="security-copilot-list">
                  <h4>Detected Patterns</h4>
                  <ul>
                    {securityCopilot.detected_patterns.map((pattern, index) => (
                      <li key={`${pattern}-${index}`}>{pattern}</li>
                    ))}
                  </ul>
                </div>
              )}

              {securityCopilot.behavior_anomalies?.length > 0 && (
                <div className="security-copilot-list">
                  <h4>Behavior Anomalies</h4>
                  <ul>
                    {securityCopilot.behavior_anomalies.map((anomaly, index) => (
                      <li key={`${anomaly}-${index}`}>{anomaly}</li>
                    ))}
                  </ul>
                </div>
              )}

              {securityCopilot.indicators?.length > 0 && (
                <div className="security-copilot-list">
                  <h4>Indicators</h4>
                  <ul>
                    {securityCopilot.indicators.map((indicator, index) => (
                      <li key={`${indicator.type}-${indicator.value}-${index}`}>
                        {indicator.type}: {indicator.value}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="security-copilot-list">
                <h4>Recommended Actions</h4>
                <ul>
                  {securityCopilot.recommendations.map((recommendation, index) => (
                    <li key={`${recommendation}-${index}`}>{recommendation}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </section>

      </main>

    </div>
  );
}

export default App;