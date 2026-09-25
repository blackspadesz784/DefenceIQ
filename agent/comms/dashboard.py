"""DefenceIQ - Embedded Web Companion Dashboard & Mobile Console.

Provides an ultra-sleek, responsive Cyberpunk Dark web interface that works
identically on mobile phone browsers and laptop browsers without IP dependency.
Supports token-based pairing, real-time threat telemetry, push alerts,
least-privilege scope visualization, and reversible containment rollbacks.
"""

def get_dashboard_html() -> str:
    """Returns the complete single-page interactive Cyberpunk Dashboard HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>DefenceIQ | AI Endpoint Security & Mobile Threat Monitor</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0a0d14;
      --bg-card: rgba(18, 24, 38, 0.85);
      --bg-card-border: rgba(0, 229, 255, 0.18);
      --accent-cyan: #00e5ff;
      --accent-green: #00ff88;
      --accent-yellow: #ffd600;
      --accent-orange: #ff9100;
      --accent-red: #ff1744;
      --text-main: #f0f4f8;
      --text-muted: #8899aa;
      --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.45);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      -webkit-tap-highlight-color: transparent;
    }

    body {
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(circle at 15% 15%, rgba(0, 229, 255, 0.05) 0%, transparent 40%),
        radial-gradient(circle at 85% 85%, rgba(0, 255, 136, 0.04) 0%, transparent 40%);
      color: var(--text-main);
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
      min-height: 100vh;
      padding-bottom: 50px;
    }

    header {
      padding: 16px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(10, 13, 20, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--bg-card-border);
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-icon {
      width: 36px;
      height: 36px;
      border-radius: 9px;
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-green));
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      color: #050811;
      font-size: 16px;
      box-shadow: 0 0 15px rgba(0, 229, 255, 0.4);
    }

    .brand-title {
      font-size: 20px;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(90deg, #fff, var(--accent-cyan));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand-sub {
      font-size: 11px;
      color: var(--accent-green);
      font-family: 'JetBrains Mono', monospace;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .token-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      background: rgba(0, 229, 255, 0.1);
      border: 1px solid rgba(0, 229, 255, 0.3);
      padding: 6px 12px;
      border-radius: 20px;
      color: var(--accent-cyan);
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .container {
      max-width: 920px;
      margin: 0 auto;
      padding: 20px 16px;
    }

    /* Cards */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--bg-card-border);
      border-radius: 16px;
      padding: 20px;
      box-shadow: var(--glass-shadow);
      margin-bottom: 20px;
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }

    .card-title {
      font-size: 15px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      color: var(--accent-cyan);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Input & Button elements */
    .input-group {
      display: flex;
      gap: 8px;
      margin-top: 14px;
      flex-wrap: wrap;
    }

    input[type="text"] {
      background: rgba(5, 8, 17, 0.8);
      border: 1px solid rgba(0, 229, 255, 0.3);
      color: #fff;
      font-family: 'JetBrains Mono', monospace;
      font-size: 15px;
      padding: 10px 14px;
      border-radius: 10px;
      flex: 1;
      min-width: 180px;
      text-transform: uppercase;
      outline: none;
    }

    input[type="text"]:focus {
      border-color: var(--accent-cyan);
      box-shadow: 0 0 12px rgba(0, 229, 255, 0.3);
    }

    .btn {
      border: none;
      font-weight: 700;
      padding: 10px 18px;
      border-radius: 10px;
      cursor: pointer;
      font-size: 13px;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .btn-primary {
      background: linear-gradient(135deg, var(--accent-cyan), #0091ea);
      color: #050811;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text-main);
      border: 1px solid rgba(255, 255, 255, 0.15);
    }

    .btn-danger {
      background: rgba(255, 23, 68, 0.15);
      color: var(--accent-red);
      border: 1px solid rgba(255, 23, 68, 0.4);
    }

    .btn:active {
      transform: scale(0.97);
    }

    /* Hero Health Badge */
    .health-card {
      background: var(--bg-card);
      border: 1px solid var(--bg-card-border);
      border-radius: 20px;
      padding: 24px;
      box-shadow: var(--glass-shadow);
      margin-bottom: 20px;
      display: flex;
      flex-direction: column;
      align-items: center;
      position: relative;
      overflow: hidden;
    }

    .health-circle {
      width: 110px;
      height: 110px;
      border-radius: 50%;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      margin-bottom: 12px;
      box-shadow: 0 0 30px rgba(0, 255, 136, 0.25);
      border: 3px solid var(--accent-green);
      transition: all 0.4s ease;
    }

    .health-state-title {
      font-size: 22px;
      font-weight: 800;
      letter-spacing: 0.5px;
    }

    .health-subtitle {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 4px;
      text-align: center;
    }

    /* Device Info Banner */
    .device-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(0, 229, 255, 0.05);
      border: 1px solid rgba(0, 229, 255, 0.15);
      border-radius: 12px;
      padding: 12px 16px;
      margin-bottom: 18px;
      flex-wrap: wrap;
      gap: 10px;
    }

    .device-info-col {
      display: flex;
      flex-direction: column;
    }

    .device-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }

    .device-value {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-main);
    }

    /* Privacy Banner */
    .privacy-notice {
      background: rgba(0, 255, 136, 0.05);
      border-left: 3px solid var(--accent-green);
      padding: 10px 14px;
      border-radius: 0 8px 8px 0;
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 14px;
      line-height: 1.5;
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }

    .stat-pill {
      background: var(--bg-card);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 14px;
      text-align: center;
    }

    .stat-num {
      font-size: 20px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent-cyan);
    }

    .stat-label {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 4px;
    }

    /* Threat Alerts Feed */
    .alert-card {
      background: rgba(14, 19, 31, 0.9);
      border-radius: 14px;
      padding: 16px;
      margin-bottom: 12px;
      border-left: 4px solid var(--accent-cyan);
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
      transition: all 0.2s ease;
    }

    .alert-card.RED {
      border-left-color: var(--accent-red);
      background: rgba(255, 23, 68, 0.06);
    }

    .alert-card.ORANGE {
      border-left-color: var(--accent-orange);
      background: rgba(255, 145, 0, 0.06);
    }

    .alert-card.YELLOW {
      border-left-color: var(--accent-yellow);
      background: rgba(255, 214, 0, 0.05);
    }

    .alert-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }

    .alert-title {
      font-size: 15px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .badge-band {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 6px;
    }

    .badge-RED { background: var(--accent-red); color: #fff; }
    .badge-ORANGE { background: var(--accent-orange); color: #000; }
    .badge-YELLOW { background: var(--accent-yellow); color: #000; }
    .badge-GREEN { background: var(--accent-green); color: #000; }

    .alert-meta {
      font-size: 12px;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
      margin-bottom: 8px;
    }

    .alert-action-rec {
      font-size: 13px;
      color: #cbd5e1;
      margin: 8px 0;
      line-height: 1.4;
    }

    .alert-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }

    .chip {
      background: rgba(255, 255, 255, 0.08);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 6px;
      color: #94a3b8;
    }

    /* Live pulse */
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent-green);
      display: inline-block;
      margin-right: 6px;
      box-shadow: 0 0 10px var(--accent-green);
      animation: pulse 1.5s infinite;
    }

    @keyframes pulse {
      0% { opacity: 0.4; }
      50% { opacity: 1; transform: scale(1.2); }
      100% { opacity: 0.4; }
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="brand-icon">DIQ</div>
      <div>
        <div class="brand-title">DefenceIQ</div>
        <div class="brand-sub"><span class="pulse-dot"></span>Secure Sentinel</div>
      </div>
    </div>
    <div class="header-actions">
      <div id="token-display" class="token-badge" onclick="showPairingModal()">
        <span>🔑 TOKEN:</span>
        <span id="current-token-text">LOADING</span>
      </div>
    </div>
  </header>

  <div class="container">

    <!-- Device Identity Banner -->
    <div class="device-banner">
      <div class="device-info-col">
        <span class="device-label">Device Identity</span>
        <span class="device-value" id="dev-hostname">Connecting...</span>
      </div>
      <div class="device-info-col">
        <span class="device-label">Unique Device ID</span>
        <span class="device-value" id="dev-id" style="font-family: 'JetBrains Mono', monospace;">--</span>
      </div>
      <div class="device-info-col">
        <span class="device-label">Messaging Channel</span>
        <span class="device-value" id="dev-channel" style="color: var(--accent-green);">E2E Relay (IP-Independent)</span>
      </div>
      <div class="device-info-col">
        <span class="device-label">Token Management</span>
        <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="showPairingModal()">Pair / Rotate</button>
      </div>
    </div>

    <!-- Pairing Modal Card (Collapsible or Prompt) -->
    <div id="pairing-card" class="card" style="display: none; border-color: var(--accent-cyan);">
      <div class="card-header">
        <span class="card-title">🔗 Link Mobile & Laptop (Token Pairing)</span>
        <button class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="hidePairingModal()">✕ Close</button>
      </div>
      <p style="font-size: 13px; color: var(--text-muted); line-height: 1.5;">
        Pair your laptop with the DefenceIQ Mobile App using a unique token. <strong>No IP addresses, port forwarding, or local Wi-Fi pairing required</strong> — devices communicate securely anywhere over an authenticated, end-to-end encrypted messaging relay.
      </p>

      <div class="input-group">
        <input type="text" id="token-input" placeholder="e.g. DIQ-8K2A-9X1B or 11C6C497">
        <button class="btn btn-primary" onclick="submitPairingToken()">Pair Laptop with Token</button>
        <button class="btn btn-secondary" onclick="generateNewMobileToken()">Generate Mobile Token</button>
        <button class="btn btn-danger" onclick="revokePairingToken()">Revoke / Unpair</button>
      </div>

      <div class="privacy-notice">
        <strong>Privacy & Security Guarantee:</strong> All threat telemetry and alerts transmitted between devices are strictly metadata-only (process name, SHA-256 hash, entropy score, risk signals). Sensitive document and file contents are never read or transmitted.
      </div>
    </div>

    <!-- Hero Health Card -->
    <div class="health-card">
      <div id="health-circle" class="health-circle">
        <span style="font-size: 32px;" id="health-icon">🛡️</span>
      </div>
      <div class="health-state-title" id="health-title">SECURE</div>
      <div class="health-subtitle" id="health-subtitle">Real-time layered defense active across processes, files, network & USB</div>
    </div>

    <!-- Metrics Grid -->
    <div class="stats-grid">
      <div class="stat-pill">
        <div class="stat-num" id="stat-pids">--</div>
        <div class="stat-label">Monitored PIDs</div>
      </div>
      <div class="stat-pill">
        <div class="stat-num" id="stat-sockets">--</div>
        <div class="stat-label">Active Sockets</div>
      </div>
      <div class="stat-pill">
        <div class="stat-num" id="stat-threats">0</div>
        <div class="stat-label">Total Threats</div>
      </div>
      <div class="stat-pill">
        <div class="stat-num" style="color: var(--accent-green);" id="stat-rollbacks">0</div>
        <div class="stat-label">Rollbacks</div>
      </div>
    </div>

    <!-- Authorized Monitoring Scope Card -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">📁 User-Authorized Monitoring Scope</span>
        <span style="font-size: 11px; color: var(--accent-green); font-family: 'JetBrains Mono', monospace;">LEAST PRIVILEGE</span>
      </div>
      <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 10px;">
        The security agent continuously protects these authorized directories without exposing file contents:
      </p>
      <div id="authorized-paths-list" class="alert-chips">
        <span class="chip">Downloads (Watchdog + PE Entropy)</span>
        <span class="chip">Desktop (Executable Filter)</span>
        <span class="chip">Documents (Mass Encryption Watcher)</span>
        <span class="chip">Startup Keys (Persistence Sentinel)</span>
      </div>
    </div>

    <!-- Live Threat Alerts & Activity Logs -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">🚨 Real-Time Threat Alerts & Push Log</span>
        <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="fetchIncidents()">Refresh</button>
      </div>

      <div id="alerts-container">
        <div style="text-align: center; color: var(--text-muted); padding: 30px; font-size: 13px;">
          Listening for security telemetry events... All endpoint monitors operational.
        </div>
      </div>
    </div>

  </div>

  <script>
    let currentToken = localStorage.getItem("defenceiq_pairing_token") || "11C6C497";
    let ws = null;

    // Check URL parameters for ?token=XXXX
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("token")) {
      currentToken = urlParams.get("token").toUpperCase();
      localStorage.setItem("defenceiq_pairing_token", currentToken);
    }

    function showPairingModal() {
      document.getElementById("pairing-card").style.display = "block";
    }

    function hidePairingModal() {
      document.getElementById("pairing-card").style.display = "none";
    }

    function generateNewMobileToken() {
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      let p1 = "", p2 = "";
      for (let i = 0; i < 4; i++) p1 += chars.charAt(Math.floor(Math.random() * chars.length));
      for (let i = 0; i < 4; i++) p2 += chars.charAt(Math.floor(Math.random() * chars.length));
      const generated = "DIQ-" + p1 + "-" + p2;
      document.getElementById("token-input").value = generated;
    }

    async function submitPairingToken() {
      const val = document.getElementById("token-input").value.trim().toUpperCase();
      if (!val || val.length < 4) {
        alert("Please enter a valid pairing token (at least 4 characters).");
        return;
      }
      try {
        const res = await fetch("/pair-mobile", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: val })
        });
        const data = await res.json();
        if (data.success) {
          currentToken = val;
          localStorage.setItem("defenceiq_pairing_token", currentToken);
          document.getElementById("current-token-text").innerText = currentToken;
          alert("Successfully paired laptop with token: " + currentToken);
          hidePairingModal();
          init();
        } else {
          alert("Pairing failed: " + (data.detail || "Unknown error"));
        }
      } catch (e) {
        alert("Error during pairing: " + e.message);
      }
    }

    async function revokePairingToken() {
      if (!confirm("Are you sure you want to unpair mobile device and revoke this token?")) return;
      try {
        const res = await fetch("/revoke-pairing", { method: "POST" });
        const data = await res.json();
        if (data.success) {
          alert("Pairing revoked and security secrets rotated.");
          currentToken = data.new_token || "";
          localStorage.setItem("defenceiq_pairing_token", currentToken);
          document.getElementById("current-token-text").innerText = currentToken;
          hidePairingModal();
          init();
        }
      } catch (e) {
        alert("Error revoking pairing: " + e.message);
      }
    }

    async function init() {
      document.getElementById("current-token-text").innerText = currentToken || "NOT SET";
      if (!currentToken) showPairingModal();

      // Request browser notification permission for real-time threat alerts
      if ("Notification" in window && Notification.permission === "default") {
        Notification.requestPermission();
      }

      await fetchStatus();
      await fetchIncidents();
      connectWebSocket();
    }

    async function fetchStatus() {
      try {
        const res = await fetch("/status?token=" + encodeURIComponent(currentToken));
        if (res.ok) {
          const data = await res.json();
          document.getElementById("dev-hostname").innerText = data.hostname || "Laptop";
          document.getElementById("dev-id").innerText = "LAPTOP-" + (data.hostname ? data.hostname.substring(0, 8).toUpperCase() : "SECURE");
          document.getElementById("stat-pids").innerText = data.monitored_pids_count || 0;
          document.getElementById("stat-sockets").innerText = data.active_sockets_count || 0;
          
          if (data.stats) {
            document.getElementById("stat-threats").innerText = data.stats.total_incidents || 0;
            document.getElementById("stat-rollbacks").innerText = data.stats.total_actions || 0;
          }

          updateHealthUI(data.health_state);
        }
      } catch (e) {
        console.debug("Status fetch:", e);
      }
    }

    function updateHealthUI(state) {
      const circle = document.getElementById("health-circle");
      const title = document.getElementById("health-title");
      const sub = document.getElementById("health-subtitle");
      const icon = document.getElementById("health-icon");

      if (state === "CRITICAL_THREAT") {
        circle.style.borderColor = "var(--accent-red)";
        circle.style.boxShadow = "0 0 30px rgba(255, 23, 68, 0.4)";
        title.innerText = "CRITICAL THREAT";
        title.style.color = "var(--accent-red)";
        icon.innerText = "🚨";
        sub.innerText = "High-confidence anomaly detected. Automated containment active.";
      } else if (state === "ELEVATED_RISK") {
        circle.style.borderColor = "var(--accent-orange)";
        circle.style.boxShadow = "0 0 30px rgba(255, 145, 0, 0.35)";
        title.innerText = "ELEVATED RISK";
        title.style.color = "var(--accent-orange)";
        icon.innerText = "⚠️";
        sub.innerText = "Multiple contributing threat signals correlated across processes and network.";
      } else {
        circle.style.borderColor = "var(--accent-green)";
        circle.style.boxShadow = "0 0 30px rgba(0, 255, 136, 0.25)";
        title.innerText = "SECURE";
        title.style.color = "var(--accent-green)";
        icon.innerText = "🛡️";
        sub.innerText = "All 4 endpoint monitors & ML detection layers active.";
      }
    }

    async function fetchIncidents() {
      try {
        const res = await fetch("/incidents?limit=20&token=" + encodeURIComponent(currentToken));
        if (res.ok) {
          const data = await res.json();
          renderIncidents(data.incidents || []);
        }
      } catch (e) {
        console.debug("Incidents fetch:", e);
      }
    }

    function renderIncidents(incidents) {
      const container = document.getElementById("alerts-container");
      if (!incidents || incidents.length === 0) {
        container.innerHTML = `
          <div style="text-align: center; color: var(--text-muted); padding: 30px; font-size: 13px;">
            No threats detected. All monitored directories and processes are behaving normally.
          </div>
        `;
        return;
      }

      container.innerHTML = incidents.map(inc => {
        const band = inc.risk_band || "GREEN";
        const score = inc.risk_score || 0;
        const proc = inc.root_process_name || "Process";
        const pid = inc.root_pid ? `(PID ${inc.root_pid})` : "";
        const signals = (inc.signals || []).map(s => `<span class="chip">${s}</span>`).join("");
        const files = (inc.touched_files || []).slice(0, 3).map(f => `<span class="chip">📄 ${f.split(/[\\\\/]/).pop()}</span>`).join("");
        const rollbackBtn = (inc.status === "CONTAINED" || inc.status === "OPEN")
          ? `<button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="triggerRollback('${inc.incident_id}')">Undo Containment (Rollback)</button>`
          : `<span style="font-size: 11px; color: var(--accent-green); font-family: 'JetBrains Mono', monospace;">✓ ${inc.status}</span>`;

        return `
          <div class="alert-card ${band}">
            <div class="alert-header">
              <span class="alert-title">
                <span>${band === "RED" ? "🚨" : (band === "ORANGE" ? "⚠️" : "🛡️")}</span>
                <span>${proc} ${pid}</span>
              </span>
              <span class="badge-band badge-${band}">${band} • ${score}/100</span>
            </div>
            <div class="alert-meta">
              ID: ${inc.incident_id ? inc.incident_id.substring(0, 8) : "--"} | Time: ${inc.updated_at ? new Date(inc.updated_at).toLocaleTimeString() : "--"}
            </div>
            <div class="alert-action-rec">
              ${inc.explanation || "Suspicious behavioral signals detected by DefenceIQ Event Correlator."}
            </div>
            ${files ? `<div class="alert-chips" style="margin-bottom: 6px;">${files}</div>` : ""}
            <div class="alert-chips">${signals}</div>
            <div style="margin-top: 12px; display: flex; justify-content: flex-end;">
              ${rollbackBtn}
            </div>
          </div>
        `;
      }).join("");
    }

    async function triggerRollback(incidentId) {
      if (!confirm("Execute automated rollback to restore files/unblock firewall for this incident?")) return;
      try {
        const res = await fetch(`/incidents/${incidentId}/rollback?token=` + encodeURIComponent(currentToken), { method: "POST" });
        const data = await res.json();
        if (data.success) {
          alert("Rollback executed successfully!");
          fetchIncidents();
          fetchStatus();
        } else {
          alert("Rollback failed: " + (data.detail || "Error"));
        }
      } catch (e) {
        alert("Rollback error: " + e.message);
      }
    }

    function connectWebSocket() {
      if (ws) ws.close();
      const loc = window.location;
      const wsProto = loc.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${wsProto}//${loc.host}/ws/alerts?token=${encodeURIComponent(currentToken)}`;

      ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const frame = JSON.parse(event.data);
          if (frame.type === "incident") {
            fetchIncidents();
            fetchStatus();
            // Show browser notification if permitted
            if ("Notification" in window && Notification.permission === "granted") {
              const inc = frame.incident || {};
              new Notification(`DefenceIQ Alert: ${inc.root_process_name || 'Threat'}`, {
                body: `Score: ${inc.risk_score}/100 [${inc.risk_band}]. ${inc.explanation || ''}`,
                icon: "/favicon.ico"
              });
            }
          } else if (frame.type === "action" || frame.type === "incident_rollback" || frame.type === "paired_mobile") {
            fetchStatus();
            fetchIncidents();
          }
        } catch (e) {}
      };

      ws.onclose = () => {
        setTimeout(connectWebSocket, 4000);
      };
    }

    window.addEventListener("DOMContentLoaded", init);
  </script>
</body>
</html>"""
