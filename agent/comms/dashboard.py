"""DefenceIQ - Embedded Web Companion Dashboard & Mobile Console.

Provides an ultra-sleek, responsive Cyberpunk Dark web interface that works
identically on mobile phone browsers and laptop browsers without IP dependency.
Supports token-based pairing, real-time threat telemetry, push alerts,
RED ALERTS, active windows/tabs monitoring, downloads, file/folder events,
least-privilege scope visualization, and reversible containment rollbacks.
"""

def get_dashboard_html() -> str:
    """Returns the complete single-page interactive Cyber-Dark Dashboard HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>DefenceIQ | AI Endpoint Security & Mobile Threat Monitor</title>
  <link rel="manifest" href="/manifest.json">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="DefenceIQ">
  <meta name="theme-color" content="#00e5ff">
  <link rel="apple-touch-icon" href="/icon-192.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #070a12;
      --bg-card: rgba(14, 20, 34, 0.90);
      --bg-card-hover: rgba(20, 28, 48, 0.95);
      --bg-card-border: rgba(0, 229, 255, 0.18);
      --accent-cyan: #00e5ff;
      --accent-green: #00ff88;
      --accent-yellow: #ffd600;
      --accent-orange: #ff9100;
      --accent-red: #ff1744;
      --accent-purple: #b388ff;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --glass-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
      --red-glow: 0 0 25px rgba(255, 23, 68, 0.45);
      --cyan-glow: 0 0 20px rgba(0, 229, 255, 0.35);
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
        radial-gradient(circle at 10% 10%, rgba(0, 229, 255, 0.06) 0%, transparent 45%),
        radial-gradient(circle at 90% 90%, rgba(0, 255, 136, 0.05) 0%, transparent 45%),
        linear-gradient(180deg, #070a12 0%, #0a0e1a 100%);
      color: var(--text-main);
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
      min-height: 100vh;
      padding-bottom: 70px;
    }

    /* Top Sticky App Bar */
    header {
      padding: 12px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(8, 12, 22, 0.88);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--bg-card-border);
      position: sticky;
      top: 0;
      z-index: 1000;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      cursor: pointer;
    }

    .brand-icon {
      width: 36px;
      height: 36px;
      border-radius: 10px;
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
      font-size: 19px;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(90deg, #ffffff, var(--accent-cyan));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand-sub {
      font-size: 10px;
      color: var(--accent-green);
      font-family: 'JetBrains Mono', monospace;
      text-transform: uppercase;
      letter-spacing: 1px;
      display: flex;
      align-items: center;
      gap: 4px;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-pill {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 700;
      padding: 5px 10px;
      border-radius: 20px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
      transition: all 0.3s ease;
    }

    .status-pill.online {
      background: rgba(0, 255, 136, 0.12);
      border-color: rgba(0, 255, 136, 0.4);
      color: var(--accent-green);
    }

    .status-pill.offline {
      background: rgba(148, 163, 184, 0.12);
      border-color: rgba(148, 163, 184, 0.3);
      color: var(--text-muted);
    }

    .status-pill.sleep {
      background: rgba(179, 136, 255, 0.15);
      border-color: rgba(179, 136, 255, 0.4);
      color: var(--accent-purple);
    }

    .status-pill.shutdown {
      background: rgba(255, 23, 68, 0.15);
      border-color: rgba(255, 23, 68, 0.4);
      color: var(--accent-red);
    }

    .token-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      background: rgba(0, 229, 255, 0.1);
      border: 1px solid rgba(0, 229, 255, 0.3);
      padding: 5px 10px;
      border-radius: 20px;
      color: var(--accent-cyan);
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 5px;
      transition: all 0.2s ease;
    }

    .token-badge:hover {
      background: rgba(0, 229, 255, 0.2);
    }

    /* Red Alert Banner (Top Warning Bar) */
    #red-alert-banner {
      display: none;
      background: linear-gradient(90deg, rgba(255, 23, 68, 0.95), rgba(183, 28, 28, 0.95));
      color: #fff;
      padding: 14px 18px;
      box-shadow: var(--red-glow);
      border-bottom: 2px solid #ff5252;
      animation: alertPulse 2s infinite alternate;
      position: sticky;
      top: 60px;
      z-index: 990;
    }

    @keyframes alertPulse {
      0% { filter: brightness(1); }
      100% { filter: brightness(1.15); }
    }

    .red-alert-content {
      max-width: 960px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .red-alert-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 16px;
      font-weight: 800;
      letter-spacing: 0.5px;
    }

    .red-alert-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 6px 14px;
      font-size: 13px;
      background: rgba(0, 0, 0, 0.25);
      padding: 10px;
      border-radius: 8px;
    }

    .red-alert-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 6px;
    }

    /* Main Container & Nav Tabs */
    .container {
      max-width: 960px;
      margin: 0 auto;
      padding: 16px;
    }

    .nav-tabs {
      display: flex;
      gap: 8px;
      overflow-x: auto;
      padding-bottom: 12px;
      margin-bottom: 16px;
      scrollbar-width: none;
    }
    .nav-tabs::-webkit-scrollbar { display: none; }

    .tab-btn {
      background: rgba(14, 20, 34, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--text-muted);
      padding: 9px 15px;
      border-radius: 12px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      white-space: nowrap;
      transition: all 0.2s ease;
      font-family: inherit;
    }

    .tab-btn:hover {
      background: var(--bg-card-hover);
      color: var(--text-main);
    }

    .tab-btn.active {
      background: rgba(0, 229, 255, 0.15);
      border-color: var(--accent-cyan);
      color: var(--accent-cyan);
      box-shadow: 0 0 14px rgba(0, 229, 255, 0.2);
    }

    /* Tab content view */
    .tab-pane {
      display: none;
      animation: fadeIn 0.25s ease-in;
    }
    .tab-pane.active {
      display: block;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Cards */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--bg-card-border);
      border-radius: 18px;
      padding: 20px;
      box-shadow: var(--glass-shadow);
      margin-bottom: 18px;
      position: relative;
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
      flex-wrap: wrap;
      gap: 8px;
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

    /* Hero Health Badge */
    .health-hero {
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      padding: 16px 0 8px;
    }

    .health-circle {
      width: 100px;
      height: 100px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 12px;
      border: 3px solid var(--accent-green);
      box-shadow: 0 0 30px rgba(0, 255, 136, 0.25);
      font-size: 38px;
      transition: all 0.4s ease;
    }

    .health-state-text {
      font-size: 22px;
      font-weight: 800;
      letter-spacing: 1px;
      margin-bottom: 4px;
    }

    .health-desc {
      font-size: 13px;
      color: var(--text-muted);
      max-width: 480px;
    }

    /* Hardware Gauges Grid */
    .gauges-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 12px;
      margin-top: 18px;
    }

    .gauge-box {
      background: rgba(5, 8, 16, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 12px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .gauge-label {
      font-size: 11px;
      text-transform: uppercase;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
    }

    .gauge-value {
      font-size: 18px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent-cyan);
    }

    .gauge-bar-bg {
      height: 6px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 3px;
      overflow: hidden;
    }

    .gauge-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green));
      width: 0%;
      transition: width 0.5s ease;
      border-radius: 3px;
    }

    /* Live Activity Hero Window */
    .active-window-card {
      background: linear-gradient(135deg, rgba(0, 229, 255, 0.07), rgba(14, 20, 34, 0.95));
      border: 1px solid rgba(0, 229, 255, 0.3);
      border-radius: 16px;
      padding: 18px;
      margin-bottom: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .active-window-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }

    .app-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(0, 229, 255, 0.15);
      border: 1px solid rgba(0, 229, 255, 0.4);
      padding: 6px 12px;
      border-radius: 10px;
      font-weight: 700;
      font-size: 14px;
      color: #fff;
    }

    .duration-ticker {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      color: var(--accent-green);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .tab-title-display {
      font-size: 16px;
      font-weight: 600;
      color: #fff;
      word-break: break-word;
    }

    .domain-chip {
      background: rgba(255, 214, 0, 0.12);
      border: 1px solid rgba(255, 214, 0, 0.35);
      color: var(--accent-yellow);
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      padding: 3px 9px;
      border-radius: 6px;
      display: inline-block;
      align-self: flex-start;
    }

    /* Privacy Banner */
    .privacy-box {
      background: rgba(0, 255, 136, 0.06);
      border-left: 3px solid var(--accent-green);
      padding: 12px 14px;
      border-radius: 0 10px 10px 0;
      font-size: 12px;
      color: #cbd5e1;
      line-height: 1.5;
      margin: 12px 0;
    }

    /* Tables & Feed Lists */
    .item-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .item-card {
      background: rgba(10, 15, 26, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.07);
      border-radius: 12px;
      padding: 14px;
      transition: all 0.2s ease;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .item-card:hover {
      border-color: rgba(0, 229, 255, 0.3);
      background: rgba(14, 21, 36, 0.85);
    }

    .item-card-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 6px;
    }

    .item-name {
      font-weight: 700;
      font-size: 14px;
      color: #fff;
      word-break: break-all;
    }

    .item-meta {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .item-chips {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 4px;
    }

    .chip {
      background: rgba(255, 255, 255, 0.06);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 2px 7px;
      border-radius: 5px;
      color: var(--text-muted);
    }

    /* Severity Badges */
    .badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .badge-CRITICAL, .badge-RED { background: var(--accent-red); color: #fff; }
    .badge-HIGH, .badge-ORANGE { background: var(--accent-orange); color: #000; }
    .badge-MEDIUM, .badge-YELLOW { background: var(--accent-yellow); color: #000; }
    .badge-LOW, .badge-GREEN { background: var(--accent-green); color: #000; }
    .badge-INFORMATION, .badge-CLEAN { background: rgba(0, 229, 255, 0.2); color: var(--accent-cyan); border: 1px solid rgba(0, 229, 255, 0.4); }
    .badge-SUSPICIOUS { background: var(--accent-yellow); color: #000; }
    .badge-MALICIOUS { background: var(--accent-red); color: #fff; }

    /* Buttons */
    .btn {
      border: none;
      font-weight: 700;
      padding: 9px 16px;
      border-radius: 10px;
      cursor: pointer;
      font-size: 12px;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-family: inherit;
    }

    .btn-primary {
      background: linear-gradient(135deg, var(--accent-cyan), #0091ea);
      color: #050811;
    }
    .btn-primary:hover { filter: brightness(1.1); box-shadow: 0 0 12px rgba(0, 229, 255, 0.4); }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text-main);
      border: 1px solid rgba(255, 255, 255, 0.15);
    }
    .btn-secondary:hover { background: rgba(255, 255, 255, 0.14); }

    .btn-danger {
      background: rgba(255, 23, 68, 0.18);
      color: var(--accent-red);
      border: 1px solid rgba(255, 23, 68, 0.45);
    }
    .btn-danger:hover { background: var(--accent-red); color: #fff; }

    .btn-success {
      background: rgba(0, 255, 136, 0.18);
      color: var(--accent-green);
      border: 1px solid rgba(0, 255, 136, 0.45);
    }

    .btn:active { transform: scale(0.97); }

    /* Inputs */
    input[type="text"], select {
      background: rgba(5, 8, 16, 0.85);
      border: 1px solid rgba(0, 229, 255, 0.3);
      color: #fff;
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      padding: 9px 12px;
      border-radius: 8px;
      outline: none;
      width: 100%;
    }
    input[type="text"]:focus, select:focus {
      border-color: var(--accent-cyan);
      box-shadow: 0 0 10px rgba(0, 229, 255, 0.3);
    }

    /* Modal Sheet */
    .modal-backdrop {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(6px);
      z-index: 2000;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }

    .modal-dialog {
      background: #0d1322;
      border: 1px solid var(--accent-cyan);
      border-radius: 18px;
      max-width: 500px;
      width: 100%;
      padding: 24px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.8);
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    /* Severity Stats Row */
    .sev-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(80px, 1fr));
      gap: 8px;
      margin: 12px 0;
    }

    .sev-pill {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 10px;
      padding: 8px;
      text-align: center;
    }

    .sev-count {
      font-size: 18px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }

    .sev-name {
      font-size: 10px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-top: 2px;
    }

    /* Live pulse animation */
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
      animation: pulse 1.6s infinite;
    }
    .pulse-green { background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green); }
    .pulse-red { background: var(--accent-red); box-shadow: 0 0 8px var(--accent-red); }
    .pulse-amber { background: var(--accent-yellow); box-shadow: 0 0 8px var(--accent-yellow); }

    @keyframes pulse {
      0% { opacity: 0.4; }
      50% { opacity: 1; transform: scale(1.2); }
      100% { opacity: 0.4; }
    }
  </style>
</head>
<body>

  <!-- App Header -->
  <header>
    <div class="brand" onclick="switchTab('tab-overview')">
      <div class="brand-icon">DIQ</div>
      <div>
        <div class="brand-title">DefenceIQ</div>
        <div class="brand-sub">
          <span class="pulse-dot pulse-green" id="header-pulse"></span>
          <span id="header-conn-text">LIVE SENTINEL</span>
        </div>
      </div>
    </div>
    <div class="header-actions">
      <div id="device-status-pill" class="status-pill online">
        <span id="status-dot" class="pulse-dot pulse-green"></span>
        <span id="status-text">ONLINE</span>
      </div>
      <div id="token-badge" class="token-badge" onclick="showModal('pairing-modal')">
        <span>🔑</span>
        <span id="token-text">LOADING</span>
      </div>
    </div>
  </header>

  <!-- 🔴 Persistent Top RED ALERT Banner (Revealed on Critical Threat) -->
  <div id="red-alert-banner">
    <div class="red-alert-content">
      <div class="red-alert-header">
        <span>🚨 CRITICAL SECURITY ALERT</span>
        <button class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="dismissRedAlert()">✕ Acknowledge</button>
      </div>
      <div style="font-size: 15px; font-weight: 800;" id="ra-threat-name">Mass File Modification Detected</div>
      <div class="red-alert-grid">
        <div><strong>Process:</strong> <span id="ra-process">Unknown Application</span></div>
        <div><strong>Affected Folder:</strong> <span id="ra-folder">Documents/Projects</span></div>
        <div><strong>Files Affected:</strong> <span id="ra-count">247</span></div>
        <div><strong>Time:</strong> <span id="ra-time">Just now</span></div>
        <div><strong>Risk:</strong> <span id="ra-risk">Possible ransomware-like activity</span></div>
        <div><strong>Reason:</strong> <span id="ra-reason">Rapid high-entropy file modifications</span></div>
      </div>
      <div style="font-size: 13px;" id="ra-recommendation">Automatic process containment active. Reversible rollback available.</div>
      <div class="red-alert-actions">
        <button class="btn btn-primary" onclick="investigateActiveRedAlert()">🔍 Investigate Incident</button>
        <button class="btn btn-secondary" onclick="rollbackActiveRedAlert()">↩️ Execute One-Tap Rollback</button>
        <button class="btn btn-danger" onclick="suspendActiveRedAlertProcess()">🚫 Suspend Process</button>
      </div>
    </div>
  </div>

  <div class="container">

    <!-- Navigation Tabs -->
    <div class="nav-tabs">
      <button class="tab-btn active" onclick="switchTab('tab-overview')">📊 Overview</button>
      <button class="tab-btn" onclick="switchTab('tab-windows')">🪟 Windows & Tabs</button>
      <button class="tab-btn" onclick="switchTab('tab-downloads')">⬇️ Downloads</button>
      <button class="tab-btn" onclick="switchTab('tab-files')">📁 File Activity</button>
      <button class="tab-btn" onclick="switchTab('tab-alerts')">🚨 Security Alerts</button>
      <button class="tab-btn" onclick="switchTab('tab-scope')">⚙️ Scope & Privacy</button>
    </div>

    <!-- ===================================================================== -->
    <!-- TAB 1: OVERVIEW & DEVICE STATUS                                       -->
    <!-- ===================================================================== -->
    <div id="tab-overview" class="tab-pane active">

      <!-- Overall Health Card -->
      <div class="card">
        <div class="health-hero">
          <div id="health-circle" class="health-circle">🛡️</div>
          <div id="health-title" class="health-state-text" style="color: var(--accent-green);">SYSTEM SECURE</div>
          <div id="health-desc" class="health-desc">All personal endpoint monitors and heuristic ML engines active. Zero high-risk anomalies detected.</div>
        </div>

        <!-- Telemetry Gauges -->
        <div class="gauges-grid">
          <div class="gauge-box">
            <div class="gauge-label">
              <span>CPU Load</span>
              <span id="gauge-cpu-val">0%</span>
            </div>
            <div class="gauge-bar-bg"><div id="gauge-cpu-fill" class="gauge-bar-fill"></div></div>
          </div>
          <div class="gauge-box">
            <div class="gauge-label">
              <span>Memory</span>
              <span id="gauge-ram-val">0%</span>
            </div>
            <div class="gauge-bar-bg"><div id="gauge-ram-fill" class="gauge-bar-fill"></div></div>
          </div>
          <div class="gauge-box">
            <div class="gauge-label">
              <span>Storage</span>
              <span id="gauge-disk-val">0%</span>
            </div>
            <div class="gauge-bar-bg"><div id="gauge-disk-fill" class="gauge-bar-fill"></div></div>
          </div>
          <div class="gauge-box">
            <div class="gauge-label">
              <span>Battery</span>
              <span id="gauge-batt-val">100%</span>
            </div>
            <div class="gauge-bar-bg"><div id="gauge-batt-fill" class="gauge-bar-fill"></div></div>
          </div>
        </div>
      </div>

      <!-- Paired Device Info Banner -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">💻 Paired Laptop Status</span>
          <span id="last-seen-ticker" style="font-size: 11px; font-family: 'JetBrains Mono', monospace; color: var(--accent-green);">Updated Just Now</span>
        </div>
        <div class="item-meta" style="font-size: 12px; gap: 14px;">
          <div><strong>Host:</strong> <span id="dev-host">Loading...</span></div>
          <div><strong>Device ID:</strong> <span id="dev-id" style="color: var(--accent-cyan);">--</span></div>
          <div><strong>Channel:</strong> <span style="color: var(--accent-green);">E2E Relay (IP-Independent)</span></div>
          <div><strong>Protection:</strong> <span id="dev-prot-lvl" class="badge badge-CLEAN">BALANCED</span></div>
        </div>

        <div style="margin-top: 14px; display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="btn btn-secondary" onclick="showModal('pairing-modal')">🔗 Manage Pairing Token</button>
          <button class="btn btn-secondary" onclick="rotateTokenAction()">🔄 Rotate Security Secrets</button>
          <button class="btn btn-secondary" onclick="switchTab('tab-alerts')">🚨 View Threats (<span id="btn-threat-count">0</span>)</button>
        </div>
      </div>

      <!-- Live Active Window Glance -->
      <div class="active-window-card" id="overview-active-window-box">
        <div class="active-window-top">
          <div class="app-badge">
            <span>💻</span>
            <span id="ov-app-name">Checking foreground app...</span>
          </div>
          <div class="duration-ticker">
            <span>⏱️ Active:</span>
            <span id="ov-duration">0s</span>
          </div>
        </div>
        <div class="tab-title-display" id="ov-tab-title">Listening for active desktop window...</div>
        <div id="ov-domain-badge" class="domain-chip" style="display:none;">domain.com</div>
      </div>

    </div>

    <!-- ===================================================================== -->
    <!-- TAB 2: ACTIVE WINDOWS & BROWSER TABS                                   -->
    <!-- ===================================================================== -->
    <div id="tab-windows" class="tab-pane">

      <!-- Hero Active Window Details -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">🪟 Current Foreground Activity</span>
          <span class="badge badge-CLEAN" id="win-proc-pid">PID --</span>
        </div>

        <div class="active-window-card" style="margin-bottom: 0;">
          <div class="active-window-top">
            <div class="app-badge">
              <span id="win-app-icon">🌐</span>
              <span id="win-app-name">Unknown</span>
            </div>
            <div class="duration-ticker">
              <span>⏱️ Active Duration:</span>
              <span id="win-duration-text">0s</span>
            </div>
          </div>

          <div style="font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">
            Browser / App: <span id="win-browser-name" style="color: #fff;">None</span>
          </div>

          <div class="tab-title-display" id="win-tab-title">--</div>
          <div id="win-domain-chip" class="domain-chip" style="display: none;">--</div>
          <div style="font-size: 11px; color: var(--text-dim); font-family: 'JetBrains Mono', monospace;">
            Started: <span id="win-start-time">--</span>
          </div>
        </div>

        <div class="privacy-box">
          <strong>🔒 Strict Privacy Protection Guarantee:</strong>
          Sensitive page contents, passwords, form fields, search tokens, and messages are automatically redacted before transmission. Telemetry is restricted to window title metadata and duration.
        </div>
      </div>

      <!-- Recent Window & Tab History -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">📜 Recent Applications & Websites</span>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="fetchWindows()">Refresh</button>
        </div>
        <div id="windows-history-list" class="item-list">
          <div style="text-align: center; color: var(--text-muted); padding: 20px;">No window activity logged yet.</div>
        </div>
      </div>

    </div>

    <!-- ===================================================================== -->
    <!-- TAB 3: DOWNLOAD MONITORING                                            -->
    <!-- ===================================================================== -->
    <div id="tab-downloads" class="tab-pane">

      <div class="card">
        <div class="card-header">
          <span class="card-title">⬇️ Monitored Downloads & Security Scans</span>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="fetchDownloads()">Refresh</button>
        </div>

        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">
          Automatically intercepts new files downloaded on the laptop. Scans each file using PE static analysis, YARA rules, Shannon entropy, and hash reputation without transmitting private file contents.
        </p>

        <div id="downloads-feed-list" class="item-list">
          <div style="text-align: center; color: var(--text-muted); padding: 25px;">No recent downloads recorded. Monitored path: %USERPROFILE%\\Downloads</div>
        </div>
      </div>

    </div>

    <!-- ===================================================================== -->
    <!-- TAB 4: FILE & FOLDER ACTIVITY                                         -->
    <!-- ===================================================================== -->
    <div id="tab-files" class="tab-pane">

      <div class="card">
        <div class="card-header">
          <span class="card-title">📁 File & Folder Modification Sentinel</span>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="fetchFiles()">Refresh</button>
        </div>

        <!-- Filter Chips -->
        <div class="item-chips" style="margin-bottom: 14px;">
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="filterFiles('ALL')">All Changes</button>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="filterFiles('CREATED')">Created</button>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="filterFiles('MODIFIED')">Modified</button>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="filterFiles('DELETED')">Deleted</button>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="filterFiles('MOVED')">Moved / Renamed</button>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="filterFiles('FOLDER')">Folders</button>
        </div>

        <!-- Mass File Change Status Widget -->
        <div id="mass-change-widget" style="display: none; background: rgba(255, 145, 0, 0.12); border: 1px solid var(--accent-orange); border-radius: 10px; padding: 10px 14px; margin-bottom: 14px; font-size: 13px; color: #ffcc80;">
          ⚠️ <strong>Rapid File Activity Detected:</strong> <span id="mc-count">0</span> modifications recorded in sliding 5-second window.
        </div>

        <div id="files-feed-list" class="item-list">
          <div style="text-align: center; color: var(--text-muted); padding: 25px;">Listening for filesystem events in authorized directories...</div>
        </div>
      </div>

    </div>

    <!-- ===================================================================== -->
    <!-- TAB 5: SECURITY ALERTS & THREAT CENTER                                 -->
    <!-- ===================================================================== -->
    <div id="tab-alerts" class="tab-pane">

      <!-- Severity Counters -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">🚨 Threat Level & Severity Breakdown</span>
          <span id="alerts-status-tag" class="badge badge-CLEAN">SECURE</span>
        </div>

        <div class="sev-grid">
          <div class="sev-pill" style="border-color: rgba(255, 23, 68, 0.4);">
            <div class="sev-count" style="color: var(--accent-red);" id="sc-critical">0</div>
            <div class="sev-name">Critical</div>
          </div>
          <div class="sev-pill" style="border-color: rgba(255, 145, 0, 0.4);">
            <div class="sev-count" style="color: var(--accent-orange);" id="sc-high">0</div>
            <div class="sev-name">High</div>
          </div>
          <div class="sev-pill" style="border-color: rgba(255, 214, 0, 0.4);">
            <div class="sev-count" style="color: var(--accent-yellow);" id="sc-medium">0</div>
            <div class="sev-name">Medium</div>
          </div>
          <div class="sev-pill" style="border-color: rgba(0, 255, 136, 0.4);">
            <div class="sev-count" style="color: var(--accent-green);" id="sc-low">0</div>
            <div class="sev-name">Low</div>
          </div>
          <div class="sev-pill" style="border-color: rgba(0, 229, 255, 0.4);">
            <div class="sev-count" style="color: var(--accent-cyan);" id="sc-info">0</div>
            <div class="sev-name">Info</div>
          </div>
        </div>

        <!-- Simulation Test Bar -->
        <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid rgba(255, 255, 255, 0.08);">
          <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">
            🧪 Test Defensive Simulations (Verify Push Notifications & Red Alerts):
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn btn-danger" onclick="triggerSimulation('mass_file_modification')">🔴 Simulate Mass File Modification (Red Alert)</button>
            <button class="btn btn-danger" onclick="triggerSimulation('suspicious_script')">⚡ Simulate Suspicious Script</button>
            <button class="btn btn-secondary" onclick="triggerSimulation('miner')">⛏️ Simulate Miner Behavior</button>
          </div>
        </div>
      </div>

      <!-- Real-Time Alerts Feed -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">📜 Incidents & Audit History</span>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="fetchIncidents()">Refresh</button>
        </div>

        <div id="incidents-container" class="item-list">
          <div style="text-align: center; color: var(--text-muted); padding: 30px;">
            No incidents detected. Endpoint telemetry normal.
          </div>
        </div>
      </div>

    </div>

    <!-- ===================================================================== -->
    <!-- TAB 6: SCOPE & PRIVACY SETTINGS                                       -->
    <!-- ===================================================================== -->
    <div id="tab-scope" class="tab-pane">

      <!-- Monitored Scope -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">📁 User-Authorized Monitoring Scope</span>
          <span class="badge badge-CLEAN">LEAST PRIVILEGE</span>
        </div>

        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
          The DefenceIQ agent only monitors locations and processes explicitly authorized by you:
        </p>

        <div id="authorized-paths-container" class="item-list" style="margin-bottom: 16px;">
          <div class="item-card"><span class="item-name">%USERPROFILE%\\Downloads</span></div>
          <div class="item-card"><span class="item-name">%USERPROFILE%\\Documents</span></div>
          <div class="item-card"><span class="item-name">%USERPROFILE%\\Desktop</span></div>
        </div>

        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <input type="text" id="add-path-input" placeholder="Enter directory path to monitor (e.g. C:\\Projects)">
          <button class="btn btn-primary" onclick="addMonitoredPath()">Add Directory</button>
        </div>
      </div>

      <!-- Protection Level Settings -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">🛡️ Protection Policy Level</span>
        </div>

        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px;">
          <button class="btn btn-secondary" id="lvl-btn-basic" onclick="setProtectionLevel('basic')">Basic (Log Only)</button>
          <button class="btn btn-primary" id="lvl-btn-balanced" onclick="setProtectionLevel('balanced')">Balanced (Contain Suspicious)</button>
          <button class="btn btn-secondary" id="lvl-btn-maximum" onclick="setProtectionLevel('maximum')">Maximum (Strict Isolation)</button>
        </div>

        <div class="privacy-box">
          <strong>Privacy Declaration (Strict Non-Surveillance):</strong><br>
          • <strong>Zero Keystroke / Password Logging:</strong> Form fields, credentials, and keystrokes are never recorded.<br>
          • <strong>Zero Webcam / Mic Access:</strong> Hardware sensors are never activated.<br>
          • <strong>No File Content Transmission:</strong> Files stay 100% on the laptop; only cryptographic hashes, entropy values, and metadata are shared with the mobile companion.
        </div>
      </div>

    </div>

  </div>

  <!-- Pairing Modal Sheet -->
  <div id="pairing-modal" class="modal-backdrop">
    <div class="modal-dialog">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span class="card-title">🔗 Device Pairing & Key Management</span>
        <button class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="hideModal('pairing-modal')">✕</button>
      </div>

      <p style="font-size: 13px; color: var(--text-muted); line-height: 1.5;">
        Pair your laptop with the DefenceIQ Companion App using a cryptographically random token.
        <strong>No IP address, port forwarding, or local Wi-Fi required</strong>.
      </p>

      <div style="display: flex; flex-direction: column; gap: 8px;">
        <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Current Token</label>
        <input type="text" id="modal-token-input" placeholder="DIQ-XXXX-XXXX">
      </div>

      <div style="display: flex; gap: 8px; flex-wrap: wrap;">
        <button class="btn btn-primary" onclick="submitModalToken()">Save & Pair</button>
        <button class="btn btn-secondary" onclick="generateNewMobileToken()">Generate Token</button>
        <button class="btn btn-secondary" onclick="rotateTokenAction()">Rotate Key</button>
        <button class="btn btn-danger" onclick="revokePairingAction()">Revoke / Unpair</button>
      </div>
    </div>
  </div>

  <script>
    // State
    let currentToken = localStorage.getItem("defenceiq_pairing_token") || "DIQ-2TFM-UZNF";
    let ws = null;
    let pollTimer = null;
    let durationTimer = null;
    let activeDurationSeconds = 0;
    let allFileActivities = [];
    let lastSeenEpoch = Date.now();
    let currentRedAlert = null;

    // Check URL parameters for ?token=XXXX
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("token")) {
      currentToken = urlParams.get("token").toUpperCase();
      localStorage.setItem("defenceiq_pairing_token", currentToken);
    }

    function switchTab(tabId) {
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      
      const target = document.getElementById(tabId);
      if (target) target.classList.add("active");

      // Highlight button
      const buttons = document.querySelectorAll(".tab-btn");
      buttons.forEach(btn => {
        if (btn.getAttribute("onclick") && btn.getAttribute("onclick").includes(tabId)) {
          btn.classList.add("active");
        }
      });

      // Lazy load tab data
      if (tabId === "tab-windows") fetchWindows();
      if (tabId === "tab-downloads") fetchDownloads();
      if (tabId === "tab-files") fetchFiles();
      if (tabId === "tab-alerts") fetchIncidents();
    }

    function showModal(id) {
      document.getElementById(id).style.display = "flex";
      if (id === "pairing-modal") {
        document.getElementById("modal-token-input").value = currentToken;
      }
    }

    function hideModal(id) {
      document.getElementById(id).style.display = "none";
    }

    function generateNewMobileToken() {
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      let p1 = "", p2 = "";
      for (let i = 0; i < 4; i++) p1 += chars.charAt(Math.floor(Math.random() * chars.length));
      for (let i = 0; i < 4; i++) p2 += chars.charAt(Math.floor(Math.random() * chars.length));
      document.getElementById("modal-token-input").value = "DIQ-" + p1 + "-" + p2;
    }

    async function submitModalToken() {
      const val = document.getElementById("modal-token-input").value.trim().toUpperCase();
      if (!val || val.length < 4) {
        alert("Please enter a valid token (at least 4 characters).");
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
          document.getElementById("token-text").innerText = currentToken;
          hideModal("pairing-modal");
          init();
        } else {
          alert("Pairing failed: " + (data.detail || "Error"));
        }
      } catch (e) {
        // In relay mode or offline, save locally
        currentToken = val;
        localStorage.setItem("defenceiq_pairing_token", currentToken);
        document.getElementById("token-text").innerText = currentToken;
        hideModal("pairing-modal");
        init();
      }
    }

    async function rotateTokenAction() {
      if (!confirm("Rotate pairing secrets? Existing paired sessions will need to re-pair with the new token.")) return;
      try {
        const res = await fetch("/rotate-token?token=" + encodeURIComponent(currentToken), { method: "POST" });
        const data = await res.json();
        if (data.success && data.new_token) {
          currentToken = data.new_token;
          localStorage.setItem("defenceiq_pairing_token", currentToken);
          document.getElementById("token-text").innerText = currentToken;
          alert("Token rotated successfully. New Token: " + currentToken);
          hideModal("pairing-modal");
          init();
        }
      } catch (e) {
        alert("Error rotating token: " + e.message);
      }
    }

    async function revokePairingAction() {
      if (!confirm("Revoke pairing and unpair all devices?")) return;
      try {
        const res = await fetch("/revoke-pairing", { method: "POST" });
        const data = await res.json();
        if (data.success) {
          currentToken = data.new_token || "";
          localStorage.setItem("defenceiq_pairing_token", currentToken);
          document.getElementById("token-text").innerText = currentToken;
          hideModal("pairing-modal");
          alert("Pairing revoked.");
          init();
        }
      } catch (e) {
        alert("Error revoking pairing: " + e.message);
      }
    }

    // --- Data Fetching & Polling ---
    async function fetchStatus() {
      try {
        const res = await fetch("/status?token=" + encodeURIComponent(currentToken));
        if (res.ok) {
          const data = await res.json();
          lastSeenEpoch = Date.now();
          renderStatus(data);
        } else {
          checkOfflineState();
        }
      } catch (e) {
        checkOfflineState();
      }
    }

    function checkOfflineState() {
      const elapsed = Math.round((Date.now() - lastSeenEpoch) / 1000);
      const pill = document.getElementById("device-status-pill");
      const dot = document.getElementById("status-dot");
      const txt = document.getElementById("status-text");
      const ticker = document.getElementById("last-seen-ticker");

      if (elapsed > 15) {
        pill.className = "status-pill offline";
        dot.className = "pulse-dot pulse-amber";
        txt.innerText = "OFFLINE";
        ticker.innerText = `Offline (Last seen ${elapsed}s ago)`;
        ticker.style.color = "var(--text-muted)";
      }
    }

    function renderStatus(data) {
      document.getElementById("dev-host").innerText = data.hostname || "Laptop";
      document.getElementById("dev-id").innerText = data.device_id || ("LAPTOP-" + (data.hostname ? data.hostname.substring(0, 8).toUpperCase() : "SECURE"));
      document.getElementById("btn-threat-count").innerText = (data.stats ? data.stats.total_incidents : 0) || 0;

      // Online status
      const state = data.online_status || "ONLINE";
      const pill = document.getElementById("device-status-pill");
      const dot = document.getElementById("status-dot");
      const txt = document.getElementById("status-text");
      const ticker = document.getElementById("last-seen-ticker");

      pill.className = "status-pill " + state.toLowerCase();
      txt.innerText = state;
      ticker.innerText = "Updated Just Now";
      ticker.style.color = "var(--accent-green)";

      if (state === "ONLINE") {
        dot.className = "pulse-dot pulse-green";
      } else if (state === "SLEEP") {
        dot.className = "pulse-dot pulse-amber";
        ticker.innerText = "Laptop in Sleep / Hibernation";
      } else if (state === "SHUTDOWN") {
        dot.className = "pulse-dot pulse-red";
        ticker.innerText = "Laptop Shut Down";
      }

      // Gauges
      if (data.system_metrics) {
        const sm = data.system_metrics;
        const cpu = sm.cpu_percent || 0;
        const ram = sm.ram ? sm.ram.percent : 0;
        const disk = sm.disk ? sm.disk.percent : 0;
        const batt = sm.battery && sm.battery.percent !== null ? sm.battery.percent : 100;

        document.getElementById("gauge-cpu-val").innerText = cpu + "%";
        document.getElementById("gauge-cpu-fill").style.width = Math.min(cpu, 100) + "%";

        document.getElementById("gauge-ram-val").innerText = ram + "%";
        document.getElementById("gauge-ram-fill").style.width = Math.min(ram, 100) + "%";

        document.getElementById("gauge-disk-val").innerText = disk + "%";
        document.getElementById("gauge-disk-fill").style.width = Math.min(disk, 100) + "%";

        document.getElementById("gauge-batt-val").innerText = batt + "%" + (sm.battery && sm.battery.plugged ? " ⚡" : "");
        document.getElementById("gauge-batt-fill").style.width = Math.min(batt, 100) + "%";
      }

      // Health state
      const hState = data.health_state || "SECURE";
      const hCircle = document.getElementById("health-circle");
      const hTitle = document.getElementById("health-title");
      const hDesc = document.getElementById("health-desc");

      if (hState === "CRITICAL_THREAT") {
        hCircle.style.borderColor = "var(--accent-red)";
        hCircle.style.boxShadow = "var(--red-glow)";
        hCircle.innerText = "🚨";
        hTitle.innerText = "CRITICAL THREAT DETECTED";
        hTitle.style.color = "var(--accent-red)";
        hDesc.innerText = "Automated process containment or high-risk anomaly active.";
      } else if (hState === "ELEVATED_RISK") {
        hCircle.style.borderColor = "var(--accent-orange)";
        hCircle.style.boxShadow = "0 0 25px rgba(255, 145, 0, 0.35)";
        hCircle.innerText = "⚠️";
        hTitle.innerText = "ELEVATED RISK";
        hTitle.style.color = "var(--accent-orange)";
        hDesc.innerText = "Multiple suspicious behavioral signals correlated on host.";
      } else {
        hCircle.style.borderColor = "var(--accent-green)";
        hCircle.style.boxShadow = "0 0 30px rgba(0, 255, 136, 0.25)";
        hCircle.innerText = "🛡️";
        hTitle.innerText = "SYSTEM SECURE";
        hTitle.style.color = "var(--accent-green)";
        hDesc.innerText = "All personal endpoint monitors active. Telemetry nominal.";
      }

      // Active Window glance
      if (data.active_window) {
        updateActiveWindowGlance(data.active_window);
      }

      // Severity counts
      if (data.severity_counts) {
        const sc = data.severity_counts;
        document.getElementById("sc-critical").innerText = sc.CRITICAL || 0;
        document.getElementById("sc-high").innerText = sc.HIGH || 0;
        document.getElementById("sc-medium").innerText = sc.MEDIUM || 0;
        document.getElementById("sc-low").innerText = sc.LOW || 0;
        document.getElementById("sc-info").innerText = sc.INFORMATION || 0;
      }
    }

    function updateActiveWindowGlance(act) {
      if (!act) return;
      document.getElementById("ov-app-name").innerText = act.app_name || act.process_name || "Active App";
      document.getElementById("ov-tab-title").innerText = act.tab_title || act.window_title || "--";
      activeDurationSeconds = act.duration_seconds || 0;
      document.getElementById("ov-duration").innerText = formatDuration(activeDurationSeconds);

      const dBadge = document.getElementById("ov-domain-badge");
      if (act.domain) {
        dBadge.style.display = "inline-block";
        dBadge.innerText = act.domain;
      } else {
        dBadge.style.display = "none";
      }

      // Detailed tab
      document.getElementById("win-app-name").innerText = act.app_name || act.process_name || "Unknown";
      document.getElementById("win-proc-pid").innerText = "PID " + (act.pid || "--");
      document.getElementById("win-browser-name").innerText = act.browser_name || (act.is_browser ? "Browser" : "Desktop Application");
      document.getElementById("win-tab-title").innerText = act.tab_title || act.window_title || "--";
      document.getElementById("win-duration-text").innerText = formatDuration(activeDurationSeconds);
      document.getElementById("win-start-time").innerText = act.start_time ? new Date(act.start_time).toLocaleTimeString() : "--";

      const wDomain = document.getElementById("win-domain-chip");
      if (act.domain) {
        wDomain.style.display = "inline-block";
        wDomain.innerText = "🌐 Domain: " + act.domain;
      } else {
        wDomain.style.display = "none";
      }
    }

    function formatDuration(sec) {
      if (sec < 60) return sec + "s";
      const m = Math.floor(sec / 60);
      const s = sec % 60;
      return m + "m " + s + "s";
    }

    // --- Windows & Tabs History ---
    async function fetchWindows() {
      try {
        const res = await fetch("/activities/windows?token=" + encodeURIComponent(currentToken));
        if (res.ok) {
          const data = await res.json();
          if (data.current_activity) updateActiveWindowGlance(data.current_activity);
          renderWindowsHistory(data.recent_activities || []);
        }
      } catch (e) {}
    }

    function renderWindowsHistory(activities) {
      const container = document.getElementById("windows-history-list");
      if (!activities || activities.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 20px;">No window activity logged yet.</div>`;
        return;
      }

      container.innerHTML = activities.map(a => `
        <div class="item-card">
          <div class="item-card-top">
            <span class="item-name">${a.app_name} (${a.process_name})</span>
            <span class="chip">${formatDuration(a.duration_seconds || 0)}</span>
          </div>
          <div style="font-size: 13px; color: #cbd5e1;">${a.tab_title || a.window_title || '--'}</div>
          <div class="item-meta">
            ${a.domain ? `<span class="chip" style="color: var(--accent-yellow);">🌐 ${a.domain}</span>` : ""}
            <span>PID: ${a.pid}</span>
            <span>Started: ${a.start_time ? new Date(a.start_time).toLocaleTimeString() : '--'}</span>
          </div>
        </div>
      `).join("");
    }

    // --- Downloads Monitoring ---
    async function fetchDownloads() {
      try {
        const res = await fetch("/activities/downloads?limit=30&token=" + encodeURIComponent(currentToken));
        if (res.ok) {
          const data = await res.json();
          renderDownloads(data.downloads || []);
        }
      } catch (e) {}
    }

    function renderDownloads(downloads) {
      const container = document.getElementById("downloads-feed-list");
      if (!downloads || downloads.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 25px;">No recent downloads recorded in %USERPROFILE%\\Downloads</div>`;
        return;
      }

      container.innerHTML = downloads.map(dl => {
        const v = dl.scan_verdict || "CLEAN";
        const vBadge = `<span class="badge badge-${v}">${v}</span>`;
        const sigs = (dl.risk_signals || []).map(s => `<span class="chip">${s}</span>`).join("");

        return `
          <div class="item-card">
            <div class="item-card-top">
              <span class="item-name">📥 ${dl.file_name}</span>
              ${vBadge}
            </div>
            <div class="item-meta">
              <span>Type: ${dl.file_type || 'File'}</span>
              <span>Size: ${dl.file_size_display || (dl.file_size_bytes + ' B')}</span>
              <span>Domain: <strong>${dl.source_domain || 'Direct / Local'}</strong></span>
              <span>Time: ${dl.download_timestamp ? new Date(dl.download_timestamp).toLocaleTimeString() : '--'}</span>
            </div>
            <div style="font-size: 11px; color: var(--text-dim); font-family: 'JetBrains Mono', monospace; word-break: break-all;">
              Path: ${dl.destination_path || 'Downloads'}
            </div>
            ${sigs ? `<div class="item-chips">${sigs}</div>` : ""}
          </div>
        `;
      }).join("");
    }

    // --- Files & Folders Activity ---
    async function fetchFiles() {
      try {
        const res = await fetch("/activities/files?limit=40&token=" + encodeURIComponent(currentToken));
        if (res.ok) {
          const data = await res.json();
          allFileActivities = data.activities || [];
          renderFiles(allFileActivities);
        }
      } catch (e) {}
    }

    function filterFiles(type) {
      if (type === "ALL") {
        renderFiles(allFileActivities);
      } else if (type === "FOLDER") {
        renderFiles(allFileActivities.filter(f => f.event_type.includes("FOLDER")));
      } else {
        renderFiles(allFileActivities.filter(f => f.event_type.includes(type)));
      }
    }

    function renderFiles(files) {
      const container = document.getElementById("files-feed-list");
      if (!files || files.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 25px;">Listening for filesystem events in authorized directories...</div>`;
        return;
      }

      container.innerHTML = files.map(f => {
        let etColor = "var(--accent-cyan)";
        if (f.event_type.includes("DELETED")) etColor = "var(--accent-red)";
        if (f.event_type.includes("MODIFIED")) etColor = "var(--accent-yellow)";
        if (f.event_type.includes("CREATED")) etColor = "var(--accent-green)";

        const sigs = (f.signals || []).map(s => `<span class="chip" style="color: var(--accent-orange);">${s}</span>`).join("");

        return `
          <div class="item-card">
            <div class="item-card-top">
              <span class="item-name">${f.file_name || 'Item'}</span>
              <span class="badge" style="background: rgba(255,255,255,0.08); color: ${etColor}; border: 1px solid ${etColor};">${f.event_type}</span>
            </div>
            <div class="item-meta">
              <span>Path: ${f.file_path}</span>
              ${f.file_size_bytes ? `<span>Size: ${f.file_size_bytes} B</span>` : ""}
              ${f.entropy !== null && f.entropy !== undefined ? `<span>Entropy: ${f.entropy}</span>` : ""}
              ${f.responsible_process ? `<span style="color: var(--accent-cyan);">Process: ${f.responsible_process}</span>` : ""}
              <span>Time: ${f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : '--'}</span>
            </div>
            ${sigs ? `<div class="item-chips">${sigs}</div>` : ""}
          </div>
        `;
      }).join("");
    }

    // --- Incidents & Security Alerts ---
    async function fetchIncidents() {
      try {
        const res = await fetch("/incidents?limit=30&token=" + encodeURIComponent(currentToken));
        if (res.ok) {
          const data = await res.json();
          renderIncidents(data.incidents || []);
        }
      } catch (e) {}
    }

    function renderIncidents(incidents) {
      const container = document.getElementById("incidents-container");
      if (!incidents || incidents.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 30px;">No incidents detected. All endpoint monitors operational.</div>`;
        return;
      }

      // Check if top critical incident requires red alert banner
      const crit = incidents.find(i => (i.risk_score >= 80 || i.risk_band === "RED") && i.status !== "RESOLVED" && i.status !== "ROLLED_BACK");
      if (crit) {
        triggerRedAlertUI(crit);
      }

      container.innerHTML = incidents.map(inc => {
        const band = inc.risk_band || "GREEN";
        const score = inc.risk_score || 0;
        const proc = inc.root_process_name || "Process";
        const pid = inc.root_pid ? `(PID ${inc.root_pid})` : "";
        const sigs = (inc.signals || []).map(s => `<span class="chip">${s}</span>`).join("");
        const files = (inc.touched_files || []).slice(0, 3).map(f => `<span class="chip">📄 ${f.split(/[\\\\/]/).pop()}</span>`).join("");

        const rollbackBtn = (inc.status === "CONTAINED" || inc.status === "OPEN" || inc.status === "ACTIVE")
          ? `<button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="triggerRollback('${inc.incident_id}')">↩️ Rollback Containment</button>`
          : `<span style="font-size: 11px; color: var(--accent-green); font-family: 'JetBrains Mono', monospace;">✓ ${inc.status}</span>`;

        return `
          <div class="item-card" style="border-left: 4px solid var(--accent-${band === 'RED' ? 'red' : (band === 'ORANGE' ? 'orange' : 'green')});">
            <div class="item-card-top">
              <span class="item-name">
                <span>${band === 'RED' ? '🚨' : (band === 'ORANGE' ? '⚠️' : '🛡️')}</span>
                <span>${proc} ${pid}</span>
              </span>
              <span class="badge badge-${band}">${band} • ${score}/100</span>
            </div>
            <div style="font-size: 13px; color: #cbd5e1; margin: 4px 0;">
              ${inc.explanation || "Heuristic anomaly detected."}
            </div>
            <div class="item-meta">
              <span>Incident: ${inc.incident_id ? inc.incident_id.substring(0, 8) : '--'}</span>
              <span>Updated: ${inc.updated_at ? new Date(inc.updated_at).toLocaleTimeString() : '--'}</span>
            </div>
            ${files ? `<div class="item-chips" style="margin-top: 4px;">${files}</div>` : ""}
            <div class="item-chips">${sigs}</div>
            <div style="margin-top: 10px; display: flex; justify-content: flex-end; gap: 6px;">
              ${rollbackBtn}
            </div>
          </div>
        `;
      }).join("");
    }

    // --- Red Alert Handling ---
    function triggerRedAlertUI(inc) {
      currentRedAlert = inc;
      const banner = document.getElementById("red-alert-banner");
      banner.style.display = "block";

      document.getElementById("ra-threat-name").innerText = inc.threat_name || (inc.signals && inc.signals.includes("modified_encrypted_many_files") ? "Mass File Modification Detected" : `High Risk Threat: ${inc.root_process_name}`);
      document.getElementById("ra-process").innerText = `${inc.root_process_name || 'Process'} (PID ${inc.root_pid || 'N/A'})`;
      
      const files = inc.touched_files || [];
      const folder = files.length > 0 ? files[0].substring(0, files[0].lastIndexOf("\\\\") || files[0].lastIndexOf("/")) : "Documents/Projects";
      document.getElementById("ra-folder").innerText = folder || "Documents/Projects";
      document.getElementById("ra-count").innerText = files.length > 0 ? files.length : "247";
      document.getElementById("ra-time").innerText = inc.updated_at ? new Date(inc.updated_at).toLocaleTimeString() : "Just now";
      document.getElementById("ra-reason").innerText = inc.explanation || "Rapid high-entropy file modifications matching ransomware-like activity.";

      // Native browser notification
      if ("Notification" in window && Notification.permission === "granted") {
        new Notification("🔴 CRITICAL SECURITY ALERT: DefenceIQ", {
          body: `${document.getElementById("ra-threat-name").innerText} - Process: ${inc.root_process_name}`,
          icon: "/favicon.ico"
        });
      }
    }

    function dismissRedAlert() {
      document.getElementById("red-alert-banner").style.display = "none";
      if (currentRedAlert) {
        fetch("/actions/respond?token=" + encodeURIComponent(currentToken), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "acknowledge", incident_id: currentRedAlert.incident_id })
        });
      }
    }

    async function rollbackActiveRedAlert() {
      if (!currentRedAlert) return;
      await triggerRollback(currentRedAlert.incident_id);
      dismissRedAlert();
    }

    async function suspendActiveRedAlertProcess() {
      if (!currentRedAlert) return;
      try {
        const res = await fetch("/actions/respond?token=" + encodeURIComponent(currentToken), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: "suspend_process",
            incident_id: currentRedAlert.incident_id,
            target_pid: currentRedAlert.root_pid
          })
        });
        const data = await res.json();
        alert("Process suspension action executed.");
        fetchIncidents();
        fetchStatus();
      } catch (e) {
        alert("Action error: " + e.message);
      }
    }

    function investigateActiveRedAlert() {
      switchTab('tab-alerts');
    }

    async function triggerRollback(incidentId) {
      if (!confirm("Execute automated containment rollback to restore files/firewall?")) return;
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

    // --- Simulations ---
    async function triggerSimulation(scenario) {
      try {
        const res = await fetch("/simulate/alert?token=" + encodeURIComponent(currentToken), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scenario: scenario })
        });
        const data = await res.json();
        if (data.success) {
          fetchIncidents();
          fetchStatus();
          switchTab('tab-alerts');
        }
      } catch (e) {
        alert("Simulation error: " + e.message);
      }
    }

    // --- Scope & Settings ---
    async function addMonitoredPath() {
      const input = document.getElementById("add-path-input");
      const pathVal = input.value.trim();
      if (!pathVal) return;
      try {
        const res = await fetch("/protection/scope?token=" + encodeURIComponent(currentToken), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ add_path: pathVal })
        });
        const data = await res.json();
        if (data.success) {
          alert("Added path to authorized scope: " + pathVal);
          input.value = "";
          renderAuthorizedPaths(data.authorized_directories);
        }
      } catch (e) {
        alert("Error updating scope: " + e.message);
      }
    }

    async function setProtectionLevel(lvl) {
      try {
        const res = await fetch("/protection/level?token=" + encodeURIComponent(currentToken), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ level: lvl })
        });
        const data = await res.json();
        if (data.success) {
          alert("Protection level set to: " + lvl.toUpperCase());
          fetchStatus();
        }
      } catch (e) {
        alert("Error setting level: " + e.message);
      }
    }

    function renderAuthorizedPaths(paths) {
      const c = document.getElementById("authorized-paths-container");
      if (!paths || !c) return;
      c.innerHTML = paths.map(p => `<div class="item-card"><span class="item-name">${p}</span></div>`).join("");
    }

    // --- WebSocket Connection ---
    function connectWebSocket() {
      if (ws) ws.close();
      const loc = window.location;
      const wsProto = loc.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${wsProto}//${loc.host}/ws/alerts?token=${encodeURIComponent(currentToken)}`;

      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          document.getElementById("header-conn-text").innerText = "LIVE WS STREAM";
        };

        ws.onmessage = (event) => {
          try {
            const frame = JSON.parse(event.data);
            if (frame.type === "incident") {
              fetchIncidents();
              fetchStatus();
            } else if (frame.type === "paired_mobile" || frame.type === "token_rotated") {
              fetchStatus();
            } else if (frame.type === "telemetry_event" || frame.type === "action") {
              fetchStatus();
            }
          } catch (e) {}
        };

        ws.onclose = () => {
          setTimeout(connectWebSocket, 4000);
        };
      } catch (e) {}
    }

    // --- Init ---
    async function init() {
      document.getElementById("token-text").innerText = currentToken || "NOT SET";

      if ("Notification" in window && Notification.permission === "default") {
        Notification.requestPermission();
      }

      await fetchStatus();
      await fetchWindows();
      await fetchDownloads();
      await fetchFiles();
      await fetchIncidents();
      connectWebSocket();

      // Live interval tickers
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(() => {
        fetchStatus();
        checkOfflineState();
      }, 3500);

      if (durationTimer) clearInterval(durationTimer);
      durationTimer = setInterval(() => {
        activeDurationSeconds += 1;
        document.getElementById("ov-duration").innerText = formatDuration(activeDurationSeconds);
        document.getElementById("win-duration-text").innerText = formatDuration(activeDurationSeconds);
      }, 1000);
    }

    window.addEventListener("DOMContentLoaded", init);

    // ── PWA Install Banner ──────────────────────────────────────
    let _deferredInstallPrompt = null;

    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      _deferredInstallPrompt = e;
      const banner = document.getElementById('pwa-install-banner');
      if (banner) banner.style.display = 'flex';
    });

    document.addEventListener('DOMContentLoaded', () => {
      const btn = document.getElementById('pwa-install-btn');
      const dismiss = document.getElementById('pwa-install-dismiss');
      if (btn) {
        btn.addEventListener('click', async () => {
          if (_deferredInstallPrompt) {
            _deferredInstallPrompt.prompt();
            const { outcome } = await _deferredInstallPrompt.userChoice;
            _deferredInstallPrompt = null;
            document.getElementById('pwa-install-banner').style.display = 'none';
          }
        });
      }
      if (dismiss) {
        dismiss.addEventListener('click', () => {
          document.getElementById('pwa-install-banner').style.display = 'none';
        });
      }
    });

    window.addEventListener('appinstalled', () => {
      document.getElementById('pwa-install-banner').style.display = 'none';
    });

    // ── Service Worker Registration ─────────────────────────────
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').then(reg => {
          console.log('[DefenceIQ PWA] Service worker registered:', reg.scope);
        }).catch(err => {
          console.warn('[DefenceIQ PWA] SW registration failed:', err);
        });
      });
    }
  </script>

  <!-- PWA Install Banner -->
  <div id="pwa-install-banner" style="
    display: none;
    position: fixed;
    bottom: 80px;
    left: 12px;
    right: 12px;
    background: linear-gradient(135deg, rgba(0,229,255,0.18), rgba(0,255,136,0.12));
    border: 1px solid rgba(0,229,255,0.45);
    border-radius: 16px;
    padding: 14px 16px;
    z-index: 9999;
    align-items: center;
    gap: 12px;
    backdrop-filter: blur(14px);
    box-shadow: 0 8px 32px rgba(0,229,255,0.2);
  ">
    <span style="font-size:26px;">🛡️</span>
    <div style="flex:1;">
      <div style="font-weight:700;font-size:14px;color:#00e5ff;font-family:'Outfit',sans-serif;">Install DefenceIQ</div>
      <div style="font-size:12px;color:#94a3b8;font-family:'Outfit',sans-serif;">Add to home screen for app-like experience</div>
    </div>
    <button id="pwa-install-btn" style="
      background: linear-gradient(135deg,#00e5ff,#00ff88);
      color:#070a12;
      border:none;
      border-radius:10px;
      padding:8px 14px;
      font-weight:700;
      font-size:13px;
      cursor:pointer;
      font-family:'Outfit',sans-serif;
    ">Install</button>
    <button id="pwa-install-dismiss" style="
      background:transparent;
      border:1px solid rgba(255,255,255,0.2);
      border-radius:8px;
      color:#94a3b8;
      padding:8px 10px;
      cursor:pointer;
      font-size:12px;
    ">✕</button>
  </div>
</body>
</html>"""
