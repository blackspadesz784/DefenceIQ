"""DefenceIQ - Executive White Web Companion Dashboard & Mobile Console.

Provides a clean, professional, high-contrast White/Light dashboard interface for
monitoring laptop endpoint security, live device connection status, hardware metrics,
token-based device pairing, automatic security alerts, threat incidents, active windows,
downloads, files, and quarantine containment.
"""

def get_dashboard_html() -> str:
    """Returns the complete single-page interactive White-Theme Dashboard HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>DefenceIQ | Endpoint Security & Threat Monitor</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-body: #f8fafc;
      --bg-surface: #ffffff;
      --bg-subtle: #f1f5f9;
      --bg-hover: #e2e8f0;
      --border-main: #e2e8f0;
      --border-subtle: #cbd5e1;
      --border-focus: #3b82f6;
      --text-main: #0f172a;
      --text-secondary: #475569;
      --text-muted: #64748b;
      --text-light: #94a3b8;
      --primary-blue: #2563eb;
      --primary-hover: #1d4ed8;
      --primary-light: #eff6ff;
      --success-green: #059669;
      --success-light: #ecfdf5;
      --warning-amber: #d97706;
      --warning-light: #fffbeb;
      --danger-red: #dc2626;
      --danger-light: #fef2f2;
      --purple-accent: #7c3aed;
      --purple-light: #f5f3ff;
      --card-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.07), 0 1px 2px -1px rgba(0, 0, 0, 0.05);
      --card-shadow-hover: 0 4px 6px -1px rgba(0, 0, 0, 0.08), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
      --modal-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.05);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      -webkit-tap-highlight-color: transparent;
    }

    body {
      background-color: var(--bg-body);
      color: var(--text-main);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      padding-bottom: 60px;
      line-height: 1.5;
    }

    /* Top Navigation Header */
    header {
      padding: 12px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border-main);
      position: sticky;
      top: 0;
      z-index: 1000;
      box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.03);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      cursor: pointer;
    }

    .brand-icon {
      width: 38px;
      height: 38px;
      border-radius: 10px;
      background: var(--primary-blue);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      box-shadow: 0 2px 4px rgba(37, 99, 235, 0.25);
    }

    .brand-icon svg {
      width: 22px;
      height: 22px;
      fill: none;
      stroke: currentColor;
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .brand-text-col {
      display: flex;
      flex-direction: column;
    }

    .brand-title {
      font-size: 18px;
      font-weight: 800;
      letter-spacing: -0.3px;
      color: var(--text-main);
    }

    .brand-sub {
      font-size: 11px;
      font-weight: 600;
      color: var(--primary-blue);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    /* Status Pills */
    .status-pill {
      font-size: 12px;
      font-weight: 600;
      padding: 5px 12px;
      border-radius: 9999px;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      border: 1px solid transparent;
      transition: all 0.2s ease;
    }

    .status-pill.connected, .status-pill.online {
      background: var(--success-light);
      border-color: #a7f3d0;
      color: var(--success-green);
    }

    .status-pill.connecting {
      background: var(--primary-light);
      border-color: #bfdbfe;
      color: var(--primary-blue);
    }

    .status-pill.connection-lost {
      background: var(--warning-light);
      border-color: #fde68a;
      color: var(--warning-amber);
    }

    .status-pill.disconnected, .status-pill.offline, .status-pill.laptop-offline {
      background: var(--bg-subtle);
      border-color: var(--border-subtle);
      color: var(--text-secondary);
    }

    .status-pill.shutdown {
      background: var(--danger-light);
      border-color: #fecaca;
      color: var(--danger-red);
    }

    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
    }
    .pulse-green { background: #10b981; animation: pulseG 1.8s infinite; }
    .pulse-blue { background: #3b82f6; animation: pulseB 1.5s infinite; }
    .pulse-amber { background: #f59e0b; animation: pulseA 1.8s infinite; }
    .pulse-red { background: #ef4444; }
    .pulse-gray { background: #94a3b8; }

    @keyframes pulseG {
      0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
      70% { box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
      100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    @keyframes pulseB {
      0% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4); }
      70% { box-shadow: 0 0 0 6px rgba(59, 130, 246, 0); }
      100% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0); }
    }
    @keyframes pulseA {
      0% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.4); }
      70% { box-shadow: 0 0 0 6px rgba(245, 158, 11, 0); }
      100% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0); }
    }

    .token-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      background: var(--bg-subtle);
      border: 1px solid var(--border-main);
      padding: 5px 12px;
      border-radius: 9999px;
      color: var(--text-main);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-weight: 600;
      transition: all 0.2s ease;
    }

    .token-badge:hover {
      background: var(--bg-hover);
      border-color: var(--border-subtle);
    }

    /* Red Alert Banner */
    #red-alert-banner {
      display: none;
      background: #fef2f2;
      color: #991b1b;
      border-bottom: 2px solid #ef4444;
      padding: 14px 24px;
      box-shadow: 0 2px 4px rgba(220, 38, 38, 0.1);
      position: sticky;
      top: 63px;
      z-index: 990;
    }

    .red-alert-content {
      max-width: 1040px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .red-alert-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 15px;
      font-weight: 700;
    }

    .red-alert-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 8px 16px;
      font-size: 13px;
      background: #fee2e2;
      padding: 10px 14px;
      border-radius: 8px;
    }

    .red-alert-actions {
      display: flex;
      gap: 10px;
      margin-top: 4px;
    }

    /* Container & Layout */
    .container {
      max-width: 1040px;
      margin: 0 auto;
      padding: 20px 24px;
    }

    /* Navigation Tabs */
    .nav-tabs {
      display: flex;
      gap: 8px;
      overflow-x: auto;
      padding-bottom: 12px;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--border-main);
      scrollbar-width: none;
    }
    .nav-tabs::-webkit-scrollbar { display: none; }

    .tab-btn {
      background: var(--bg-surface);
      border: 1px solid var(--border-main);
      color: var(--text-secondary);
      padding: 9px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      white-space: nowrap;
      transition: all 0.2s ease;
      font-family: inherit;
    }

    .tab-btn:hover {
      background: var(--bg-subtle);
      color: var(--text-main);
    }

    .tab-btn.active {
      background: var(--primary-blue);
      border-color: var(--primary-blue);
      color: #ffffff;
      box-shadow: 0 1px 3px rgba(37, 99, 235, 0.3);
    }

    .tab-btn svg {
      width: 16px;
      height: 16px;
      fill: none;
      stroke: currentColor;
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .badge-count {
      background: #ef4444;
      color: #ffffff;
      font-size: 11px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 9999px;
      font-family: 'JetBrains Mono', monospace;
    }

    /* Tab Content Panes */
    .tab-pane {
      display: none;
      animation: fadeIn 0.2s ease;
    }
    .tab-pane.active { display: block; }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Device Card (Requirement 7) */
    .device-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-main);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: var(--card-shadow);
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .device-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 12px;
    }

    .device-info-left {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .device-icon-box {
      width: 48px;
      height: 48px;
      border-radius: 10px;
      background: var(--primary-light);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary-blue);
    }

    .device-icon-box svg {
      width: 26px;
      height: 26px;
      fill: none;
      stroke: currentColor;
      stroke-width: 2;
    }

    .device-names h2 {
      font-size: 18px;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .device-type-label {
      font-size: 13px;
      color: var(--text-muted);
      font-weight: 500;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-top: 3px;
    }

    .device-meta-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      background: var(--bg-subtle);
      padding: 14px 16px;
      border-radius: 8px;
      border: 1px solid var(--border-main);
      font-size: 13px;
    }

    .device-meta-item {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }

    .meta-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-weight: 600;
      color: var(--text-muted);
    }

    .meta-value {
      font-weight: 600;
      color: var(--text-main);
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }

    /* Pairing Section (Requirement 3 & 4) */
    .pairing-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-main);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: var(--card-shadow);
    }

    .pairing-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }

    .pairing-title {
      font-size: 15px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text-main);
    }

    .pairing-title svg {
      width: 18px;
      height: 18px;
      stroke: var(--primary-blue);
      fill: none;
      stroke-width: 2;
    }

    .token-display-box {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--bg-subtle);
      border: 1px solid var(--border-main);
      border-radius: 10px;
      padding: 14px 18px;
      margin-top: 10px;
      gap: 12px;
      flex-wrap: wrap;
    }

    .token-code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 2px;
      color: var(--primary-blue);
    }

    .token-expiry-label {
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 6px;
      margin-top: 4px;
    }

    .paired-state-box {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--success-light);
      border: 1px solid #a7f3d0;
      border-radius: 10px;
      padding: 14px 18px;
      margin-top: 10px;
      flex-wrap: wrap;
      gap: 12px;
    }

    .paired-info {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .paired-info svg {
      width: 24px;
      height: 24px;
      stroke: var(--success-green);
      fill: none;
      stroke-width: 2;
    }

    /* Metric Cards Grid */
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }

    .metric-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-main);
      border-radius: 10px;
      padding: 16px;
      box-shadow: var(--card-shadow);
      display: flex;
      flex-direction: column;
      gap: 10px;
      transition: all 0.2s ease;
    }

    .metric-card:hover {
      box-shadow: var(--card-shadow-hover);
      border-color: var(--border-subtle);
    }

    .metric-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .metric-label-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .metric-icon-small {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: var(--bg-subtle);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary-blue);
    }

    .metric-icon-small svg {
      width: 16px;
      height: 16px;
      fill: none;
      stroke: currentColor;
      stroke-width: 2;
    }

    .metric-title {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .metric-value-huge {
      font-size: 22px;
      font-weight: 700;
      color: var(--text-main);
      font-family: 'JetBrains Mono', monospace;
    }

    .progress-bar-bg {
      background: var(--bg-subtle);
      height: 6px;
      border-radius: 3px;
      overflow: hidden;
      margin-top: 4px;
    }

    .progress-fill {
      height: 100%;
      background: var(--primary-blue);
      border-radius: 3px;
      transition: width 0.4s ease;
    }
    .fill-green { background: var(--success-green); }
    .fill-amber { background: var(--warning-amber); }
    .fill-red { background: var(--danger-red); }

    .metric-sub {
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
    }

    /* List Card Items */
    .list-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-main);
      border-radius: 12px;
      padding: 16px 20px;
      margin-bottom: 20px;
      box-shadow: var(--card-shadow);
    }

    .list-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border-main);
    }

    .list-title {
      font-size: 15px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text-main);
    }

    .list-title svg {
      width: 18px;
      height: 18px;
      stroke: var(--primary-blue);
      fill: none;
      stroke-width: 2;
    }

    .item-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-main);
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 10px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      transition: all 0.15s ease;
    }

    .item-card:hover {
      background: #fafafa;
      border-color: var(--border-subtle);
    }

    .item-card-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 6px;
    }

    .item-name {
      font-weight: 600;
      font-size: 14px;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .item-name svg {
      width: 16px;
      height: 16px;
      stroke: var(--text-muted);
      fill: none;
      stroke-width: 2;
    }

    .item-meta {
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
    }

    /* Badges */
    .badge {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }

    .badge-CRITICAL, .badge-RED { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }
    .badge-HIGH, .badge-ORANGE { background: #ffedd5; color: #c2410c; border: 1px solid #fed7aa; }
    .badge-MEDIUM, .badge-YELLOW { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
    .badge-LOW, .badge-GREEN { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
    .badge-INFO, .badge-INFORMATION, .badge-CLEAN { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
    .badge-WARNING { background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }

    /* Action Buttons */
    .btn {
      border: 1px solid transparent;
      font-weight: 600;
      padding: 8px 14px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 13px;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-family: inherit;
    }

    .btn svg {
      width: 15px;
      height: 15px;
      fill: none;
      stroke: currentColor;
      stroke-width: 2;
    }

    .btn-primary {
      background: var(--primary-blue);
      color: #ffffff;
    }
    .btn-primary:hover { background: var(--primary-hover); }

    .btn-secondary {
      background: var(--bg-surface);
      border-color: var(--border-main);
      color: var(--text-secondary);
    }
    .btn-secondary:hover { background: var(--bg-subtle); color: var(--text-main); }

    .btn-danger {
      background: #fef2f2;
      border-color: #fecaca;
      color: var(--danger-red);
    }
    .btn-danger:hover { background: #fee2e2; }

    .btn-success {
      background: var(--success-light);
      border-color: #a7f3d0;
      color: var(--success-green);
    }
    .btn-success:hover { background: #d1fae5; }

    /* Modal Sheet */
    .modal-backdrop {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(15, 23, 42, 0.6);
      backdrop-filter: blur(4px);
      z-index: 2000;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }

    .modal-dialog {
      background: #ffffff;
      border: 1px solid var(--border-main);
      border-radius: 14px;
      max-width: 480px;
      width: 100%;
      padding: 24px;
      box-shadow: var(--modal-shadow);
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .modal-title {
      font-size: 17px;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    input[type="text"] {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
      padding: 10px 14px;
      border-radius: 8px;
      outline: none;
      width: 100%;
      transition: all 0.2s ease;
    }

    input[type="text"]:focus {
      border-color: var(--primary-blue);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
    }

    /* Toast Notification */
    #toast-msg {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #0f172a;
      color: #ffffff;
      padding: 12px 18px;
      border-radius: 8px;
      box-shadow: var(--modal-shadow);
      font-size: 13px;
      font-weight: 500;
      display: none;
      align-items: center;
      gap: 10px;
      z-index: 3000;
      animation: toastIn 0.2s ease;
    }

    @keyframes toastIn {
      from { transform: translateY(10px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    /* Empty state */
    .empty-placeholder {
      padding: 32px 16px;
      text-align: center;
      color: var(--text-muted);
      font-size: 13px;
    }

    .empty-placeholder svg {
      width: 36px;
      height: 36px;
      stroke: var(--text-light);
      margin: 0 auto 10px;
      display: block;
    }
  </style>
</head>
<body>

  <!-- App Header -->
  <header>
    <div class="brand" onclick="switchTab('tab-overview')">
      <div class="brand-icon">
        <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div class="brand-text-col">
        <span class="brand-title">DefenceIQ</span>
        <span class="brand-sub">Endpoint Security</span>
      </div>
    </div>

    <div class="header-actions">
      <!-- Live Status Pill (Requirement 1) -->
      <div id="device-status-pill" class="status-pill connected">
        <span id="status-dot" class="pulse-dot pulse-green"></span>
        <span id="status-text">Connected</span>
      </div>

      <!-- Pairing Token Badge / Paired Device Indicator -->
      <div id="header-token-badge" class="token-badge" onclick="showPairingModal()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
        <span id="header-token-text">Pairing...</span>
      </div>
    </div>
  </header>

  <!-- Emergency Red Alert Warning Banner -->
  <div id="red-alert-banner">
    <div class="red-alert-content">
      <div class="red-alert-header">
        <span id="red-alert-title">CRITICAL THREAT DETECTED</span>
        <span id="red-alert-score" class="badge badge-CRITICAL">SCORE: 95</span>
      </div>
      <div class="red-alert-grid">
        <div><strong>Process:</strong> <span id="red-alert-proc">Unknown</span></div>
        <div><strong>Action:</strong> <span id="red-alert-action">Process Suspended</span></div>
        <div><strong>Signals:</strong> <span id="red-alert-signals">Mass modifications</span></div>
        <div><strong>Incident ID:</strong> <span id="red-alert-id">INC-0000</span></div>
      </div>
      <div class="red-alert-actions">
        <button id="btn-red-rollback" class="btn btn-primary" onclick="rollbackActiveIncident()">Reversible Rollback</button>
        <button class="btn btn-secondary" onclick="dismissRedAlert()">Acknowledge</button>
      </div>
    </div>
  </div>

  <!-- Main Dashboard Container -->
  <main class="container">

    <!-- Top Navigation Tabs -->
    <nav class="nav-tabs">
      <button class="tab-btn active" id="btn-tab-overview" onclick="switchTab('tab-overview')">
        <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        <span>Overview</span>
      </button>

      <button class="tab-btn" id="btn-tab-security-alerts" onclick="switchTab('tab-security-alerts')">
        <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <span>Security Alerts</span>
        <span class="badge-count" id="badge-sec-alerts-count" style="display:none;">0</span>
      </button>

      <button class="tab-btn" id="btn-tab-incidents" onclick="switchTab('tab-incidents')">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>Threat Incidents</span>
        <span class="badge-count" id="btn-threat-count">0</span>
      </button>

      <button class="tab-btn" id="btn-tab-windows" onclick="switchTab('tab-windows')">
        <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        <span>Active Windows</span>
      </button>

      <button class="tab-btn" id="btn-tab-downloads" onclick="switchTab('tab-downloads')">
        <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        <span>Downloads & Files</span>
      </button>

      <button class="tab-btn" id="btn-tab-quarantine" onclick="switchTab('tab-quarantine')">
        <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <span>Quarantine Vault</span>
      </button>

      <button class="tab-btn" id="btn-tab-settings" onclick="switchTab('tab-settings')">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
        <span>Pairing & Controls</span>
      </button>
    </nav>

    <!-- TAB 1: OVERVIEW -->
    <div id="tab-overview" class="tab-pane active">

      <!-- Connection Dashboard Card (Requirement 7) -->
      <section class="device-card">
        <div class="device-card-header">
          <div class="device-info-left">
            <div class="device-icon-box">
              <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="2" y1="20" x2="22" y2="20"/></svg>
            </div>
            <div class="device-names">
              <h2 id="dev-host">Security Endpoint</h2>
              <div class="device-type-label">
                <span>Laptop Security Agent</span>
                <span>•</span>
                <span id="dev-id" style="font-family:'JetBrains Mono',monospace;">LAPTOP-ENDPOINT</span>
                <span>•</span>
                <span id="dev-os">Windows 11</span>
              </div>
            </div>
          </div>

          <div style="display:flex; align-items:center; gap:8px;">
            <button class="btn btn-secondary" onclick="fetchStatus(true)">
              <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
              <span>Refresh</span>
            </button>
            <button class="btn btn-primary" onclick="showPairingModal()">
              <svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
              <span>Pair Device</span>
            </button>
          </div>
        </div>

        <div class="device-meta-row">
          <div class="device-meta-item">
            <span class="meta-label">Live Connection</span>
            <span class="meta-value" id="card-connection-status" style="color:var(--success-green);">Connected (Live)</span>
          </div>
          <div class="device-meta-item">
            <span class="meta-label">Last Seen</span>
            <span class="meta-value" id="card-last-seen">Just now</span>
          </div>
          <div class="device-meta-item">
            <span class="meta-label">Local LAN Endpoint</span>
            <span class="meta-value" id="card-lan-ip">127.0.0.1:8765</span>
          </div>
          <div class="device-meta-item">
            <span class="meta-label">Paired Mobile Device</span>
            <span class="meta-value" id="card-paired-mobile">Awaiting Mobile Companion</span>
          </div>
        </div>
      </section>

      <!-- Hardware Telemetry Metric Cards -->
      <section class="metric-grid">
        <!-- CPU Usage -->
        <div class="metric-card">
          <div class="metric-top">
            <div class="metric-label-group">
              <div class="metric-icon-small">
                <svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="15" x2="23" y2="15"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="15" x2="4" y2="15"/></svg>
              </div>
              <span class="metric-title">CPU Utilization</span>
            </div>
            <span class="metric-value-huge" id="gauge-cpu-val">0%</span>
          </div>
          <div class="progress-bar-bg">
            <div id="gauge-cpu-fill" class="progress-fill" style="width: 0%;"></div>
          </div>
          <div class="metric-sub">
            <span id="sub-cpu-cores">4 Cores / 8 Threads</span>
            <span id="sub-cpu-freq">2.4 GHz</span>
          </div>
        </div>

        <!-- RAM Usage -->
        <div class="metric-card">
          <div class="metric-top">
            <div class="metric-label-group">
              <div class="metric-icon-small">
                <svg viewBox="0 0 24 24"><path d="M6 19v-3"/><path d="M10 19v-3"/><path d="M14 19v-3"/><path d="M18 19v-3"/><rect x="2" y="5" width="20" height="10" rx="2"/></svg>
              </div>
              <span class="metric-title">Memory (RAM)</span>
            </div>
            <span class="metric-value-huge" id="gauge-ram-val">0%</span>
          </div>
          <div class="progress-bar-bg">
            <div id="gauge-ram-fill" class="progress-fill fill-amber" style="width: 0%;"></div>
          </div>
          <div class="metric-sub">
            <span id="sub-ram-used">0.0 GB Used</span>
            <span id="sub-ram-total">16.0 GB Total</span>
          </div>
        </div>

        <!-- Disk Storage -->
        <div class="metric-card">
          <div class="metric-top">
            <div class="metric-label-group">
              <div class="metric-icon-small">
                <svg viewBox="0 0 24 24"><line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/></svg>
              </div>
              <span class="metric-title">Storage Drive</span>
            </div>
            <span class="metric-value-huge" id="gauge-disk-val">0%</span>
          </div>
          <div class="progress-bar-bg">
            <div id="gauge-disk-fill" class="progress-fill" style="width: 0%;"></div>
          </div>
          <div class="metric-sub">
            <span id="sub-disk-free">0 GB Free</span>
            <span id="sub-disk-total">512 GB Total</span>
          </div>
        </div>

        <!-- Battery Status -->
        <div class="metric-card">
          <div class="metric-top">
            <div class="metric-label-group">
              <div class="metric-icon-small">
                <svg viewBox="0 0 24 24"><rect x="1" y="6" width="18" height="12" rx="2"/><line x1="23" y1="11" x2="23" y2="13"/></svg>
              </div>
              <span class="metric-title">Battery Status</span>
            </div>
            <span class="metric-value-huge" id="gauge-batt-val">100%</span>
          </div>
          <div class="progress-bar-bg">
            <div id="gauge-batt-fill" class="progress-fill fill-green" style="width: 100%;"></div>
          </div>
          <div class="metric-sub">
            <span id="sub-batt-plugged">AC Power Connected</span>
            <span id="sub-batt-health">Optimal</span>
          </div>
        </div>
      </section>

      <!-- Active Window & Network Telemetry Card -->
      <section class="list-card">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            <span>Network & Active Application</span>
          </div>
          <span class="badge badge-CLEAN" id="badge-health-overview">SECURE</span>
        </div>

        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:14px;">
          <div style="background:var(--bg-subtle); padding:14px; border-radius:8px; border:1px solid var(--border-main);">
            <div style="font-size:11px; text-transform:uppercase; font-weight:600; color:var(--text-muted); margin-bottom:4px;">Current Active Window / Tab</div>
            <div style="font-weight:600; font-size:14px; color:var(--text-main);" id="overview-active-title">Desktop Workspace</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:2px;" id="overview-active-sub">explorer.exe</div>
          </div>

          <div style="background:var(--bg-subtle); padding:14px; border-radius:8px; border:1px solid var(--border-main);">
            <div style="font-size:11px; text-transform:uppercase; font-weight:600; color:var(--text-muted); margin-bottom:4px;">Network I/O Throughput</div>
            <div style="font-weight:600; font-size:14px; color:var(--text-main);" id="overview-net-speed">DL: 0.0 KB/s • UL: 0.0 KB/s</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:2px;" id="overview-net-channel">Local Wi-Fi + Encrypted Cloud Relay</div>
          </div>
        </div>
      </section>

    </div>

    <!-- TAB 2: AUTOMATIC SECURITY ALERTS (Requirement 2) -->
    <div id="tab-security-alerts" class="tab-pane">
      <section class="list-card">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>Automatic Security Event Log</span>
          </div>
          <button class="btn btn-secondary" onclick="fetchSecurityAlerts()">
            <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            <span>Refresh Alerts</span>
          </button>
        </div>

        <p style="font-size:13px; color:var(--text-muted); margin-bottom:14px;">
          Automatic alerts for connection status transitions, new devices, unexpected disconnects, and authentication attempts. No authentication secrets are ever displayed.
        </p>

        <div id="security-alerts-container">
          <div class="empty-placeholder">
            <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>No security anomalies or unauthorized connection attempts detected.</span>
          </div>
        </div>
      </section>
    </div>

    <!-- TAB 3: THREAT INCIDENTS -->
    <div id="tab-incidents" class="tab-pane">
      <section class="list-card">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <span>Correlated Threat Incidents</span>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="btn btn-secondary" onclick="fetchIncidents()">
              <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
              <span>Refresh</span>
            </button>
            <button class="btn btn-secondary" onclick="simulateAlert('mass_file_modification')">
              <span>Simulate Ransomware</span>
            </button>
          </div>
        </div>

        <div id="incidents-container">
          <div class="empty-placeholder">
            <svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            <span>System is clean. No active threat incidents detected.</span>
          </div>
        </div>
      </section>
    </div>

    <!-- TAB 4: ACTIVE WINDOWS & TABS -->
    <div id="tab-windows" class="tab-pane">
      <section class="list-card">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            <span>Foreground Window & Browser History</span>
          </div>
          <button class="btn btn-secondary" onclick="fetchWindows()">
            <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            <span>Refresh</span>
          </button>
        </div>

        <div id="windows-container">
          <div class="empty-placeholder">
            <span>Loading window activities...</span>
          </div>
        </div>
      </section>
    </div>

    <!-- TAB 5: DOWNLOADS & FILE ACTIVITY -->
    <div id="tab-downloads" class="tab-pane">
      <section class="list-card">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            <span>Recent Downloads & File Scans</span>
          </div>
          <button class="btn btn-secondary" onclick="fetchDownloads()">
            <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            <span>Refresh</span>
          </button>
        </div>

        <div id="downloads-container">
          <div class="empty-placeholder">
            <span>No incoming downloads recorded.</span>
          </div>
        </div>
      </section>

      <section class="list-card" style="margin-top:20px;">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <span>Authorized File System Activity</span>
          </div>
        </div>

        <div id="files-container">
          <div class="empty-placeholder">
            <span>No authorized file changes recorded.</span>
          </div>
        </div>
      </section>
    </div>

    <!-- TAB 6: QUARANTINE VAULT -->
    <div id="tab-quarantine" class="tab-pane">
      <section class="list-card">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <span>Quarantine Isolation Vault</span>
          </div>
          <button class="btn btn-secondary" onclick="fetchQuarantine()">
            <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            <span>Refresh Vault</span>
          </button>
        </div>

        <p style="font-size:13px; color:var(--text-muted); margin-bottom:14px;">
          Suspicious files automatically isolated with encrypted headers and stripped execution rights. Reversible at any time.
        </p>

        <div id="quarantine-container">
          <div class="empty-placeholder">
            <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <span>Quarantine vault is empty. No files isolated.</span>
          </div>
        </div>
      </section>
    </div>

    <!-- TAB 7: PAIRING & SECURITY CONTROLS (Requirements 3 & 4) -->
    <div id="tab-settings" class="tab-pane">
      <!-- Device Pairing Card -->
      <section class="pairing-card">
        <div class="pairing-header">
          <div class="pairing-title">
            <svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            <span>Token-Based Device Pairing</span>
          </div>
          <span class="badge badge-INFO" id="pairing-mode-badge">Laptop → Phone</span>
        </div>

        <!-- Unpaired State: Shows Laptop Token for entering on phone -->
        <div id="unpaired-token-view">
          <p style="font-size:13px; color:var(--text-secondary);">
            Open the DefenceIQ Android app on your mobile phone and enter this unique pairing code to securely pair devices:
          </p>

          <div class="token-display-box">
            <div>
              <div class="token-code" id="laptop-pairing-token-val">DIQ-XXXX-XXXX</div>
              <div class="token-expiry-label">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                <span id="token-expiry-countdown">Valid for 10 minutes</span>
              </div>
            </div>

            <div style="display:flex; gap:8px;">
              <button class="btn btn-primary" onclick="copyPairingToken()">
                <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                <span>Copy Code</span>
              </button>
              <button class="btn btn-secondary" onclick="generateFreshToken()">
                <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                <span>Regenerate</span>
              </button>
            </div>
          </div>

          <div style="margin-top:16px; padding:12px; background:var(--bg-subtle); border-radius:8px; border:1px solid var(--border-main);">
            <div style="font-weight:600; font-size:13px; color:var(--text-main); margin-bottom:6px;">Reverse Pairing (Phone → Laptop)</div>
            <p style="font-size:12px; color:var(--text-muted); margin-bottom:10px;">
              Generated a code on your mobile phone? Enter the phone's pairing code below to connect:
            </p>
            <div style="display:flex; gap:8px;">
              <input type="text" id="reverse-mobile-token-input" placeholder="e.g. DIQ-7K9P-4X2M" style="max-width:240px;">
              <button class="btn btn-secondary" onclick="submitReverseMobileToken()">Pair from Phone Code</button>
            </div>
          </div>
        </div>

        <!-- Paired State: Token is hidden, device info displayed (Requirement 3) -->
        <div id="paired-token-view" style="display:none;">
          <div class="paired-state-box">
            <div class="paired-info">
              <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              <div>
                <div style="font-weight:700; font-size:14px; color:#065f46;" id="paired-dev-title">Securely Paired with Mobile Companion</div>
                <div style="font-size:12px; color:#047857;" id="paired-dev-meta">Device: Android Phone • Session Active</div>
              </div>
            </div>

            <button class="btn btn-danger" onclick="revokePairingAction()">
              <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              <span>Revoke & Unpair</span>
            </button>
          </div>
        </div>
      </section>

      <!-- Protection Level Controls -->
      <section class="list-card">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
            <span>Agent Protection Mode</span>
          </div>
        </div>

        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px;">
          <button class="btn btn-secondary" id="btn-mode-basic" onclick="setProtectionMode('basic')">
            <span>Basic (Monitor Only)</span>
          </button>
          <button class="btn btn-primary" id="btn-mode-balanced" onclick="setProtectionMode('balanced')">
            <span>Balanced (Auto-Suspend Red)</span>
          </button>
          <button class="btn btn-secondary" id="btn-mode-maximum" onclick="setProtectionMode('maximum')">
            <span>Maximum (Isolate Red & Orange)</span>
          </button>
        </div>
      </section>

      <!-- Companion APK Download Card -->
      <section class="list-card">
        <div class="list-header">
          <div class="list-title">
            <svg viewBox="0 0 24 24"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
            <span>Android Companion APK</span>
          </div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
          <div>
            <div style="font-weight:600; font-size:14px;">DefenceIQ Android Companion Application</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">Direct download APK to install on your Android device.</div>
          </div>
          <a href="/download-apk" class="btn btn-primary" download style="text-decoration:none;">
            <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            <span>Download APK</span>
          </a>
        </div>
      </section>
    </div>

  </main>

  <!-- Reverse Pairing Modal (Phone -> Laptop) -->
  <div id="pairing-modal" class="modal-backdrop">
    <div class="modal-dialog">
      <div class="modal-title">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--primary-blue)" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
        <span>Pair Mobile Device</span>
      </div>

      <p style="font-size:13px; color:var(--text-secondary);">
        Enter the pairing code generated by your mobile companion app:
      </p>

      <input type="text" id="modal-token-input" placeholder="e.g. DIQ-8K2A-9X1B">

      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:8px;">
        <button class="btn btn-secondary" onclick="hideModal('pairing-modal')">Cancel</button>
        <button class="btn btn-primary" onclick="submitModalToken()">Verify & Pair</button>
      </div>
    </div>
  </div>

  <!-- Toast notification -->
  <div id="toast-msg">
    <span id="toast-text">Message</span>
  </div>

  <script>
    // ── Global State ─────────────────────────────────────────────
    let currentToken = "";
    let lastSeenEpoch = Date.now();
    let pollInterval = null;
    let ws = null;
    let tokenCountdownTimer = null;
    let activeIncidentId = null;

    // ── Tab Navigation ───────────────────────────────────────────
    function switchTab(tabId) {
      document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

      const targetPane = document.getElementById(tabId);
      const targetBtn = document.getElementById('btn-' + tabId);
      if (targetPane) targetPane.classList.add('active');
      if (targetBtn) targetBtn.classList.add('active');

      if (tabId === 'tab-security-alerts') fetchSecurityAlerts();
      if (tabId === 'tab-incidents') fetchIncidents();
      if (tabId === 'tab-windows') fetchWindows();
      if (tabId === 'tab-downloads') { fetchDownloads(); fetchFiles(); }
      if (tabId === 'tab-quarantine') fetchQuarantine();
      if (tabId === 'tab-settings') fetchPairingStatus();
    }

    // ── Toast Helper ─────────────────────────────────────────────
    function showToast(text, isError = false) {
      const toast = document.getElementById('toast-msg');
      const toastTxt = document.getElementById('toast-text');
      toastTxt.innerText = text;
      toast.style.background = isError ? "#b91c1c" : "#0f172a";
      toast.style.display = "flex";
      setTimeout(() => { toast.style.display = "none"; }, 3500);
    }

    function showModal(id) { document.getElementById(id).style.display = 'flex'; }
    function hideModal(id) { document.getElementById(id).style.display = 'none'; }
    function showPairingModal() {
      document.getElementById('modal-token-input').value = "";
      showModal('pairing-modal');
    }

    // ── Copy Token ───────────────────────────────────────────────
    function copyPairingToken() {
      const code = document.getElementById('laptop-pairing-token-val').innerText.trim();
      navigator.clipboard.writeText(code).then(() => {
        showToast("Pairing code copied to clipboard!");
      }).catch(() => {
        showToast("Copied: " + code);
      });
    }

    // ── Reverse Mobile Token Pairing (Phone -> Laptop) ────────────
    async function submitReverseMobileToken() {
      const input = document.getElementById('reverse-mobile-token-input').value.trim().toUpperCase();
      if (!input || input.length < 4) {
        showToast("Please enter a valid pairing code (e.g. DIQ-XXXX-XXXX)", true);
        return;
      }
      await performPairingWithToken(input);
    }

    async function submitModalToken() {
      const input = document.getElementById('modal-token-input').value.trim().toUpperCase();
      if (!input || input.length < 4) {
        showToast("Please enter a valid pairing code (e.g. DIQ-XXXX-XXXX)", true);
        return;
      }
      hideModal('pairing-modal');
      await performPairingWithToken(input);
    }

    async function performPairingWithToken(tok) {
      try {
        const res = await fetch("/pair-mobile", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: tok, device_name: "Mobile Companion", device_type: "mobile" })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          currentToken = tok;
          localStorage.setItem("defenceiq_token", currentToken);
          showToast("Successfully paired with mobile device!");
          fetchPairingStatus();
          fetchStatus();
        } else {
          showToast(data.detail || "Pairing failed. Please verify the code.", true);
        }
      } catch (e) {
        showToast("Connection error during pairing: " + e.message, true);
      }
    }

    // ── Generate Fresh Token ─────────────────────────────────────
    async function generateFreshToken() {
      try {
        const res = await fetch("/token/generate", { method: "POST" });
        const data = await res.json();
        if (data.success && data.token) {
          currentToken = data.token;
          localStorage.setItem("defenceiq_token", currentToken);
          document.getElementById('laptop-pairing-token-val').innerText = currentToken;
          document.getElementById('header-token-text').innerText = currentToken;
          showToast("Generated fresh pairing code.");
          startTokenTimer(600);
        }
      } catch (e) {
        showToast("Error generating token: " + e.message, true);
      }
    }

    // ── Revoke Pairing ───────────────────────────────────────────
    async function revokePairingAction() {
      if (!confirm("Revoke pairing and unpair all connected devices?")) return;
      try {
        const res = await fetch("/revoke-pairing", { method: "POST" });
        const data = await res.json();
        if (data.success) {
          currentToken = data.new_token || "";
          localStorage.setItem("defenceiq_token", currentToken);
          showToast("Pairing revoked and secrets rotated.");
          fetchPairingStatus();
          fetchStatus();
        }
      } catch (e) {
        showToast("Error revoking pairing: " + e.message, true);
      }
    }

    // ── Protection Mode ──────────────────────────────────────────
    async function setProtectionMode(level) {
      try {
        const res = await fetch("/protection/level?token=" + encodeURIComponent(currentToken), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ level: level })
        });
        if (res.ok) {
          showToast("Protection mode updated to " + level.toUpperCase());
          updateModeButtons(level);
        }
      } catch (e) {
        showToast("Error updating protection mode: " + e.message, true);
      }
    }

    function updateModeButtons(level) {
      ['basic', 'balanced', 'maximum'].forEach(m => {
        const btn = document.getElementById('btn-mode-' + m);
        if (btn) {
          btn.className = (m === level.toLowerCase()) ? "btn btn-primary" : "btn btn-secondary";
        }
      });
    }

    // ── Token Countdown Timer ────────────────────────────────────
    function startTokenTimer(secondsLeft) {
      if (tokenCountdownTimer) clearInterval(tokenCountdownTimer);
      let s = secondsLeft;
      const el = document.getElementById('token-expiry-countdown');
      tokenCountdownTimer = setInterval(() => {
        if (s <= 0) {
          clearInterval(tokenCountdownTimer);
          el.innerText = "Token expired. Click Regenerate.";
          el.style.color = "var(--danger-red)";
        } else {
          const m = Math.floor(s / 60);
          const rem = s % 60;
          el.innerText = `Valid for ${m}m ${rem < 10 ? '0' : ''}${rem}s`;
          el.style.color = "var(--text-muted)";
          s--;
        }
      }, 1000);
    }

    // ── Pairing Status Fetcher ───────────────────────────────────
    async function fetchPairingStatus() {
      try {
        const res = await fetch("/pairing/status");
        if (!res.ok) return;
        const data = await res.json();

        const unpairedView = document.getElementById('unpaired-token-view');
        const pairedView = document.getElementById('paired-token-view');
        const headerTokenText = document.getElementById('header-token-text');
        const cardConn = document.getElementById('card-connection-status');
        const cardMobile = document.getElementById('card-paired-mobile');
        const modeBadge = document.getElementById('pairing-mode-badge');

        if (data.is_paired && data.paired_device) {
          unpairedView.style.display = 'none';
          pairedView.style.display = 'block';
          modeBadge.innerText = "Paired";
          modeBadge.className = "badge badge-LOW";
          headerTokenText.innerText = "Paired: " + (data.paired_device.device_name || "Phone");
          cardMobile.innerText = data.paired_device.device_name + " (Paired)";
          document.getElementById('paired-dev-title').innerText = "Paired with " + data.paired_device.device_name;
          document.getElementById('paired-dev-meta').innerText = `Device Type: ${data.paired_device.device_type || 'Mobile'} • Paired at ${data.paired_device.paired_at ? new Date(data.paired_device.paired_at).toLocaleTimeString() : 'Recently'}`;
        } else {
          unpairedView.style.display = 'block';
          pairedView.style.display = 'none';
          modeBadge.innerText = "Awaiting Pairing";
          modeBadge.className = "badge badge-INFO";
          cardMobile.innerText = "Awaiting Mobile Companion";

          if (data.active_token && data.active_token.token) {
            currentToken = data.active_token.token;
            localStorage.setItem("defenceiq_token", currentToken);
            document.getElementById('laptop-pairing-token-val').innerText = currentToken;
            headerTokenText.innerText = currentToken;
            startTokenTimer(data.active_token.ttl_seconds_remaining || 600);
          }
        }

        // Live connection badge
        updateConnectionBadge(data.connection_status || "Connected");
      } catch (e) {
        console.debug("fetchPairingStatus note:", e);
      }
    }

    // ── Update Connection Badge (Requirement 1) ──────────────────
    function updateConnectionBadge(statusStr) {
      const pill = document.getElementById('device-status-pill');
      const dot = document.getElementById('status-dot');
      const txt = document.getElementById('status-text');
      const cardConn = document.getElementById('card-connection-status');

      txt.innerText = statusStr;
      if (cardConn) cardConn.innerText = statusStr;

      const norm = (statusStr || "").toLowerCase().replace(/\\s+/g, '-');
      pill.className = "status-pill " + norm;

      if (norm.includes("connected") && !norm.includes("lost")) {
        dot.className = "pulse-dot pulse-green";
        if (cardConn) cardConn.style.color = "var(--success-green)";
      } else if (norm.includes("connecting")) {
        dot.className = "pulse-dot pulse-blue";
        if (cardConn) cardConn.style.color = "var(--primary-blue)";
      } else if (norm.includes("connection-lost")) {
        dot.className = "pulse-dot pulse-amber";
        if (cardConn) cardConn.style.color = "var(--warning-amber)";
      } else if (norm.includes("offline")) {
        dot.className = "pulse-dot pulse-red";
        if (cardConn) cardConn.style.color = "var(--danger-red)";
      } else {
        dot.className = "pulse-dot pulse-gray";
        if (cardConn) cardConn.style.color = "var(--text-secondary)";
      }
    }

    // ── Fetch Status & Telemetry ─────────────────────────────────
    async function fetchStatus(isManual = false) {
      try {
        const res = await fetch("/device/status?token=" + encodeURIComponent(currentToken));
        if (res.ok) {
          const data = await res.json();
          lastSeenEpoch = Date.now();
          renderDeviceMetrics(data);
          if (isManual) showToast("Telemetry refreshed.");
        } else {
          checkOfflineFallback();
        }
      } catch (e) {
        checkOfflineFallback();
      }
    }

    function checkOfflineFallback() {
      const elapsed = Math.round((Date.now() - lastSeenEpoch) / 1000);
      if (elapsed > 15) {
        updateConnectionBadge("Laptop Offline");
        document.getElementById('card-last-seen').innerText = `${elapsed}s ago (Offline)`;
      }
    }

    function renderDeviceMetrics(data) {
      document.getElementById('dev-host').innerText = data.hostname || "Security Endpoint";
      document.getElementById('dev-id').innerText = data.device_id || "LAPTOP-ENDPOINT";
      if (data.network_status && data.network_status.lan_ip) {
        document.getElementById('card-lan-ip').innerText = `${data.network_status.lan_ip}:${data.network_status.port || 8765}`;
      }

      document.getElementById('card-last-seen').innerText = "Just now";

      if (data.connection_status) {
        updateConnectionBadge(data.connection_status);
      }

      if (data.protection_level) {
        updateModeButtons(data.protection_level);
      }

      const sm = data.system_metrics;
      if (sm) {
        const cpu = sm.cpu_percent || 0;
        document.getElementById('gauge-cpu-val').innerText = cpu + "%";
        document.getElementById('gauge-cpu-fill').style.width = Math.min(cpu, 100) + "%";
        document.getElementById('sub-cpu-cores').innerText = `${sm.cpu_cores_physical || 4} Cores / ${sm.cpu_cores_logical || 8} Threads`;
        document.getElementById('sub-cpu-freq').innerText = `${sm.cpu_freq_mhz || 2400} MHz`;

        if (sm.ram) {
          const ramP = sm.ram.percent || 0;
          document.getElementById('gauge-ram-val').innerText = ramP + "%";
          document.getElementById('gauge-ram-fill').style.width = Math.min(ramP, 100) + "%";
          document.getElementById('sub-ram-used').innerText = `${sm.ram.used_gb || 0} GB Used`;
          document.getElementById('sub-ram-total').innerText = `${sm.ram.total_gb || 16} GB Total`;
        }

        if (sm.disk) {
          const diskP = sm.disk.percent || 0;
          document.getElementById('gauge-disk-val').innerText = diskP + "%";
          document.getElementById('gauge-disk-fill').style.width = Math.min(diskP, 100) + "%";
          document.getElementById('sub-disk-free').innerText = `${sm.disk.free_gb || 0} GB Free`;
          document.getElementById('sub-disk-total').innerText = `${sm.disk.total_gb || 512} GB Total`;
        }

        if (sm.battery) {
          const battP = sm.battery.percent !== null ? sm.battery.percent : 100;
          document.getElementById('gauge-batt-val').innerText = battP + "%";
          document.getElementById('gauge-batt-fill').style.width = Math.min(battP, 100) + "%";
          document.getElementById('sub-batt-plugged').innerText = sm.battery.plugged ? "AC Power Connected ⚡" : "On Battery 🔋";
        }

        if (sm.network) {
          document.getElementById('overview-net-speed').innerText = `DL: ${sm.network.download_speed_kbps || 0} KB/s • UL: ${sm.network.upload_speed_kbps || 0} KB/s`;
        }
      }
    }

    // ── Fetch Security Alerts (Requirement 2) ────────────────────
    async function fetchSecurityAlerts() {
      try {
        const res = await fetch("/security/alerts");
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('security-alerts-container');
        const badge = document.getElementById('badge-sec-alerts-count');

        if (!data.alerts || data.alerts.length === 0) {
          container.innerHTML = `
            <div class="empty-placeholder">
              <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              <span>No security anomalies or unauthorized connection attempts detected.</span>
            </div>`;
          badge.style.display = 'none';
          return;
        }

        badge.innerText = data.alerts.length;
        badge.style.display = 'inline-block';

        let html = '';
        data.alerts.forEach(a => {
          const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : 'Just now';
          const sevClass = a.severity || 'INFO';
          html += `
            <div class="item-card">
              <div class="item-card-top">
                <span class="item-name">
                  <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  <span>${escapeHtml(a.event_type ? a.event_type.replace(/_/g, ' ') : 'Security Event')}</span>
                </span>
                <span class="badge badge-${sevClass}">${sevClass}</span>
              </div>
              <div style="font-size:13px; color:var(--text-secondary); margin-top:2px;">
                ${escapeHtml(a.details || 'Security event logged.')}
              </div>
              <div class="item-meta">
                <span><strong>Device:</strong> ${escapeHtml(a.device_name || 'Endpoint')}</span>
                <span><strong>Status:</strong> ${escapeHtml(a.connection_status || 'Logged')}</span>
                <span><strong>Time:</strong> ${timeStr}</span>
              </div>
            </div>`;
        });
        container.innerHTML = html;
      } catch (e) {
        console.debug("fetchSecurityAlerts note:", e);
      }
    }

    // ── Fetch Threat Incidents ───────────────────────────────────
    async function fetchIncidents() {
      try {
        const res = await fetch("/incidents?token=" + encodeURIComponent(currentToken));
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('incidents-container');
        const countBadge = document.getElementById('btn-threat-count');

        countBadge.innerText = data.count || (data.incidents ? data.incidents.length : 0);

        if (!data.incidents || data.incidents.length === 0) {
          container.innerHTML = `
            <div class="empty-placeholder">
              <svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              <span>System is clean. No active threat incidents detected.</span>
            </div>`;
          return;
        }

        let html = '';
        data.incidents.forEach(inc => {
          const score = inc.risk_score || 0;
          const band = inc.risk_band || 'LOW';
          const isRed = band === 'RED' || score >= 85;

          if (isRed && inc.status === 'OPEN') {
            triggerRedAlert(inc);
          }

          html += `
            <div class="item-card">
              <div class="item-card-top">
                <span class="item-name">
                  <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                  <span>${escapeHtml(inc.root_process_name || 'Process')} (PID: ${inc.root_pid || 'N/A'})</span>
                </span>
                <span class="badge badge-${band}">SCORE ${score} • ${band}</span>
              </div>
              <div style="font-size:13px; color:var(--text-secondary);">
                ${escapeHtml(inc.explanation || 'Suspicious signals detected')}
              </div>
              <div class="item-meta">
                <span><strong>ID:</strong> ${inc.incident_id}</span>
                <span><strong>Status:</strong> ${inc.status}</span>
                <span><strong>Signals:</strong> ${(inc.signals || []).join(', ') || 'Anomaly'}</span>
              </div>
              <div style="display:flex; gap:8px; margin-top:4px;">
                <button class="btn btn-primary" onclick="rollbackIncident('${inc.incident_id}')">Reversible Rollback</button>
                <button class="btn btn-secondary" onclick="acknowledgeIncident('${inc.incident_id}')">Acknowledge</button>
              </div>
            </div>`;
        });
        container.innerHTML = html;
      } catch (e) {
        console.debug("fetchIncidents note:", e);
      }
    }

    async function rollbackIncident(id) {
      try {
        const res = await fetch(`/incidents/${id}/rollback?token=` + encodeURIComponent(currentToken), { method: "POST" });
        if (res.ok) {
          showToast(`Incident ${id} rollback executed.`);
          dismissRedAlert();
          fetchIncidents();
        }
      } catch (e) {
        showToast("Rollback error: " + e.message, true);
      }
    }

    async function acknowledgeIncident(id) {
      try {
        const res = await fetch(`/actions/respond?token=` + encodeURIComponent(currentToken), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "acknowledge", incident_id: id })
        });
        if (res.ok) {
          showToast(`Incident ${id} acknowledged.`);
          dismissRedAlert();
          fetchIncidents();
        }
      } catch (e) {
        showToast("Error: " + e.message, true);
      }
    }

    // ── Red Alert Banner Handlers ────────────────────────────────
    function triggerRedAlert(inc) {
      activeIncidentId = inc.incident_id;
      const banner = document.getElementById('red-alert-banner');
      document.getElementById('red-alert-title').innerText = "CRITICAL SECURITY INCIDENT DETECTED";
      document.getElementById('red-alert-score').innerText = "SCORE: " + (inc.risk_score || 95);
      document.getElementById('red-alert-proc').innerText = inc.root_process_name || "malware.exe";
      document.getElementById('red-alert-action').innerText = inc.status === "CONTAINED" ? "Process Suspended" : "Containment Active";
      document.getElementById('red-alert-signals').innerText = (inc.signals || []).slice(0, 2).join(', ');
      document.getElementById('red-alert-id').innerText = inc.incident_id || "INC-0000";
      banner.style.display = "block";
    }

    function dismissRedAlert() {
      document.getElementById('red-alert-banner').style.display = "none";
    }

    function rollbackActiveIncident() {
      if (activeIncidentId) rollbackIncident(activeIncidentId);
    }

    // ── Simulation Helper ────────────────────────────────────────
    async function simulateAlert(scenario) {
      try {
        const res = await fetch("/simulate/alert?token=" + encodeURIComponent(currentToken), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scenario: scenario })
        });
        const data = await res.json();
        if (data.success) {
          showToast("Simulated threat generated: " + scenario);
          fetchIncidents();
        }
      } catch (e) {
        showToast("Simulation error: " + e.message, true);
      }
    }

    // ── Fetch Windows / Tabs ─────────────────────────────────────
    async function fetchWindows() {
      try {
        const res = await fetch("/activities/windows?token=" + encodeURIComponent(currentToken));
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('windows-container');

        if (data.current_activity) {
          document.getElementById('overview-active-title').innerText = data.current_activity.window_title || "Active Workspace";
          document.getElementById('overview-active-sub').innerText = `${data.current_activity.process_name || 'system'} • ${data.current_activity.domain || 'Local'}`;
        }

        const recent = data.recent_activities || [];
        if (recent.length === 0) {
          container.innerHTML = `<div class="empty-placeholder"><span>No recent window activity recorded.</span></div>`;
          return;
        }

        let html = '';
        recent.forEach(w => {
          html += `
            <div class="item-card">
              <div class="item-card-top">
                <span class="item-name">
                  <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/></svg>
                  <span>${escapeHtml(w.window_title || 'Untitled')}</span>
                </span>
                <span class="badge badge-INFO">${escapeHtml(w.process_name || 'app')}</span>
              </div>
              <div class="item-meta">
                ${w.domain ? `<span><strong>Domain:</strong> ${escapeHtml(w.domain)}</span>` : ''}
                <span><strong>Duration:</strong> ${w.duration_seconds || 1}s</span>
                <span><strong>Time:</strong> ${w.timestamp ? new Date(w.timestamp).toLocaleTimeString() : ''}</span>
              </div>
            </div>`;
        });
        container.innerHTML = html;
      } catch (e) {
        console.debug("fetchWindows note:", e);
      }
    }

    // ── Fetch Downloads & Files ──────────────────────────────────
    async function fetchDownloads() {
      try {
        const res = await fetch("/activities/downloads?token=" + encodeURIComponent(currentToken));
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('downloads-container');

        if (!data.downloads || data.downloads.length === 0) {
          container.innerHTML = `<div class="empty-placeholder"><span>No downloads recorded.</span></div>`;
          return;
        }

        let html = '';
        data.downloads.forEach(d => {
          const verdict = d.scan_verdict || 'CLEAN';
          const isMal = verdict === 'MALICIOUS' || verdict === 'SUSPICIOUS';
          html += `
            <div class="item-card">
              <div class="item-card-top">
                <span class="item-name">
                  <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  <span>${escapeHtml(d.file_name || 'Download')}</span>
                </span>
                <span class="badge badge-${isMal ? 'RED' : 'GREEN'}">${verdict}</span>
              </div>
              <div class="item-meta">
                <span><strong>Size:</strong> ${(d.file_size_bytes / 1024).toFixed(1)} KB</span>
                <span><strong>Source:</strong> ${escapeHtml(d.origin_domain || 'Web')}</span>
                <span><strong>Time:</strong> ${d.timestamp ? new Date(d.timestamp).toLocaleTimeString() : ''}</span>
              </div>
            </div>`;
        });
        container.innerHTML = html;
      } catch (e) {
        console.debug("fetchDownloads note:", e);
      }
    }

    async function fetchFiles() {
      try {
        const res = await fetch("/activities/files?token=" + encodeURIComponent(currentToken));
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('files-container');

        if (!data.activities || data.activities.length === 0) {
          container.innerHTML = `<div class="empty-placeholder"><span>No file activity recorded.</span></div>`;
          return;
        }

        let html = '';
        data.activities.slice(0, 15).forEach(f => {
          html += `
            <div class="item-card">
              <div class="item-card-top">
                <span class="item-name">
                  <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                  <span>${escapeHtml(f.file_path ? f.file_path.split('\\\\').pop() : 'File')}</span>
                </span>
                <span class="badge badge-INFO">${escapeHtml(f.event_type || 'CHANGE')}</span>
              </div>
              <div class="item-meta">
                <span><strong>Path:</strong> ${escapeHtml(f.file_path || '')}</span>
                <span><strong>Time:</strong> ${f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : ''}</span>
              </div>
            </div>`;
        });
        container.innerHTML = html;
      } catch (e) {
        console.debug("fetchFiles note:", e);
      }
    }

    // ── Fetch Quarantine Vault ───────────────────────────────────
    async function fetchQuarantine() {
      try {
        const res = await fetch("/quarantine?token=" + encodeURIComponent(currentToken));
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('quarantine-container');

        if (!data.quarantined_files || data.quarantined_files.length === 0) {
          container.innerHTML = `
            <div class="empty-placeholder">
              <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              <span>Quarantine vault is empty. No files isolated.</span>
            </div>`;
          return;
        }

        let html = '';
        data.quarantined_files.forEach(q => {
          html += `
            <div class="item-card">
              <div class="item-card-top">
                <span class="item-name">
                  <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                  <span>${escapeHtml(q.original_name || 'Isolated File')}</span>
                </span>
                <span class="badge badge-RED">${q.status || 'CONTAINED'}</span>
              </div>
              <div class="item-meta">
                <span><strong>ID:</strong> ${q.quarantine_id}</span>
                <span><strong>Isolated At:</strong> ${q.quarantined_at ? new Date(q.quarantined_at).toLocaleString() : ''}</span>
              </div>
              <div style="margin-top:6px;">
                <button class="btn btn-success" onclick="restoreQuarantineFile('${q.quarantine_id}')">Restore File</button>
              </div>
            </div>`;
        });
        container.innerHTML = html;
      } catch (e) {
        console.debug("fetchQuarantine note:", e);
      }
    }

    async function restoreQuarantineFile(qid) {
      try {
        const res = await fetch(`/quarantine/${qid}/restore?token=` + encodeURIComponent(currentToken), { method: "POST" });
        if (res.ok) {
          showToast(`File ${qid} restored to original location.`);
          fetchQuarantine();
        }
      } catch (e) {
        showToast("Error restoring file: " + e.message, true);
      }
    }

    // ── Escape HTML Helper ───────────────────────────────────────
    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    // ── WebSocket Live Connection ────────────────────────────────
    function setupWebSocket() {
      if (ws) {
        try { ws.close(); } catch(e){}
      }
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${proto}//${window.location.host}/ws/alerts?token=${encodeURIComponent(currentToken)}`;

      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => {
          updateConnectionBadge("Connected");
          document.getElementById('card-last-seen').innerText = "Just now";
        };
        ws.onmessage = (event) => {
          lastSeenEpoch = Date.now();
          document.getElementById('card-last-seen').innerText = "Just now";
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === "incident" && msg.incident) {
              if (msg.incident.risk_band === "RED" || msg.incident.risk_score >= 85) {
                triggerRedAlert(msg.incident);
              }
              fetchIncidents();
            } else if (msg.type === "security_alert") {
              fetchSecurityAlerts();
            } else if (msg.type === "device_paired" || msg.type === "paired_mobile" || msg.type === "pairing_revoked") {
              fetchPairingStatus();
            }
          } catch(e){}
        };
        ws.onclose = () => {
          updateConnectionBadge("Connection Lost");
          setTimeout(setupWebSocket, 4000);
        };
      } catch(e) {
        console.debug("WS connection note:", e);
      }
    }

    // ── App Initialization ───────────────────────────────────────
    function init() {
      // Check URL query parameters for token first
      const params = new URLSearchParams(window.location.search);
      const urlToken = params.get("token");
      if (urlToken) {
        currentToken = urlToken.trim().toUpperCase();
        localStorage.setItem("defenceiq_token", currentToken);
      } else {
        currentToken = localStorage.getItem("defenceiq_token") || "";
      }

      fetchPairingStatus();
      fetchStatus();
      fetchSecurityAlerts();
      fetchIncidents();
      fetchWindows();
      setupWebSocket();

      // Periodic auto-refresh every 3.5 seconds
      if (pollInterval) clearInterval(pollInterval);
      pollInterval = setInterval(() => {
        fetchStatus();
        fetchPairingStatus();
      }, 3500);
    }

    window.addEventListener("DOMContentLoaded", init);
  </script>
</body>
</html>"""
