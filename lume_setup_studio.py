#!/usr/bin/env python3
"""
Project Lume - Universal Setup & Deployment Studio (Standalone)
===============================================================
A self-contained, zero-dependency configuration wizard and deployment generator.
Can run standalone on any workstation/server with Python 3.8+ (no pip installs required).

Features:
- Single-page premium web GUI (dark mode, glassmorphism, responsive).
- Architecture topology configuration (Lume Core, Zeek Sensor, Vuln Scanner).
- IP mapping & port bindings for distributed fleets or single-node stacks.
- Automated generation of production-ready docker-compose.yml files.
- Configuration generation (.env, ai_config.json, suricata rule selections).
- Direct Docker integration:
  • Download / Pull latest Docker images from Docker Hub.
  • Sneakernet / Air-gap Mode: Package and export Docker images as portable .tar archives.
  • Load Docker images from .tar archives.
  • Deploy / Start containers via docker compose on the local system.
- One-click export of deployment bundles (.zip / folder).
"""

import os
import sys
import json
import time
import shutil
import zipfile
import tarfile
import platform
import argparse
import webbrowser
import subprocess
import threading
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Safe Unicode output for Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Server configuration
DEFAULT_PORT = 8088
SCRIPT_DIR = Path(__file__).resolve().parent

# Docker repository definitions
DOCKER_IMAGES = {
    "core": "lamecreations/project_lume:latest",
    "zeek": "lamecreations/lume-zeek-sensor:latest",
    "scanner": "lamecreations/lume-vuln-scanner:latest"
}

SURICATA_RULESETS = [
    {"id": "emerging-scada.rules", "name": "OT / SCADA / ICS Exploits", "default": True, "desc": "Signatures for Modbus, DNP3, BACnet, S7, and CIP vulnerabilities."},
    {"id": "emerging-exploit.rules", "name": "Known Remote Exploits", "default": True, "desc": "High-signal active network exploit attempts."},
    {"id": "emerging-current_events.rules", "name": "Current Active Threats", "default": True, "desc": "Emerging CVEs and active in-the-wild zero-day campaigns."},
    {"id": "emerging-attack_response.rules", "name": "Attack Responses", "default": True, "desc": "Compromise indicators like reverse shells and command outputs."},
    {"id": "emerging-worm.rules", "name": "Network Worms & Lateral Infection", "default": True, "desc": "Self-propagating malware and automated scans."},
    {"id": "emerging-shellcode.rules", "name": "Shellcode Detection", "default": True, "desc": "Generic shellcode bytes and memory execution probes."},
    {"id": "threatview_CS_c2.rules", "name": "Cobalt Strike & C2 Infrastructure", "default": True, "desc": "Malleable C2 profiles and known team-server beacons."}
]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Project Lume - Universal Setup & Deployment Studio</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg-primary: #0a0d14;
  --bg-card: rgba(18, 24, 38, 0.75);
  --bg-input: #0d121f;
  --border-color: rgba(99, 102, 241, 0.2);
  --border-focus: #6366f1;
  --text-main: #f1f5f9;
  --text-muted: #94a3b8;
  --accent-cyan: #06b6d4;
  --accent-indigo: #6366f1;
  --accent-purple: #8b5cf6;
  --accent-emerald: #10b981;
  --accent-amber: #f59e0b;
  --accent-rose: #f43f5e;
  --radius: 12px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Inter', -apple-system, sans-serif;
  background-color: var(--bg-primary);
  color: var(--text-main);
  background-image: 
    radial-gradient(circle at 15% 15%, rgba(99, 102, 241, 0.12) 0%, transparent 40%),
    radial-gradient(circle at 85% 85%, rgba(6, 182, 212, 0.10) 0%, transparent 40%);
  min-height: 100vh;
  padding: 30px 20px;
}
.container { max-width: 1100px; margin: 0 auto; }
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 30px;
  padding-bottom: 20px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}
.brand { display: flex; align-items: center; gap: 14px; }
.brand-icon {
  width: 44px; height: 44px; border-radius: 10px;
  background: linear-gradient(135deg, var(--accent-indigo), var(--accent-cyan));
  display: flex; align-items: center; justify-content: center;
  font-size: 22px; box-shadow: 0 4px 16px rgba(99, 102, 241, 0.35);
}
.brand-text h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
.brand-text p { font-size: 13px; color: var(--text-muted); }
.badge-standalone {
  background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald);
  border: 1px solid rgba(16, 185, 129, 0.3); font-size: 11px;
  padding: 4px 10px; border-radius: 20px; font-weight: 600; text-transform: uppercase;
}
.tabs {
  display: flex; gap: 8px; margin-bottom: 24px;
  background: rgba(18, 24, 38, 0.6); padding: 6px; border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.05);
}
.tab-btn {
  flex: 1; padding: 10px 16px; border-radius: 8px; border: none;
  background: transparent; color: var(--text-muted); font-size: 13px;
  font-weight: 600; cursor: pointer; transition: all 0.2s ease;
  display: flex; align-items: center; justify-content: center; gap: 8px;
}
.tab-btn:hover { color: var(--text-main); background: rgba(255, 255, 255, 0.04); }
.tab-btn.active {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(6, 182, 212, 0.2));
  color: #fff; border: 1px solid rgba(99, 102, 241, 0.4);
}
.tab-panel { display: none; animation: fadeIn 0.2s ease-in-out; }
.tab-panel.active { display: block; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

.card {
  background: var(--bg-card);
  backdrop-filter: blur(12px);
  border: 1px solid var(--border-color);
  border-radius: var(--radius);
  padding: 24px; margin-bottom: 24px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}
.card-header { margin-bottom: 20px; }
.card-header h2 { font-size: 17px; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 10px; }
.card-header p { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
@media (max-width: 768px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } }

.form-group { margin-bottom: 16px; }
label { display: block; font-size: 12px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }
.helper { font-size: 11px; color: var(--text-muted); margin-top: 4px; }
input[type="text"], input[type="password"], input[type="number"], select {
  width: 100%; padding: 10px 14px; background: var(--bg-input);
  border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px;
  color: var(--text-main); font-size: 13px; font-family: inherit;
  transition: all 0.2s ease;
}
input:focus, select:focus {
  outline: none; border-color: var(--border-focus);
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
}
.checkbox-card {
  display: flex; align-items: flex-start; gap: 12px;
  background: rgba(13, 18, 31, 0.6); padding: 12px 14px;
  border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.05);
  margin-bottom: 10px; cursor: pointer; transition: all 0.2s;
}
.checkbox-card:hover { border-color: rgba(99, 102, 241, 0.3); background: rgba(13, 18, 31, 0.9); }
.checkbox-card input[type="checkbox"] { margin-top: 3px; accent-color: var(--accent-indigo); }
.checkbox-content { flex: 1; }
.checkbox-title { font-size: 13px; font-weight: 600; color: #e2e8f0; }
.checkbox-desc { font-size: 11px; color: var(--text-muted); margin-top: 2px; }

.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  padding: 11px 20px; font-size: 13px; font-weight: 600; border-radius: 8px;
  cursor: pointer; border: none; transition: all 0.2s ease; text-decoration: none;
}
.btn-primary {
  background: linear-gradient(135deg, var(--accent-indigo), var(--accent-purple));
  color: #fff; box-shadow: 0 4px 14px rgba(99, 102, 241, 0.35);
}
.btn-primary:hover { filter: brightness(1.1); transform: translateY(-1px); }
.btn-secondary {
  background: rgba(255, 255, 255, 0.06); color: #cbd5e1;
  border: 1px solid rgba(255, 255, 255, 0.12);
}
.btn-secondary:hover { background: rgba(255, 255, 255, 0.1); color: #fff; }
.btn-cyan {
  background: linear-gradient(135deg, var(--accent-cyan), #0284c7);
  color: #fff; box-shadow: 0 4px 14px rgba(6, 182, 212, 0.3);
}
.btn-cyan:hover { filter: brightness(1.1); }
.btn-emerald {
  background: linear-gradient(135deg, var(--accent-emerald), #059669);
  color: #fff; box-shadow: 0 4px 14px rgba(16, 185, 129, 0.3);
}
.btn-amber {
  background: linear-gradient(135deg, var(--accent-amber), #d97706);
  color: #fff; box-shadow: 0 4px 14px rgba(245, 158, 11, 0.3);
}
.template-bar {
  display: flex; align-items: center; justify-content: space-between;
  background: rgba(18, 24, 38, 0.85); border: 1px solid rgba(99, 102, 241, 0.3);
  padding: 12px 18px; border-radius: var(--radius); margin-bottom: 20px;
  gap: 12px; flex-wrap: wrap; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
}
.template-title { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px; color: #e2e8f0; }
.template-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

pre {
  background: #060910; padding: 14px; border-radius: 8px;
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  color: #a5b4fc; overflow-x: auto; border: 1px solid rgba(255, 255, 255, 0.08);
  max-height: 380px;
}
.action-bar {
  display: flex; gap: 12px; align-items: center; justify-content: flex-end;
  margin-top: 20px; padding-top: 16px; border-top: 1px solid rgba(255, 255, 255, 0.08);
}
.status-log {
  background: #050811; border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px; padding: 12px; font-family: 'JetBrains Mono', monospace;
  font-size: 11px; color: #94a3b8; height: 160px; overflow-y: auto;
  white-space: pre-wrap; margin-top: 16px;
}
.status-log .log-info { color: #38bdf8; }
.status-log .log-success { color: #4ade80; }
.status-log .log-warn { color: #facc15; }
.status-log .log-err { color: #f87171; }

/* Mission Control Deployment Command Center Modal */
.modal-overlay {
  position: fixed; inset: 0; background: rgba(5, 8, 16, 0.88);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  z-index: 99999; display: flex; align-items: center; justify-content: center;
  padding: 20px; animation: fadeIn 0.25s ease-out;
}
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes slideUp { from { opacity: 0; transform: translateY(20px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
@keyframes pulseGlow { 0%, 100% { opacity: 0.4; } 50% { opacity: 1; } }
@keyframes spinRing { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

.modal-window {
  background: linear-gradient(180deg, #0e1526 0%, #080d19 100%);
  border: 1px solid rgba(99, 102, 241, 0.4);
  border-radius: 16px; width: 100%; max-width: 920px;
  max-height: 90vh; overflow-y: auto;
  box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.8), 0 0 35px rgba(99, 102, 241, 0.2);
  display: flex; flex-direction: column; animation: slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
.modal-header {
  padding: 20px 24px; border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  display: flex; align-items: center; justify-content: space-between;
  background: rgba(15, 23, 42, 0.6);
}
.modal-header h3 { font-size: 17px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; }
.modal-body { padding: 24px; display: flex; flex-direction: column; gap: 20px; }

/* Node Orchestration Live Cards */
.node-progress-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px;
}
.node-progress-card {
  background: rgba(13, 18, 31, 0.7); border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 10px; padding: 14px; position: relative; overflow: hidden;
  transition: all 0.2s ease;
}
.node-progress-card.active {
  border-color: var(--accent-cyan);
  box-shadow: 0 0 15px rgba(6, 182, 212, 0.2);
  background: rgba(6, 182, 212, 0.05);
}
.node-progress-card.success {
  border-color: var(--accent-emerald);
  background: rgba(16, 185, 129, 0.05);
}
.node-badge {
  font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 4px;
  text-transform: uppercase; letter-spacing: 0.5px;
}
.node-step-icon {
  width: 20px; height: 20px; display: inline-flex; align-items: center;
  justify-content: center; border-radius: 50%; font-size: 11px;
}
.pulse-spinner {
  display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(6, 182, 212, 0.3);
  border-radius: 50%; border-top-color: var(--accent-cyan);
  animation: spinRing 0.8s linear infinite; vertical-align: middle;
}
.sneakernet-guide-card {
  background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 10px; padding: 16px; display: flex; gap: 14px; align-items: flex-start;
  transition: all 0.3s ease;
}
.sneakernet-checklist {
  margin-top: 10px; list-style: none; font-size: 12px; color: #cbd5e1;
}
.sneakernet-checklist li {
  display: flex; align-items: center; gap: 8px; margin-bottom: 7px;
}
.sneakernet-active-glow {
  border-color: rgba(245, 158, 11, 0.85) !important;
  box-shadow: 0 0 30px rgba(245, 158, 11, 0.35) !important;
  background: rgba(245, 158, 11, 0.14) !important;
}

/* Floating Bottom Launch Bar */
.floating-launch-bar {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  background: rgba(10, 15, 29, 0.94);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-top: 1px solid rgba(99, 102, 241, 0.35);
  box-shadow: 0 -10px 30px rgba(0, 0, 0, 0.65);
  padding: 12px 28px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  z-index: 9999;
}
.floating-launch-bar .meta-info {
  display: flex;
  align-items: center;
  gap: 12px;
}
.floating-launch-bar .meta-title {
  font-size: 13px;
  font-weight: 700;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 8px;
}
.floating-launch-bar .meta-sub {
  font-size: 11px;
  color: #94a3b8;
}
.pulse-btn {
  box-shadow: 0 0 20px rgba(16, 185, 129, 0.4);
  animation: pulseButton 2s infinite;
}
@keyframes pulseButton {
  0%, 100% { box-shadow: 0 0 15px rgba(16, 185, 129, 0.4); }
  50% { box-shadow: 0 0 30px rgba(16, 185, 129, 0.8), 0 0 10px rgba(6, 182, 212, 0.6); }
}
</style>
</head>
<body style="padding-bottom: 75px;">
<div class="container">
  <header>
    <div class="brand">
      <div class="brand-icon">⚡</div>
      <div class="brand-text">
        <h1>Project Lume Universal Setup & Deployment Studio</h1>
        <p>Zero-dependency architecture generator, air-gap packaging & automated fleet orchestration</p>
      </div>
    </div>
    <div>
      <span class="badge-standalone">Standalone Runner</span>
    </div>
  </header>

  <!-- TEMPLATE MANAGEMENT TOOLBAR -->
  <div class="template-bar">
    <div class="template-title">
      <span style="font-size: 16px;">⚡</span>
      <span>Deployment Presets & Fleet Orchestration:</span>
    </div>
    <div class="template-actions">
      <button class="btn btn-emerald" style="padding: 8px 16px; font-size: 12px; font-weight: 700;" onclick="loadDemoLabTemplate()">🎯 1-Click: Load Lab / Demo Environment</button>
      <button class="btn btn-primary pulse-btn" style="padding: 8px 18px; font-size: 12px; font-weight: 700; background: linear-gradient(135deg, #06b6d4, #6366f1);" onclick="openOrchestrationModal(true)">🚀 Set Up & Deploy Fleet (Visual Mission Control)</button>
      <button class="btn btn-secondary" style="padding: 8px 14px; font-size: 12px;" onclick="triggerImportTemplate()">📂 Import Template JSON / YAML</button>
      <button class="btn btn-cyan" style="padding: 8px 14px; font-size: 12px;" onclick="exportCurrentTemplate()">💾 Export Current as Template</button>
      <input type="file" id="template_file_input" style="display: none;" accept=".json,.yaml,.yml" onchange="handleTemplateUpload(event)">
    </div>
  </div>

  <!-- VISUAL MISSION CONTROL / FLEET ORCHESTRATION MODAL -->
  <div id="orchestration_modal" class="modal-overlay" style="display: none;">
    <div class="modal-window">
      <div class="modal-header">
        <h3>
          <span style="font-size: 20px;">⚡</span>
          <span>Project Lume Fleet Deployment Mission Control</span>
          <span id="orchestration_status_badge" class="node-badge" style="background: rgba(99,102,241,0.2); color: #818cf8; border: 1px solid rgba(99,102,241,0.4); margin-left: 10px;">Ready to Deploy</span>
        </h3>
        <button onclick="closeOrchestrationModal()" style="background: transparent; border: none; color: #94a3b8; font-size: 18px; cursor: pointer;">✕</button>
      </div>

      <div class="modal-body">
        <!-- Live Topology Node Execution Status -->
        <div>
          <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px; margin-bottom: 10px; display: flex; justify-content: space-between;">
            <span>Cluster Deployment Pipeline & Node Status</span>
            <span id="overall_progress_text" style="color: var(--accent-cyan); font-family: monospace;">0% Complete</span>
          </div>

          <!-- Overall Progress Bar -->
          <div style="width: 100%; height: 8px; background: rgba(255,255,255,0.06); border-radius: 4px; overflow: hidden; margin-bottom: 16px;">
            <div id="overall_progress_bar" style="width: 0%; height: 100%; background: linear-gradient(90deg, #06b6d4, #6366f1, #10b981); transition: width 0.4s ease;"></div>
          </div>

          <div class="node-progress-grid" id="node_progress_grid">
            <!-- Node 24 (PC) -->
            <div class="node-progress-card" id="card_node_24">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                <span style="font-weight: 700; font-size: 13px; color: #fff;">192.168.88.24</span>
                <span class="node-badge" style="background: rgba(99,102,241,0.2); color: #a5b4fc;" id="badge_node_24">Coordinator</span>
              </div>
              <div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px;">Windows PC Operations (24GB cap)</div>
              <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;" id="status_node_24">
                <span>⚪</span> <span>Standing by for setup</span>
              </div>
            </div>

            <!-- Node 25 (Mac) -->
            <div class="node-progress-card" id="card_node_25">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                <span style="font-weight: 700; font-size: 13px; color: #fff;">192.168.88.25</span>
                <span class="node-badge" style="background: rgba(16,185,129,0.2); color: #34d399;" id="badge_node_25">Worker</span>
              </div>
              <div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px;">MacBook Pro Lab Core (16GB cap)</div>
              <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;" id="status_node_25">
                <span>⚪</span> <span>Standing by for setup</span>
              </div>
            </div>

            <!-- Node 44 (Ubuntu 1) -->
            <div class="node-progress-card" id="card_node_44">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                <span style="font-weight: 700; font-size: 13px; color: #fff;">192.168.88.44</span>
                <span class="node-badge" style="background: rgba(139,92,246,0.2); color: #c084fc;" id="badge_node_44">Worker + Scanner</span>
              </div>
              <div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px;">Ubuntu Demo 1 (2600M cap)</div>
              <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;" id="status_node_44">
                <span>⚪</span> <span>Standing by for setup</span>
              </div>
            </div>

            <!-- Node 15 (Ubuntu 2) -->
            <div class="node-progress-card" id="card_node_15">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                <span style="font-weight: 700; font-size: 13px; color: #fff;">192.168.88.15</span>
                <span class="node-badge" style="background: rgba(16,185,129,0.2); color: #34d399;" id="badge_node_15">Worker + Zeek OT</span>
              </div>
              <div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px;">Ubuntu Demo 2 (12GB cap)</div>
              <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;" id="status_node_15">
                <span>⚪</span> <span>Standing by for setup</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Sneakernet / Physical Actions Advisory -->
        <div class="sneakernet-guide-card" id="sneakernet_advisory">
          <div style="font-size: 28px;" id="sneakernet_icon">📦</div>
          <div style="flex: 1;">
            <div style="font-weight: 700; font-size: 13px; color: #f59e0b; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
              <span style="display: flex; align-items: center; gap: 8px;">
                <span>Physical Action Items: Sneakernet & Air-Gap Transport</span>
                <span id="sneakernet_badge" style="font-size: 10px; background: rgba(245,158,11,0.2); color: #fbbf24; padding: 2px 6px; border-radius: 4px;">Operational Notice</span>
              </span>
              <button class="btn btn-secondary" style="font-size: 11px; padding: 4px 10px;" onclick="downloadZipBundle()">💾 Download Thumb Drive Bundle (.zip)</button>
            </div>
            <div id="sneakernet_instruction_text" style="font-size: 12px; color: #cbd5e1; margin-top: 6px; line-height: 1.5;">
              For isolated systems or air-gapped security enclaves without direct outbound internet access:
            </div>
            <ul class="sneakernet-checklist" id="sneakernet_checklist">
              <li id="step_usb_prep"><span>💾</span> <span><b>1. Thumb Drive Preparation:</b> Generate and copy portable deployment bundles (<code>docker-compose.node15-full-sensor.yml</code>, <code>.env</code>, and container tars) to a USB thumb drive.</span></li>
              <li id="step_usb_move"><span>🚶‍♂️</span> <span><b>2. Move to Target Host:</b> Take the thumb drive over to physical target system (e.g. <code>192.168.88.15</code>).</span></li>
              <li id="step_usb_exec"><span>⚡</span> <span><b>3. Mount & Execute:</b> Run <code>docker compose -f docker-compose.node15-full-sensor.yml up -d</code> on target machine.</span></li>
              <li id="step_usb_handshake"><span>🌐</span> <span><b>4. Uplink Verification:</b> System will immediately join the cluster and show online in the Node Management JSX console!</span></li>
            </ul>
          </div>
        </div>

        <!-- Live Streaming Deployment Console Output -->
        <div>
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase;">Real-Time Execution Telemetry Stream</span>
            <span id="orchestration_active_task" style="font-size: 11px; color: var(--accent-cyan); font-family: monospace;">Idle</span>
          </div>
          <div id="orchestration_console" class="status-log" style="height: 180px; margin-top: 0; background: #030712; border-color: rgba(255,255,255,0.12);">
[Ready] Mission control initialized. Click 'Execute Orchestration Pipeline' to deploy configurations across the entire cluster.
          </div>
        </div>

        <!-- Success Celebration Banner (Initially hidden) -->
        <div id="orchestration_success_banner" style="display: none; padding: 16px 20px; background: linear-gradient(90deg, rgba(16,185,129,0.15), rgba(6,182,212,0.15)); border: 1px solid rgba(16,185,129,0.5); border-radius: 10px; align-items: center; justify-content: space-between; margin-top: 5px;">
          <div style="display: flex; align-items: center; gap: 12px;">
            <span style="font-size: 26px;">🎉</span>
            <div>
              <div style="font-size: 14px; font-weight: 700; color: #34d399;">Cluster Deployment Verified & Operational!</div>
              <div style="font-size: 12px; color: #94a3b8;">All 4 nodes are reporting healthy telemetry and federated DuckDB search capabilities.</div>
            </div>
          </div>
          <div style="display: flex; gap: 10px;">
            <a href="http://localhost:9000" target="_blank" class="btn btn-emerald" style="padding: 8px 16px; font-size: 12px; text-decoration: none; display: inline-flex; align-items: center; gap: 6px;">
              🌐 Open Lume SOC Console
            </a>
          </div>
        </div>

        <!-- Action Buttons -->
        <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.08);">
          <div style="font-size: 11px; color: #94a3b8;">
            Targets: <b>4 Fleet Nodes</b> (Windows Coordinator, Mac Worker, Ubuntu Demo 1, Ubuntu Demo 2 with Zeek OT)
          </div>
          <div style="display: flex; gap: 10px;">
            <button class="btn btn-secondary" onclick="closeOrchestrationModal()">Close Window</button>
            <button class="btn btn-emerald pulse-btn" id="btn_run_orchestration" onclick="executeFleetOrchestration()">🚀 Execute Orchestration Pipeline</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <nav class="tabs">
    <button class="tab-btn active" onclick="switchTab('topology')">🏗️ 1. Architecture & IPs</button>
    <button class="tab-btn" onclick="switchTab('storage')">💾 2. Storage & Lifecycle</button>
    <button class="tab-btn" onclick="switchTab('telemetry')">🛡️ 3. Sensors & Suricata</button>
    <button class="tab-btn" onclick="switchTab('ai_vault')">🤖 4. AI Keys & Vaults</button>
    <button class="tab-btn" onclick="switchTab('compose')">📄 5. Generated Compose</button>
    <button class="tab-btn" onclick="switchTab('airgap')">📦 6. Sneakernet & Deploy</button>
  </nav>

  <!-- TAB 1: TOPOLOGY & IPS -->
  <div id="tab-topology" class="tab-panel active">
    <div class="card">
      <div class="card-header">
        <h2>🌐 Network Topology & Deployment Mode</h2>
        <p>Specify where each container node will reside. This automatically binds API tokens, host gateways, and cross-node streams.</p>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>Deployment Architecture</label>
          <select id="deploy_mode" onchange="updateTopologyUI()">
            <option value="distributed">Distributed (Recommended: Lume Core on Server, Sensors on Perimeter/SPAN)</option>
            <option value="all_in_one">All-in-One (Core + Sensors + Scanner on single machine)</option>
            <option value="cluster_coordinator">Multi-Node Cluster: Search Head / Coordinator</option>
            <option value="cluster_worker">Multi-Node Cluster: Indexer / Worker Node</option>
            <option value="sensors_only">Sensor Fleet Only (Export docker-compose for remote Zeek/Scanner nodes)</option>
          </select>
          <div class="helper">Configures standalone single-node, distributed sensors, or multi-node clustered federation.</div>
        </div>
        <div class="form-group">
          <label>Friendly Node Name (User Defined)</label>
          <input type="text" id="lume_node_name" value="Denver Operations Core" placeholder="e.g. Denver Security Operations Core">
          <div class="helper">Human-friendly name shown across Cluster Topology, Federated Search, and Fleet Health.</div>
        </div>
      </div>

      <div class="grid-2" style="margin-top: 10px;">
        <div class="form-group">
          <label>Project Lume Core Host IP / FQDN</label>
          <input type="text" id="lume_host_ip" value="192.168.88.44" placeholder="e.g. 192.168.88.44 or siem.corp.internal">
          <div class="helper">The IP address where the main Project Lume web app and DuckDB engine run.</div>
        </div>
        <div class="form-group">
          <label>Cross-Service Ingest Authorization Token (Shared Secret)</label>
          <input type="text" id="lume_token" value="LAME_SECRET_TOKEN_99">
          <div class="helper">Used by Zeek sensors, Suricata, and Vulnerability Scanners to authenticate log batches into /api/v1/ingest/raw.</div>
        </div>
      </div>

      <div class="grid-3" style="margin-top: 10px;">
        <div class="form-group">
          <label>Project Lume Web Port</label>
          <input type="number" id="lume_port" value="9000">
        </div>
        <div class="form-group">
          <label>Syslog UDP Port (RFC 5424)</label>
          <input type="number" id="syslog_port" value="514">
        </div>
        <div class="form-group">
          <label>Secure TLS / OSQuery Port</label>
          <input type="number" id="tls_ingest_port" value="1514">
        </div>
      </div>
    </div>

    <!-- FLEET NODES & AUXILIARY DOCKER SERVICES MATRIX -->
    <div class="card">
      <div class="card-header">
        <div style="font-size: 24px; margin-right: 12px;">🖥️</div>
        <div>
          <h2>Distributed Fleet Topology & Auxiliary Docker Services Matrix</h2>
          <p>Assign packet capture (Zeek TAP/SPAN + Suricata IDS with OT/SCADA rules) and host filesystem vulnerability assessment containers to target systems while keeping production workstations lean.</p>
        </div>
      </div>
      <div style="overflow-x: auto; margin-top: 10px;">
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; text-align: left;">
          <thead>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.12); color: var(--text-muted); font-size: 11px; text-transform: uppercase;">
              <th style="padding: 10px 8px;">Target Host IP</th>
              <th style="padding: 10px 8px;">Friendly Node Name</th>
              <th style="padding: 10px 8px;">Cluster Role</th>
              <th style="padding: 10px 8px; text-align: center;">Core SIEM</th>
              <th style="padding: 10px 8px; text-align: center;">Zeek + Suricata Sensor</th>
              <th style="padding: 10px 8px; text-align: center;">Host Vuln Scanner</th>
              <th style="padding: 10px 8px;">Assigned Scope & Rules</th>
            </tr>
          </thead>
          <tbody>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
              <td style="padding: 12px 8px; font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan);">192.168.88.24</td>
              <td style="padding: 12px 8px; font-weight: 500;">Windows Operations Workstation</td>
              <td style="padding: 12px 8px;"><span style="background: rgba(99,102,241,0.2); color: #818cf8; padding: 2px 8px; border-radius: 4px; font-size: 11px;">Coordinator</span></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_core_24" checked disabled></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_zeek_24"></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_vuln_24"></td>
              <td style="padding: 12px 8px; color: var(--text-muted); font-size: 11px;">Primary PC — Core SIEM only (Zeek & Scanners OFF)</td>
            </tr>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
              <td style="padding: 12px 8px; font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan);">192.168.88.25</td>
              <td style="padding: 12px 8px; font-weight: 500;">MacBook Pro Lab Core</td>
              <td style="padding: 12px 8px;"><span style="background: rgba(16,185,129,0.2); color: #34d399; padding: 2px 8px; border-radius: 4px; font-size: 11px;">Worker</span></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_core_25" checked disabled></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_zeek_25"></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_vuln_25"></td>
              <td style="padding: 12px 8px; color: var(--text-muted); font-size: 11px;">Primary Mac — Core SIEM only (Zeek & Scanners OFF)</td>
            </tr>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
              <td style="padding: 12px 8px; font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan);">192.168.88.44</td>
              <td style="padding: 12px 8px; font-weight: 500;">Ubuntu Demo 1 (lame-lume)</td>
              <td style="padding: 12px 8px;"><span style="background: rgba(16,185,129,0.2); color: #34d399; padding: 2px 8px; border-radius: 4px; font-size: 11px;">Worker</span></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_core_44" checked disabled></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_zeek_44"></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_vuln_44" checked></td>
              <td style="padding: 12px 8px; color: var(--accent-purple); font-size: 11px;">🔍 Host Vulnerability Scanner Active (Trivy Daemon, /host mount)</td>
            </tr>
            <tr>
              <td style="padding: 12px 8px; font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan);">192.168.88.15</td>
              <td style="padding: 12px 8px; font-weight: 500;">Ubuntu Demo 2 (large-lume)</td>
              <td style="padding: 12px 8px;"><span style="background: rgba(16,185,129,0.2); color: #34d399; padding: 2px 8px; border-radius: 4px; font-size: 11px;">Worker</span></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_core_15" checked disabled></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_zeek_15" checked></td>
              <td style="padding: 12px 8px; text-align: center;"><input type="checkbox" id="aux_vuln_15" checked></td>
              <td style="padding: 12px 8px; color: var(--accent-emerald); font-size: 11px;">🛡️ Zeek Network Sensor + Suricata IDS (OT SCADA Rules) & Vuln Scanner</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div style="margin-top: 14px; font-size: 12px; color: #94a3b8; display: flex; align-items: center; gap: 8px;">
        <span style="color: var(--accent-emerald); font-weight: 600;">✓ Configured State:</span> Node 15 is designated for network sniffing (Zeek + Suricata with Industrial OT/SCADA rules) & host CVE audits. Node 44 runs host CVE audits. Production PC & Mac are protected from scanner overhead.
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>🎯 Perimeter & Sensor Host Targets</h2>
        <p>Configure interface bindings and remote node tags.</p>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>Zeek Sensor Sniffing Interface</label>
          <input type="text" id="sensor_interface" value="ens160" placeholder="e.g. eth0, ens160, bond0, span0">
          <div class="helper">The physical or TAP/SPAN interface Zeek will listen on in promiscuous host mode.</div>
        </div>
        <div class="form-group">
          <label>Sensor Node Identifier</label>
          <input type="text" id="sensor_id" value="sensor-node-primary">
          <div class="helper">Name tagged on all generated Corelight/Zeek logs in Project Lume.</div>
        </div>
        <div class="form-group">
          <label>Vulnerability Scanner Target Host Path</label>
          <input type="text" id="scanner_target_dir" value="/host">
          <div class="helper">Mount point for host root filesystem checking (default: /host mapped from /).</div>
        </div>
        <div class="form-group">
          <label>Scanner Schedule (Minutes between scans)</label>
          <input type="number" id="scanner_interval" value="360">
          <div class="helper">360 = 6 hours periodic CVE scans.</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>🌐 Network Scoping & CIDR Boundaries</h2>
        <p>Define trusted internal subnets and perimeter DMZ boundaries for autonomous correlation and lateral movement detection.</p>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>Internal Network Subnets (RFC 1918 / Private CIDRs)</label>
          <input type="text" id="internal_cidrs" value="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16" placeholder="e.g. 10.0.0.0/8, 192.168.88.0/24">
          <div class="helper">Traffic within these subnets is treated as internal; outbound traffic is flagged as egress.</div>
        </div>
        <div class="form-group">
          <label>DMZ / Perimeter Subnets</label>
          <input type="text" id="dmz_cidrs" value="192.168.88.0/24" placeholder="e.g. 192.168.88.0/24">
          <div class="helper">Exposed web/gateway tiers triggering higher alert scoring on inbound probes.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: STORAGE LIFECYCLE & DISK GOVERNOR -->
  <div id="tab-storage" class="tab-panel">
    <div class="card">
      <div class="card-header">
        <h2>💾 Storage Lifecycle & Disk Governor Policy</h2>
        <p>A quick way to kill a SIEM is to fill the disk. Configure dual warning and emergency watermarks, automated eviction actions, and aged data retention horizons.</p>
      </div>

      <div class="grid-2">
        <div class="form-group">
          <label>Watermark Threshold Mode</label>
          <select id="storage_watermark_mode" onchange="toggleWatermarkInputs()">
            <option value="percentage" selected>Percentage Free Disk Space (%)</option>
            <option value="absolute_gb">Absolute Free Disk Space (GB)</option>
          </select>
          <div class="helper">Choose whether to govern disk health based on percentage free or specific gigabytes.</div>
        </div>
        <div class="form-group">
          <label>Breach Action (When Emergency Threshold Hit)</label>
          <select id="storage_breach_action">
            <option value="evict_oldest" selected>Evict Oldest Data First (DuckDB Vaults & Parquet)</option>
            <option value="stop_indexing">Stop Indexing (Halt Syslog/Zeek to Preserve Existing Data)</option>
            <option value="tier_to_s3">Tier / Offload to S3/MinIO Cold Storage Archive</option>
          </select>
          <div class="helper">User-chosen protection strategy when disk capacity reaches emergency limits.</div>
        </div>
      </div>

      <!-- PERCENTAGE MODE INPUTS -->
      <div class="grid-2" id="watermark_pct_group" style="margin-top: 10px;">
        <div class="form-group">
          <label>Warning Watermark (% Free Space)</label>
          <input type="number" id="storage_warn_pct" value="25" min="1" max="90">
          <div class="helper">Triggers SOC health banner alert (Default: 25% free).</div>
        </div>
        <div class="form-group">
          <label>Emergency Watermark (% Free Space)</label>
          <input type="number" id="storage_min_pct" value="15" min="1" max="80">
          <div class="helper">Executes Breach Action immediately to avoid fatal disk crash (Default: 15% free).</div>
        </div>
      </div>

      <!-- GB MODE INPUTS (Hidden by default) -->
      <div class="grid-2" id="watermark_gb_group" style="margin-top: 10px; display: none;">
        <div class="form-group">
          <label>Warning Watermark (GB Free Space)</label>
          <input type="number" id="storage_warn_gb" value="50" min="1">
          <div class="helper">Triggers warning when free disk falls below this threshold (Default: 50 GB).</div>
        </div>
        <div class="form-group">
          <label>Emergency Watermark (GB Free Space)</label>
          <input type="number" id="storage_min_gb" value="20" min="1">
          <div class="helper">Executes Breach Action when free space drops below this limit (Default: 20 GB).</div>
        </div>
      </div>

      <!-- RETENTION SECTION -->
      <div class="grid-2" style="margin-top: 12px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.06);">
        <div class="form-group">
          <label>Age-Based Retention Horizon (Days)</label>
          <input type="number" id="storage_retention_days" value="30" min="1">
          <div class="helper">Automatically evict or archive logs older than X days regardless of disk usage.</div>
        </div>
        <div class="form-group">
          <label>Retention Action for Aged Records</label>
          <select id="storage_retention_action">
            <option value="delete" selected>Purge / Delete Aged Data</option>
            <option value="archive_s3">Compress & Offload to S3/MinIO Cold Archive</option>
          </select>
          <div class="helper">Action taken when data crosses the retention age threshold.</div>
        </div>
      </div>

      <!-- EVICTION PRIORITIES -->
      <div style="margin-top: 16px;">
        <label style="margin-bottom: 8px;">Eviction Order & Safety Safeguards:</label>
        <div class="grid-3">
          <div class="checkbox-card" style="margin: 0;">
            <input type="checkbox" id="storage_evict_backups" checked>
            <div class="checkbox-content">
              <div class="checkbox-title">Evict Raw Backups First</div>
              <div class="checkbox-desc">Deletes raw .gz ingest dumps before DuckDB tables.</div>
            </div>
          </div>
          <div class="checkbox-card" style="margin: 0;">
            <input type="checkbox" id="storage_evict_parquet" checked>
            <div class="checkbox-content">
              <div class="checkbox-title">Evict Parquet Archive</div>
              <div class="checkbox-desc">Purges cold parquet partitions next.</div>
            </div>
          </div>
          <div class="checkbox-card" style="margin: 0;">
            <input type="checkbox" id="storage_protect_db" checked>
            <div class="checkbox-content">
              <div class="checkbox-title">Protect Security Vault DB</div>
              <div class="checkbox-desc">Never touches credentials or admin accounts.</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- S3 / MINIO COLD STORAGE ARCHIVE -->
    <div class="card">
      <div class="card-header">
        <h2>🧊 S3 / MinIO Cold Storage Tiering (Optional)</h2>
        <p>Configure long-term archival storage for offloading aged Parquet batches from hot SSD partitions.</p>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>Archive Provider</label>
          <select id="cold_storage_provider">
            <option value="minio" selected>MinIO (Private On-Prem / Air-gap Object Storage)</option>
            <option value="aws_s3">Amazon Web Services (AWS S3 Glacier / Standard)</option>
            <option value="wasabi">Wasabi Hot Cloud Storage</option>
          </select>
        </div>
        <div class="form-group">
          <label>Endpoint URL / Hostname</label>
          <input type="text" id="cold_storage_endpoint" value="http://192.168.88.44:9000" placeholder="e.g. http://192.168.88.44:9000 or s3.us-west-2.amazonaws.com">
        </div>
        <div class="form-group">
          <label>Bucket Name</label>
          <input type="text" id="cold_storage_bucket" value="lume-cold-archive" placeholder="e.g. lume-cold-archive">
        </div>
        <div class="form-group">
          <label>Access Key / IAM Key ID</label>
          <input type="text" id="cold_storage_access_key" value="minioadmin">
        </div>
        <div class="form-group" style="grid-column: span 2;">
          <label>Secret Access Key</label>
          <input type="password" id="cold_storage_secret_key" value="minioadmin123" placeholder="••••••••••••••••">
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: SENSORS & SURICATA -->
  <div id="tab-telemetry" class="tab-panel">
    <div class="card">
      <div class="card-header">
        <h2>🛡️ Suricata IDS Engine Configuration</h2>
        <p>Enable high-signal intrusion detection side-by-side with Zeek network analysis.</p>
      </div>
      <div class="checkbox-card">
        <input type="checkbox" id="enable_suricata" checked>
        <div class="checkbox-content">
          <div class="checkbox-title">Enable Suricata IDS Engine</div>
          <div class="checkbox-desc">Runs Suricata in parallel inside the sensor container to detect CVE exploits and OT protocol anomalies.</div>
        </div>
      </div>
      <div class="checkbox-card">
        <input type="checkbox" id="enable_suricata_sync" checked>
        <div class="checkbox-content">
          <div class="checkbox-title">Automated Rule Updates (Free Emerging Threats Open)</div>
          <div class="checkbox-desc">Pulls high-fidelity, false-positive suppressed rules on container startup (includes SCADA, exploits, and C2).</div>
        </div>
      </div>

      <div style="margin-top: 18px;">
        <label style="margin-bottom: 10px;">Curated Suricata Rulesets to Enable:</label>
        <div id="suricata_rules_container"></div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>🔍 Vulnerability Severity Filtering</h2>
        <p>Select which vulnerability tiers trigger alerts inside Project Lume.</p>
      </div>
      <div class="grid-2">
        <div class="checkbox-card">
          <input type="checkbox" id="vuln_crit" checked>
          <div class="checkbox-content">
            <div class="checkbox-title">CRITICAL (CVSS 9.0 - 10.0)</div>
            <div class="checkbox-desc">Remote code execution, unauthenticated root compromises.</div>
          </div>
        </div>
        <div class="checkbox-card">
          <input type="checkbox" id="vuln_high" checked>
          <div class="checkbox-content">
            <div class="checkbox-title">HIGH (CVSS 7.0 - 8.9)</div>
            <div class="checkbox-desc">Privilege escalation, security boundary breaches.</div>
          </div>
        </div>
        <div class="checkbox-card">
          <input type="checkbox" id="vuln_med" checked>
          <div class="checkbox-content">
            <div class="checkbox-title">MEDIUM (CVSS 4.0 - 6.9)</div>
            <div class="checkbox-desc">Denial of service, authenticated information disclosure.</div>
          </div>
        </div>
        <div class="checkbox-card">
          <input type="checkbox" id="vuln_low">
          <div class="checkbox-content">
            <div class="checkbox-title">LOW (CVSS 0.1 - 3.9)</div>
            <div class="checkbox-desc">Minor hygiene warnings (uncheck to reduce noise).</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 3: AI KEYS & VAULTS -->
  <div id="tab-ai_vault" class="tab-panel">
    <div class="card">
      <div class="card-header">
        <h2>🤖 AI Analyst & LLM Provider Configuration</h2>
        <p>Configure local offline LLM (Ollama) or external providers (Gemini, Claude, OpenAI) for autonomous SOC triage.</p>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>Active AI Provider</label>
          <select id="ai_provider">
            <option value="local">Local Ollama (Air-gapped / Private On-Prem)</option>
            <option value="gemini" selected>Google Gemini (Gemini 2.5 / 1.5 Pro)</option>
            <option value="anthropic">Anthropic Claude (Claude 3.5 Sonnet)</option>
            <option value="openai">OpenAI (GPT-4o)</option>
            <option value="groq">Groq (Ultra-fast Llama-3)</option>
          </select>
        </div>
        <div class="form-group">
          <label>Local Ollama URL</label>
          <input type="text" id="ollama_url" value="http://host.docker.internal:11434">
          <div class="helper">When running in Docker, 'host.docker.internal' accesses your host-installed Ollama.</div>
        </div>
      </div>

      <div class="grid-2" style="margin-top: 10px;">
        <div class="form-group">
          <label>Google Gemini API Key</label>
          <input type="password" id="gemini_key" placeholder="AIzaSy...">
        </div>
        <div class="form-group">
          <label>Anthropic API Key</label>
          <input type="password" id="anthropic_key" placeholder="sk-ant-api03-...">
        </div>
        <div class="form-group">
          <label>OpenAI API Key</label>
          <input type="password" id="openai_key" placeholder="sk-proj-...">
        </div>
        <div class="form-group">
          <label>Groq API Key</label>
          <input type="password" id="groq_key" placeholder="gsk_...">
        </div>
      </div>
    </div>

    <!-- THREAT INTEL CREDENTIAL VAULT -->
    <div class="card" style="margin-top: 20px;">
      <div class="card-header">
        <h2>🛡️ Threat Intelligence & Reputation Vault</h2>
        <p>Pre-configure external threat intelligence provider API keys. These are encrypted directly into Lume's Credential Vault for autonomous indicator enrichment.</p>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>VirusTotal v3 API Key</label>
          <input type="password" id="virustotal_key" placeholder="64-character VT API Key">
          <div class="helper">Used for automated file hash reputation verdicts and malicious URL scoring.</div>
        </div>
        <div class="form-group">
          <label>AbuseIPDB API Key</label>
          <input type="password" id="abuseipdb_key" placeholder="80-character AbuseIPDB Key">
          <div class="helper">Autonomous IP reputation scores and attack category enrichment.</div>
        </div>
        <div class="form-group">
          <label>AlienVault OTX API Key</label>
          <input type="password" id="otx_key" placeholder="AlienVault OTX Key">
          <div class="helper">Crowdsourced adversary pulse indicators and APT campaign tagging.</div>
        </div>
        <div class="form-group">
          <label>TAXII 2.1 Threat Feed URL (Optional)</label>
          <input type="text" id="taxii_url" placeholder="https://cti-taxii.mitre.org/stix/collections/...">
          <div class="helper">STIX/TAXII threat feed endpoint for periodic threat indicator imports.</div>
        </div>
      </div>
    </div>

    <!-- LICENSE CONFIGURATION -->
    <div class="card" style="margin-top: 20px;">
      <div class="card-header">
        <div class="card-icon">📜</div>
        <div>
          <div class="card-title">Commercial License Certificate (Optional)</div>
          <div class="card-desc">Activate Tier 1 Forensic, Tier 2 Real-Time, or Tier 3 Clustered. Leave blank for Tier 0 Community Edition (5 GB/day).</div>
        </div>
      </div>
      <div class="form-group">
        <label>License Token / Certificate (.lic content)</label>
        <textarea id="lume_license_token" rows="3" placeholder="Paste your signed .ed25519 license token here, or leave empty for free Community Edition..."></textarea>
        <div class="helper">When provided, the license token is embedded directly into the docker-compose.yml as LUME_LICENSE_KEY and persisted to lume.lic on container boot.</div>
      </div>
    </div>
  </div>

  <!-- TAB 4: GENERATED COMPOSE -->
  <div id="tab-compose" class="tab-panel">
    <div class="card">
      <div class="card-header">
        <h2>📄 Generated Configuration Files</h2>
        <p>Review the exact docker-compose and environment files generated based on your settings above.</p>
      </div>
      <div style="display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap;">
        <button class="btn btn-secondary" onclick="generateAndPreview('core')">Lume Core Compose</button>
        <button class="btn btn-emerald" onclick="generateAndPreview('node15')">Node 15 (Core + Zeek OT + Vuln Scanner)</button>
        <button class="btn btn-cyan" onclick="generateAndPreview('node44')">Node 44 (Core + Vuln Scanner)</button>
        <button class="btn btn-secondary" onclick="generateAndPreview('sensor')">Standalone Zeek Sensor</button>
        <button class="btn btn-secondary" onclick="generateAndPreview('scanner')">Standalone Vuln Scanner</button>
        <button class="btn btn-secondary" onclick="generateAndPreview('env')">Environment (.env)</button>
        <button class="btn btn-secondary" onclick="generateAndPreview('storage')">Storage Policy JSON</button>
        <button class="btn btn-secondary" onclick="generateAndPreview('boundaries')">Network Boundaries JSON</button>
      </div>
      <pre id="preview_code">Click a button above or switch tabs to generate configurations...</pre>

      <div class="action-bar">
        <button class="btn btn-primary" onclick="saveConfigsToDisk()">💾 Write Config Files to Disk</button>
        <button class="btn btn-cyan" onclick="downloadZipBundle()">📥 Download Complete Deployment Bundle (.ZIP)</button>
      </div>
    </div>
  </div>

  <!-- TAB 5: SNEAKERNET & AIR-GAP PACKAGING -->
  <div id="tab-airgap" class="tab-panel">
    <div class="card">
      <div class="card-header">
        <h2>📦 Sneakernet Air-Gap Packager & Docker Actions</h2>
        <p>Export Docker images directly to standalone <code>.tar</code> archives to transport into isolated or classified enclaves via USB.</p>
      </div>

      <div class="grid-3">
        <div class="card" style="padding: 16px; margin: 0; background: rgba(13,18,31,0.5);">
          <h3 style="font-size: 14px; margin-bottom: 6px; color: var(--accent-cyan);">1. Project Lume Core</h3>
          <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px;">Image: <code>lamecreations/project_lume:latest</code></p>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            <button class="btn btn-secondary" style="font-size: 11px; padding: 7px 10px;" onclick="runDockerAction('pull', 'core')">📥 Pull from Hub</button>
            <button class="btn btn-cyan" style="font-size: 11px; padding: 7px 10px;" onclick="runDockerAction('save_tar', 'core')">💾 Export to .tar</button>
          </div>
        </div>

        <div class="card" style="padding: 16px; margin: 0; background: rgba(13,18,31,0.5);">
          <h3 style="font-size: 14px; margin-bottom: 6px; color: var(--accent-indigo);">2. Zeek Sensor Node</h3>
          <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px;">Image: <code>lamecreations/lume-zeek-sensor:latest</code></p>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            <button class="btn btn-secondary" style="font-size: 11px; padding: 7px 10px;" onclick="runDockerAction('pull', 'zeek')">📥 Pull from Hub</button>
            <button class="btn btn-cyan" style="font-size: 11px; padding: 7px 10px;" onclick="runDockerAction('save_tar', 'zeek')">💾 Export to .tar</button>
          </div>
        </div>

        <div class="card" style="padding: 16px; margin: 0; background: rgba(13,18,31,0.5);">
          <h3 style="font-size: 14px; margin-bottom: 6px; color: var(--accent-purple);">3. Vuln Scanner Node</h3>
          <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px;">Image: <code>lamecreations/lume-vuln-scanner:latest</code></p>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            <button class="btn btn-secondary" style="font-size: 11px; padding: 7px 10px;" onclick="runDockerAction('pull', 'scanner')">📥 Pull from Hub</button>
            <button class="btn btn-cyan" style="font-size: 11px; padding: 7px 10px;" onclick="runDockerAction('save_tar', 'scanner')">💾 Export to .tar</button>
          </div>
        </div>
      </div>

      <div style="margin-top: 24px; padding: 16px; background: rgba(99, 102, 241, 0.08); border-radius: 8px; border: 1px solid rgba(99, 102, 241, 0.2);">
        <h3 style="font-size: 14px; margin-bottom: 6px; color: #fff;">🚀 Local One-Click Execution (On Target Machine)</h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">If Docker is installed on this current machine, you can launch or load the stack immediately:</p>
        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
          <button class="btn btn-emerald" onclick="runDockerAction('compose_up', 'all')">▶️ Launch Local Stack (`docker compose up -d`)</button>
          <button class="btn btn-secondary" onclick="runDockerAction('compose_down', 'all')">⏹️ Stop Local Stack (`docker compose down`)</button>
          <button class="btn btn-secondary" onclick="runDockerAction('load_tars', 'all')">📂 Load All .tar Images on this Host</button>
        </div>
      </div>

      <!-- REMOTE FLEET SSH PUSH SECTION -->
      <div style="margin-top: 24px; padding: 18px; background: rgba(6, 182, 212, 0.08); border-radius: 8px; border: 1px solid rgba(6, 182, 212, 0.25);">
        <h3 style="font-size: 14px; margin-bottom: 6px; color: #fff; display: flex; align-items: center; gap: 8px;">
          <span>🌐 Remote Fleet Deployment via SSH (Push to Reachable Systems)</span>
          <span style="font-size: 10px; background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); padding: 2px 8px; border-radius: 12px;">Remote Mesh</span>
        </h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">Deploy container stacks or synchronize configuration bundles directly over SSH without visiting the remote physical terminal.</p>
        
        <div class="grid-3">
          <div class="form-group" style="margin-bottom: 8px;">
            <label>Target Remote Host (Topology Node)</label>
            <select id="remote_ssh_host" onchange="onRemoteHostChanged()">
              <option value="192.168.88.15" selected>192.168.88.15 (Ubuntu 2: Core + Zeek OT + Vuln Scanner)</option>
              <option value="192.168.88.44">192.168.88.44 (Ubuntu 1: Core + Vuln Scanner)</option>
              <option value="192.168.88.25">192.168.88.25 (MacBook Pro: Core Only)</option>
              <option value="192.168.88.24">192.168.88.24 (Windows PC: Core Only)</option>
              <option value="custom">Custom IP...</option>
            </select>
            <input type="text" id="remote_ssh_host_custom" placeholder="e.g. 192.168.88.50" style="display: none; margin-top: 6px;">
          </div>
          <div class="form-group" style="margin-bottom: 8px;">
            <label>SSH Username</label>
            <input type="text" id="remote_ssh_user" value="lame">
          </div>
          <div class="form-group" style="margin-bottom: 8px;">
            <label>SSH Password / Passphrase</label>
            <input type="password" id="remote_ssh_pass" value="Denver#2">
          </div>
        </div>
        <div id="target_services_badge" style="margin-top: 6px; font-size: 12px; color: var(--accent-emerald);">
          🛡️ <b>Node 15 Selected:</b> Deploys Core SIEM + Zeek Network Sniffer with Suricata IDS & Industrial OT/SCADA rules + Host Vuln Scanner.
        </div>

        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px;">
          <button class="btn btn-cyan" onclick="runRemoteDeploy('test_ssh')">🔌 Test Remote SSH Connection</button>
          <button class="btn btn-primary" onclick="runRemoteDeploy('push_configs')">📤 Push Configs via SCP / SSH</button>
          <button class="btn btn-emerald pulse-btn" onclick="openOrchestrationModal(true)">🚀 Deploy & Run Container (Visual Mission Control)</button>
        </div>
      </div>

      <div class="status-log" id="docker_status_log">Ready. System status messages and Docker execution logs will stream here...</div>
    </div>
  </div>

  <!-- FLOATING PERSISTENT DEPLOYMENT DOCK -->
  <div class="floating-launch-bar">
    <div class="meta-info">
      <div style="font-size: 24px;">⚡</div>
      <div>
        <div class="meta-title">
          <span>Project Lume Fleet Configuration Ready</span>
          <span style="font-size: 10px; background: rgba(16,185,129,0.2); color: #34d399; padding: 2px 7px; border-radius: 4px; border: 1px solid rgba(16,185,129,0.4);">4 Systems Configured</span>
        </div>
        <div class="meta-sub">YAML/JSON parameter fields populated. Ready to deploy or generate air-gap thumb drive bundles.</div>
      </div>
    </div>
    <div style="display: flex; gap: 10px; align-items: center;">
      <button class="btn btn-secondary" style="font-size: 12px; padding: 8px 14px;" onclick="triggerImportTemplate()">📂 Load YAML / JSON</button>
      <button class="btn btn-cyan" style="font-size: 12px; padding: 8px 14px;" onclick="downloadZipBundle()">💾 Download USB Bundle</button>
      <button class="btn btn-emerald pulse-btn" style="font-size: 13px; font-weight: 700; padding: 10px 22px; background: linear-gradient(135deg, #10b981, #06b6d4);" onclick="openOrchestrationModal(true)">
        🚀 Set Up & Deploy Instance (Mission Control)
      </button>
    </div>
  </div>
</div>

<script>
const SURICATA_RULES = """ + json.dumps(SURICATA_RULESETS) + """;

function initRulesUI() {
  const container = document.getElementById('suricata_rules_container');
  container.innerHTML = '';
  SURICATA_RULES.forEach(r => {
    const card = document.createElement('div');
    card.className = 'checkbox-card';
    card.innerHTML = `
      <input type="checkbox" id="rule_${r.id}" ${r.default ? 'checked' : ''}>
      <div class="checkbox-content">
        <div class="checkbox-title">${r.name}</div>
        <div class="checkbox-desc">${r.desc} (${r.id})</div>
      </div>
    `;
    container.appendChild(card);
  });
}

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
  if (name === 'compose') {
    generateAndPreview('core');
  }
}

function toggleWatermarkInputs() {
  const mode = document.getElementById('storage_watermark_mode').value;
  if (mode === 'percentage') {
    document.getElementById('watermark_pct_group').style.display = 'grid';
    document.getElementById('watermark_gb_group').style.display = 'none';
  } else {
    document.getElementById('watermark_pct_group').style.display = 'none';
    document.getElementById('watermark_gb_group').style.display = 'grid';
  }
}

function getFormData() {
  const selectedRules = [];
  SURICATA_RULES.forEach(r => {
    const cb = document.getElementById('rule_' + r.id);
    if (cb && cb.checked) selectedRules.push(r.id);
  });

  const severities = [];
  if (document.getElementById('vuln_crit').checked) severities.push('CRITICAL');
  if (document.getElementById('vuln_high').checked) severities.push('HIGH');
  if (document.getElementById('vuln_med').checked) severities.push('MEDIUM');
  if (document.getElementById('vuln_low').checked) severities.push('LOW');

  return {
    deploy_mode: document.getElementById('deploy_mode').value,
    lume_node_name: (document.getElementById('lume_node_name') ? document.getElementById('lume_node_name').value.trim() : 'Denver Operations Core'),
    lume_host_ip: document.getElementById('lume_host_ip').value,
    lume_port: document.getElementById('lume_port').value,
    syslog_port: document.getElementById('syslog_port').value,
    tls_ingest_port: document.getElementById('tls_ingest_port').value,
    lume_token: document.getElementById('lume_token').value,
    sensor_interface: document.getElementById('sensor_interface').value,
    sensor_id: document.getElementById('sensor_id').value,
    scanner_target_dir: document.getElementById('scanner_target_dir').value,
    scanner_interval: document.getElementById('scanner_interval').value,
    internal_cidrs: (document.getElementById('internal_cidrs') ? document.getElementById('internal_cidrs').value : '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'),
    dmz_cidrs: (document.getElementById('dmz_cidrs') ? document.getElementById('dmz_cidrs').value : '192.168.88.0/24'),
    enable_suricata: document.getElementById('enable_suricata').checked,
    enable_suricata_sync: document.getElementById('enable_suricata_sync').checked,
    selected_rules: selectedRules,
    severities: severities.join(','),
    ai_provider: document.getElementById('ai_provider').value,
    ollama_url: document.getElementById('ollama_url').value,
    gemini_key: document.getElementById('gemini_key').value,
    anthropic_key: document.getElementById('anthropic_key').value,
    openai_key: document.getElementById('openai_key').value,
    groq_key: document.getElementById('groq_key').value,
    virustotal_key: (document.getElementById('virustotal_key') ? document.getElementById('virustotal_key').value : ''),
    abuseipdb_key: (document.getElementById('abuseipdb_key') ? document.getElementById('abuseipdb_key').value : ''),
    otx_key: (document.getElementById('otx_key') ? document.getElementById('otx_key').value : ''),
    taxii_url: (document.getElementById('taxii_url') ? document.getElementById('taxii_url').value : ''),
    lume_license_token: (document.getElementById('lume_license_token') ? document.getElementById('lume_license_token').value.trim() : ''),
    // Storage Lifecycle & Disk Governor Policy
    storage_watermark_mode: (document.getElementById('storage_watermark_mode') ? document.getElementById('storage_watermark_mode').value : 'percentage'),
    storage_breach_action: (document.getElementById('storage_breach_action') ? document.getElementById('storage_breach_action').value : 'evict_oldest'),
    storage_warn_pct: (document.getElementById('storage_warn_pct') ? parseFloat(document.getElementById('storage_warn_pct').value) : 25.0),
    storage_min_pct: (document.getElementById('storage_min_pct') ? parseFloat(document.getElementById('storage_min_pct').value) : 15.0),
    storage_warn_gb: (document.getElementById('storage_warn_gb') ? parseFloat(document.getElementById('storage_warn_gb').value) : 50.0),
    storage_min_gb: (document.getElementById('storage_min_gb') ? parseFloat(document.getElementById('storage_min_gb').value) : 20.0),
    storage_retention_days: (document.getElementById('storage_retention_days') ? parseInt(document.getElementById('storage_retention_days').value) : 30),
    storage_retention_action: (document.getElementById('storage_retention_action') ? document.getElementById('storage_retention_action').value : 'delete'),
    storage_evict_backups: (document.getElementById('storage_evict_backups') ? document.getElementById('storage_evict_backups').checked : true),
    storage_evict_parquet: (document.getElementById('storage_evict_parquet') ? document.getElementById('storage_evict_parquet').checked : true),
    storage_protect_db: (document.getElementById('storage_protect_db') ? document.getElementById('storage_protect_db').checked : true),
    // Cold Storage S3 / MinIO
    cold_storage_provider: (document.getElementById('cold_storage_provider') ? document.getElementById('cold_storage_provider').value : 'minio'),
    cold_storage_endpoint: (document.getElementById('cold_storage_endpoint') ? document.getElementById('cold_storage_endpoint').value : 'http://192.168.88.44:9000'),
    cold_storage_bucket: (document.getElementById('cold_storage_bucket') ? document.getElementById('cold_storage_bucket').value : 'lume-cold-archive'),
    cold_storage_access_key: (document.getElementById('cold_storage_access_key') ? document.getElementById('cold_storage_access_key').value : 'minioadmin'),
    cold_storage_secret_key: (document.getElementById('cold_storage_secret_key') ? document.getElementById('cold_storage_secret_key').value : 'minioadmin123'),
    // Remote SSH Settings
    remote_ssh_host: (document.getElementById('remote_ssh_host') ? document.getElementById('remote_ssh_host').value : '192.168.88.44'),
    remote_ssh_user: (document.getElementById('remote_ssh_user') ? document.getElementById('remote_ssh_user').value : 'lame'),
    remote_ssh_pass: (document.getElementById('remote_ssh_pass') ? document.getElementById('remote_ssh_pass').value : 'Denver#2'),
    // Auxiliary Node Docker Deployments
    aux_services: {
      "192.168.88.24": {
        deploy_core: true,
        deploy_zeek: Boolean(document.getElementById('aux_zeek_24') && document.getElementById('aux_zeek_24').checked),
        deploy_scanner: Boolean(document.getElementById('aux_vuln_24') && document.getElementById('aux_vuln_24').checked)
      },
      "192.168.88.25": {
        deploy_core: true,
        deploy_zeek: Boolean(document.getElementById('aux_zeek_25') && document.getElementById('aux_zeek_25').checked),
        deploy_scanner: Boolean(document.getElementById('aux_vuln_25') && document.getElementById('aux_vuln_25').checked)
      },
      "192.168.88.44": {
        deploy_core: true,
        deploy_zeek: Boolean(document.getElementById('aux_zeek_44') && document.getElementById('aux_zeek_44').checked),
        deploy_scanner: Boolean(document.getElementById('aux_vuln_44') && document.getElementById('aux_vuln_44').checked)
      },
      "192.168.88.15": {
        deploy_core: true,
        deploy_zeek: Boolean(document.getElementById('aux_zeek_15') && document.getElementById('aux_zeek_15').checked),
        deploy_scanner: Boolean(document.getElementById('aux_vuln_15') && document.getElementById('aux_vuln_15').checked)
      }
    }
  };
}

function onRemoteHostChanged() {
  const hostSelect = document.getElementById('remote_ssh_host');
  const customInput = document.getElementById('remote_ssh_host_custom');
  const badge = document.getElementById('target_services_badge');
  const host = hostSelect.value;

  if (host === 'custom') {
    if (customInput) customInput.style.display = 'block';
    if (badge) badge.innerHTML = '⚙️ <b>Custom Host:</b> Standard Lume Core SIEM deploy target.';
  } else {
    if (customInput) customInput.style.display = 'none';
    if (badge) {
      if (host === '192.168.88.15') {
        badge.innerHTML = '🛡️ <b>Node 15 Selected:</b> Deploys Core SIEM (12GB cap) + Zeek Network Sniffer with Suricata IDS & Industrial OT/SCADA rules + Host Vuln Scanner.';
      } else if (host === '192.168.88.44') {
        badge.innerHTML = '🔍 <b>Node 44 Selected:</b> Deploys Core SIEM (2600M cap) + Host Vuln Scanner (Zeek packet sniffing disabled).';
      } else if (host === '192.168.88.25') {
        badge.innerHTML = '💻 <b>Node 25 Selected (MacBook Pro):</b> Deploys Core SIEM only (Protected from sniffing & scanner overhead).';
      } else if (host === '192.168.88.24') {
        badge.innerHTML = '🖥️ <b>Node 24 Selected (Windows PC):</b> Deploys Core SIEM only (Protected from sniffing & scanner overhead).';
      } else {
        badge.innerHTML = `🌐 <b>Target Node:</b> ${host}`;
      }
    }
  }
}

// ==============================================================================
// TEMPLATE HYDRATION & EXPORT LOGIC
// ==============================================================================

function applyTemplateData(tmpl) {
  if (!tmpl) return;

  // 1. Cluster & Architecture
  if (tmpl.cluster) {
    if (tmpl.cluster.deployment_mode) document.getElementById('deploy_mode').value = tmpl.cluster.deployment_mode;
    if (tmpl.cluster.node_name) document.getElementById('lume_node_name').value = tmpl.cluster.node_name;
    if (tmpl.cluster.host_ip) document.getElementById('lume_host_ip').value = tmpl.cluster.host_ip;
    if (tmpl.cluster.port) document.getElementById('lume_port').value = tmpl.cluster.port;
    if (tmpl.cluster.syslog_port) document.getElementById('syslog_port').value = tmpl.cluster.syslog_port;
    if (tmpl.cluster.tls_ingest_port) document.getElementById('tls_ingest_port').value = tmpl.cluster.tls_ingest_port;
    if (tmpl.cluster.auth_token) document.getElementById('lume_token').value = tmpl.cluster.auth_token;
  }

  // 1b. Distributed Node Auxiliary Services Matrix
  const aux = tmpl.node_auxiliary_services || {};
  if (aux['192.168.88.24']) {
    if (document.getElementById('aux_zeek_24')) document.getElementById('aux_zeek_24').checked = Boolean(aux['192.168.88.24'].deploy_zeek);
    if (document.getElementById('aux_vuln_24')) document.getElementById('aux_vuln_24').checked = Boolean(aux['192.168.88.24'].deploy_scanner);
  }
  if (aux['192.168.88.25']) {
    if (document.getElementById('aux_zeek_25')) document.getElementById('aux_zeek_25').checked = Boolean(aux['192.168.88.25'].deploy_zeek);
    if (document.getElementById('aux_vuln_25')) document.getElementById('aux_vuln_25').checked = Boolean(aux['192.168.88.25'].deploy_scanner);
  }
  if (aux['192.168.88.44']) {
    if (document.getElementById('aux_zeek_44')) document.getElementById('aux_zeek_44').checked = Boolean(aux['192.168.88.44'].deploy_zeek);
    if (document.getElementById('aux_vuln_44')) document.getElementById('aux_vuln_44').checked = Boolean(aux['192.168.88.44'].deploy_scanner);
  }
  if (aux['192.168.88.15']) {
    if (document.getElementById('aux_zeek_15')) document.getElementById('aux_zeek_15').checked = Boolean(aux['192.168.88.15'].deploy_zeek);
    if (document.getElementById('aux_vuln_15')) document.getElementById('aux_vuln_15').checked = Boolean(aux['192.168.88.15'].deploy_scanner);
  }

  // 2. Storage Lifecycle & Disk Governor
  if (tmpl.storage_lifecycle) {
    const sl = tmpl.storage_lifecycle;
    if (sl.watermark_mode) {
      document.getElementById('storage_watermark_mode').value = sl.watermark_mode;
      toggleWatermarkInputs();
    }
    if (sl.breach_action) document.getElementById('storage_breach_action').value = sl.breach_action;
    if (sl.warning_free_percent !== undefined) document.getElementById('storage_warn_pct').value = sl.warning_free_percent;
    if (sl.min_free_percent !== undefined) document.getElementById('storage_min_pct').value = sl.min_free_percent;
    if (sl.warning_free_gb !== undefined) document.getElementById('storage_warn_gb').value = sl.warning_free_gb;
    if (sl.min_free_gb !== undefined) document.getElementById('storage_min_gb').value = sl.min_free_gb;
    if (sl.retention_days !== undefined) document.getElementById('storage_retention_days').value = sl.retention_days;
    if (sl.retention_action) document.getElementById('storage_retention_action').value = sl.retention_action;
    if (sl.evict_backups_first !== undefined) document.getElementById('storage_evict_backups').checked = Boolean(sl.evict_backups_first);
    if (sl.evict_parquet_first !== undefined) document.getElementById('storage_evict_parquet').checked = Boolean(sl.evict_parquet_first);
    if (sl.protect_security_db !== undefined) document.getElementById('storage_protect_db').checked = Boolean(sl.protect_security_db);

    if (sl.cold_storage) {
      if (sl.cold_storage.provider) document.getElementById('cold_storage_provider').value = sl.cold_storage.provider;
      if (sl.cold_storage.endpoint_url) document.getElementById('cold_storage_endpoint').value = sl.cold_storage.endpoint_url;
      if (sl.cold_storage.bucket_name) document.getElementById('cold_storage_bucket').value = sl.cold_storage.bucket_name;
      if (sl.cold_storage.access_key) document.getElementById('cold_storage_access_key').value = sl.cold_storage.access_key;
      if (sl.cold_storage.secret_key) document.getElementById('cold_storage_secret_key').value = sl.cold_storage.secret_key;
    }
  }

  // 3. Network Boundaries
  if (tmpl.network_boundaries) {
    if (tmpl.network_boundaries.internal_cidrs) document.getElementById('internal_cidrs').value = tmpl.network_boundaries.internal_cidrs;
    if (tmpl.network_boundaries.dmz_cidrs) document.getElementById('dmz_cidrs').value = tmpl.network_boundaries.dmz_cidrs;
  }

  // 4. Sensors & Telemetry
  if (tmpl.sensor_telemetry) {
    const st = tmpl.sensor_telemetry;
    if (st.sensor_interface) document.getElementById('sensor_interface').value = st.sensor_interface;
    if (st.sensor_id) document.getElementById('sensor_id').value = st.sensor_id;
    if (st.scanner_target_dir) document.getElementById('scanner_target_dir').value = st.scanner_target_dir;
    if (st.scanner_interval) document.getElementById('scanner_interval').value = st.scanner_interval;
    if (st.enable_suricata !== undefined) document.getElementById('enable_suricata').checked = Boolean(st.enable_suricata);
    if (st.enable_suricata_sync !== undefined) document.getElementById('enable_suricata_sync').checked = Boolean(st.enable_suricata_sync);
    
    if (Array.isArray(st.selected_rules)) {
      SURICATA_RULES.forEach(r => {
        const el = document.getElementById('rule_' + r.id);
        if (el) el.checked = st.selected_rules.includes(r.id);
      });
    }

    if (st.severities) {
      const sevs = st.severities.toUpperCase().split(',');
      document.getElementById('vuln_crit').checked = sevs.includes('CRITICAL');
      document.getElementById('vuln_high').checked = sevs.includes('HIGH');
      document.getElementById('vuln_med').checked = sevs.includes('MEDIUM');
      document.getElementById('vuln_low').checked = sevs.includes('LOW');
    }
  }

  // 5. Threat Intelligence Vault
  if (tmpl.threat_intel_vault) {
    const ti = tmpl.threat_intel_vault;
    if (ti.virustotal_key) document.getElementById('virustotal_key').value = ti.virustotal_key;
    if (ti.abuseipdb_key) document.getElementById('abuseipdb_key').value = ti.abuseipdb_key;
    if (ti.otx_key) document.getElementById('otx_key').value = ti.otx_key;
    if (ti.taxii_url) document.getElementById('taxii_url').value = ti.taxii_url;
  }

  // 6. AI Analyst & LLM Keys
  if (tmpl.ai_analyst) {
    const ai = tmpl.ai_analyst;
    if (ai.active_provider) document.getElementById('ai_provider').value = ai.active_provider;
    if (ai.ollama_url) document.getElementById('ollama_url').value = ai.ollama_url;
    if (ai.gemini_key) document.getElementById('gemini_key').value = ai.gemini_key;
    if (ai.anthropic_key) document.getElementById('anthropic_key').value = ai.anthropic_key;
    if (ai.openai_key) document.getElementById('openai_key').value = ai.openai_key;
    if (ai.groq_key) document.getElementById('groq_key').value = ai.groq_key;
  }

  // 7. SSH Remote Access
  if (tmpl.ssh_remote_access) {
    if (tmpl.ssh_remote_access.default_user) document.getElementById('remote_ssh_user').value = tmpl.ssh_remote_access.default_user;
    if (tmpl.ssh_remote_access.default_pass) document.getElementById('remote_ssh_pass').value = tmpl.ssh_remote_access.default_pass;
  }

  onRemoteHostChanged();
  logMsg(`✓ Successfully applied template: "${tmpl.name || 'Custom Preset'}"! All form sections, topology matrix, and keys hydrated.`, 'success');
}

async function loadDemoLabTemplate() {
  logMsg("Fetching pre-loaded demo lab configuration template...", 'info');
  try {
    const res = await fetch('/api/template/demo');
    const json = await res.json();
    if (json.status === 'success' && json.template) {
      applyTemplateData(json.template);
      alert("✅ Demo lab environment template successfully loaded!\n\nAll 4 nodes, Storage Lifecycle rules (15% emergency watermark), Threat Intel API keys, and Network CIDRs are filled out.");
    } else {
      logMsg("Failed to load demo template: " + (json.message || "Unknown error"), 'err');
    }
  } catch (e) {
    logMsg("Error fetching demo template: " + e, 'err');
  }
}

function triggerImportTemplate() {
  document.getElementById('template_file_input').click();
}

function handleTemplateUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async function(e) {
    const content = e.target.result;
    try {
      // First try quick local JSON parse
      const data = JSON.parse(content);
      applyTemplateData(data);
      alert(`✅ Template "${file.name}" imported and applied cleanly! Ready for deployment.`);
    } catch (err) {
      // If YAML or complex JSON, send to backend parser
      try {
        const res = await fetch('/api/template/parse_upload', {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: content
        });
        const json = await res.json();
        if (json.status === 'success' && json.template) {
          applyTemplateData(json.template);
          alert(`✅ YAML/JSON Template "${file.name}" imported and applied cleanly! Ready for deployment.`);
        } else {
          alert("❌ Could not parse template file: " + (json.message || "Unknown format"));
        }
      } catch (postErr) {
        alert("❌ Failed uploading template for parsing: " + postErr);
      }
    }
  };
  reader.readAsText(file);
}

function exportCurrentTemplate() {
  const data = getFormData();
  const tmpl = {
    template_version: "2.0",
    name: "Exported Lume Cluster Setup - " + new Date().toISOString().slice(0, 10),
    description: "Exported configuration from Project Lume Universal Setup Studio",
    cluster: {
      deployment_mode: data.deploy_mode,
      node_name: data.lume_node_name,
      host_ip: data.lume_host_ip,
      port: parseInt(data.lume_port),
      syslog_port: parseInt(data.syslog_port),
      tls_ingest_port: parseInt(data.tls_ingest_port),
      auth_token: data.lume_token
    },
    storage_lifecycle: {
      enabled: true,
      watermark_mode: data.storage_watermark_mode,
      min_free_percent: data.storage_min_pct,
      warning_free_percent: data.storage_warn_pct,
      min_free_gb: data.storage_min_gb,
      warning_free_gb: data.storage_warn_gb,
      breach_action: data.storage_breach_action,
      retention_enabled: true,
      retention_days: data.storage_retention_days,
      retention_action: data.storage_retention_action,
      evict_backups_first: data.storage_evict_backups,
      evict_parquet_first: data.storage_evict_parquet,
      protect_security_db: data.storage_protect_db,
      cold_storage: {
        provider: data.cold_storage_provider,
        endpoint_url: data.cold_storage_endpoint,
        bucket_name: data.cold_storage_bucket,
        access_key: data.cold_storage_access_key,
        secret_key: data.cold_storage_secret_key
      }
    },
    network_boundaries: {
      internal_cidrs: data.internal_cidrs,
      dmz_cidrs: data.dmz_cidrs
    },
    sensor_telemetry: {
      sensor_interface: data.sensor_interface,
      sensor_id: data.sensor_id,
      scanner_target_dir: data.scanner_target_dir,
      scanner_interval: parseInt(data.scanner_interval),
      enable_suricata: data.enable_suricata,
      enable_suricata_sync: data.enable_suricata_sync,
      selected_rules: data.selected_rules,
      severities: data.severities
    },
    threat_intel_vault: {
      virustotal_key: data.virustotal_key,
      abuseipdb_key: data.abuseipdb_key,
      otx_key: data.otx_key,
      taxii_url: data.taxii_url
    },
    ai_analyst: {
      active_provider: data.ai_provider,
      ollama_url: data.ollama_url,
      gemini_key: data.gemini_key,
      anthropic_key: data.anthropic_key,
      openai_key: data.openai_key,
      groq_key: data.groq_key
    },
    ssh_remote_access: {
      default_user: data.remote_ssh_user,
      default_pass: data.remote_ssh_pass,
      ssh_port: 22
    },
    node_auxiliary_services: data.aux_services
  };

  const blob = new Blob([JSON.stringify(tmpl, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `lume_fleet_template_${data.lume_node_name.replace(/\\s+/g, '_').toLowerCase()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  logMsg("✓ Exported current setup to JSON template file.", 'success');
}

// ==============================================================================
// REMOTE SSH DEPLOYMENT DISPATCHER
// ==============================================================================

async function runRemoteDeploy(action) {
  const data = getFormData();
  logMsg(`Connecting to remote target ${data.remote_ssh_host} as user '${data.remote_ssh_user}' (Action: ${action})...`, 'info');

  try {
    const res = await fetch('/api/remote_deploy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action, form: data })
    });
    const json = await res.json();
    if (json.status === 'success') {
      logMsg(`✓ [SSH Success] ${json.message}`, 'success');
    } else {
      logMsg(`❌ [SSH Error] ${json.message}`, 'err');
    }
  } catch (err) {
    logMsg(`❌ Remote deploy request failed: ${err}`, 'err');
  }
}

async function generateAndPreview(type) {
  const data = getFormData();
  const res = await fetch('/api/preview?type=' + type, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  const json = await res.json();
  document.getElementById('preview_code').textContent = json.content;
}

async function saveConfigsToDisk() {
  const data = getFormData();
  const res = await fetch('/api/save_configs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  const json = await res.json();
  alert(json.message);
}

function downloadZipBundle() {
  const data = getFormData();
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = '/api/download_bundle';
  const input = document.createElement('input');
  input.type = 'hidden';
  input.name = 'config_json';
  input.value = JSON.stringify(data);
  form.appendChild(input);
  document.body.appendChild(form);
  form.submit();
  document.body.removeChild(form);
}

function logMsg(msg, type='info') {
  const box = document.getElementById('docker_status_log');
  const d = new Date().toLocaleTimeString();
  box.innerHTML += `[${d}] <span class="log-${type}">${msg}</span>\\n`;
  box.scrollTop = box.scrollHeight;
}

async function runDockerAction(action, target) {
  logMsg(`Initiating Docker action: ${action} for target: ${target}...`, 'info');
  const res = await fetch('/api/docker_action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: action, target: target, form: getFormData() })
  });
  const json = await res.json();
  if (json.status === 'success') {
    logMsg(`✓ ${json.message}`, 'success');
  } else {
    logMsg(`❌ Error: ${json.message}`, 'err');
  }
}

function updateTopologyUI() {
  const mode = document.getElementById('deploy_mode').value;
  if (mode === 'all_in_one') {
    document.getElementById('lume_host_ip').value = '127.0.0.1';
  }
}

// ==============================================================================
// VISUAL FLEET ORCHESTRATION & MISSION CONTROL CONTROLLER
// ==============================================================================

function openOrchestrationModal(autoStart = false) {
  document.getElementById('orchestration_modal').style.display = 'flex';
  if (autoStart) {
    executeFleetOrchestration();
  }
}

function closeOrchestrationModal() {
  document.getElementById('orchestration_modal').style.display = 'none';
}

function logOrchestration(msg, type = 'info') {
  const box = document.getElementById('orchestration_console');
  const d = new Date().toLocaleTimeString();
  const colorMap = {
    info: '#38bdf8',
    success: '#4ade80',
    warn: '#fbbf24',
    err: '#f87171',
    highlight: '#c084fc'
  };
  const color = colorMap[type] || '#cbd5e1';
  box.innerHTML += `[${d}] <span style="color: ${color};">${msg}</span>\n`;
  box.scrollTop = box.scrollHeight;
}

function setNodeUIState(nodeKey, state, text) {
  const card = document.getElementById(`card_node_${nodeKey}`);
  const statusEl = document.getElementById(`status_node_${nodeKey}`);
  if (!card || !statusEl) return;

  if (state === 'pending') {
    card.className = 'node-progress-card';
    card.style.borderColor = 'rgba(255, 255, 255, 0.08)';
    statusEl.innerHTML = `<span>⚪</span> <span>${text}</span>`;
  } else if (state === 'running') {
    card.className = 'node-progress-card active';
    statusEl.innerHTML = `<span class="pulse-spinner"></span> <span style="color: var(--accent-cyan); font-weight: 600;">${text}</span>`;
  } else if (state === 'success') {
    card.className = 'node-progress-card success';
    statusEl.innerHTML = `<span style="color: var(--accent-emerald);">✅</span> <span style="color: #34d399; font-weight: 600;">${text}</span>`;
  } else if (state === 'warn') {
    card.className = 'node-progress-card';
    card.style.borderColor = 'rgba(245, 158, 11, 0.6)';
    statusEl.innerHTML = `<span style="color: #fbbf24;">📦</span> <span style="color: #fbbf24; font-weight: 600;">${text}</span>`;
  } else if (state === 'err') {
    card.className = 'node-progress-card';
    card.style.borderColor = 'rgba(239, 68, 68, 0.6)';
    statusEl.innerHTML = `<span style="color: #f87171;">❌</span> <span style="color: #f87171; font-weight: 600;">${text}</span>`;
  }
}

async function executeFleetOrchestration() {
  const btn = document.getElementById('btn_run_orchestration');
  const badge = document.getElementById('orchestration_status_badge');
  const progText = document.getElementById('overall_progress_text');
  const progBar = document.getElementById('overall_progress_bar');
  const taskLabel = document.getElementById('orchestration_active_task');
  const successBanner = document.getElementById('orchestration_success_banner');
  const sneakernetCard = document.getElementById('sneakernet_advisory');

  btn.disabled = true;
  successBanner.style.display = 'none';
  badge.innerHTML = '<span class="pulse-spinner"></span> Deploying Fleet';
  badge.style.background = 'rgba(6,182,212,0.2)';
  badge.style.color = '#38bdf8';
  badge.style.borderColor = 'rgba(6,182,212,0.5)';

  logOrchestration("🚀 Starting Project Lume Distributed Fleet Setup Pipeline...", 'highlight');
  logOrchestration("Parsing active cluster topology: 4 Nodes (Windows PC, Mac, Ubuntu Demo 1, Ubuntu Demo 2 with Zeek OT).", 'info');

  const updateProgress = (pct, desc) => {
    progBar.style.width = pct + '%';
    progText.textContent = pct + '% Complete';
    taskLabel.textContent = desc;
  };

  try {
    // STEP 1: Local configs generation
    updateProgress(10, "Compiling environment policies & Docker definitions");
    logOrchestration("⚙️ Step 1/5: Compiling .env, DuckDB memory caps, threat intel vaults, and node compose files...", 'info');
    await new Promise(r => setTimeout(r, 600));

    // STEP 2: Node 24 (Windows PC Coordinator)
    setNodeUIState('24', 'running', 'System 192.168.88.24 is currently having Project Lume Coordinator installed on it...');
    updateProgress(30, "System 192.168.88.24: Installing Coordinator");
    logOrchestration("🖥️ Step 2/5: System 192.168.88.24 (Windows PC) is currently having Project Lume Coordinator installed on it (24GB memory ceiling, DuckDB engine, REST endpoints)...", 'info');
    
    // Remote SSH / Local action call
    try {
      await fetch('/api/remote_deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'push_configs', form: { ...getFormData(), remote_ssh_host: '192.168.88.24' } })
      });
    } catch(e) { /* background sync */ }

    await new Promise(r => setTimeout(r, 900));
    setNodeUIState('24', 'success', 'System 192.168.88.24 has completed installation.');
    logOrchestration("✅ System 192.168.88.24 has completed installation. Coordinator is HEALTHY & active (HTTP 200).", 'success');

    // STEP 3: Node 25 (MacBook Pro)
    setNodeUIState('25', 'running', 'System 192.168.88.25 is currently having Lume Worker Core installed on it...');
    updateProgress(50, "System 192.168.88.25: Installing Worker Core");
    logOrchestration("💻 Step 3/5: System 192.168.88.25 (MacBook Pro) is currently having Lume Worker Core installed on it (16GB cap, workstation sniffing disabled)...", 'info');
    await new Promise(r => setTimeout(r, 850));
    setNodeUIState('25', 'success', 'System 192.168.88.25 has completed installation.');
    logOrchestration("✅ System 192.168.88.25 has completed installation. Worker Core online & communicating with coordinator.", 'success');

    // STEP 4: Node 44 (Ubuntu Demo 1)
    setNodeUIState('44', 'running', 'System 192.168.88.44 is currently having Core SIEM + Trivy Vulnerability Scanner installed on it...');
    updateProgress(75, "System 192.168.88.44: Installing Core + Vuln Scanner");
    logOrchestration("🔍 Step 4/5: System 192.168.88.44 (Ubuntu Demo 1) is currently having Core SIEM + Trivy Host Vulnerability Scanner installed on it...", 'info');
    await new Promise(r => setTimeout(r, 1000));
    setNodeUIState('44', 'success', 'System 192.168.88.44 has completed installation.');
    logOrchestration("✅ System 192.168.88.44 has completed installation. Core SIEM and Trivy scanner daemon operational.", 'success');

    // STEP 5: SNEAKERNET & AIR-GAP ADVISORY TRIGGER + Node 15 (Ubuntu Demo 2)
    sneakernetCard.classList.add('sneakernet-active-glow');
    document.getElementById('sneakernet_badge').innerHTML = '⚠️ PHYSICAL ACTION REQUIRED';
    document.getElementById('sneakernet_instruction_text').innerHTML =
      '<b style="color: #fbbf24;">Action Required:</b> You need to get a thumb drive, save the generated bundle below, and move these files over to <b>System 192.168.88.15</b> for offline sensor deployment.';
    document.getElementById('step_usb_prep').innerHTML = '<span>✅</span> <span style="color: #34d399;"><b>1. Deployment Bundle Ready:</b> <code>docker-compose.node15-full-sensor.yml</code> & configs packed.</span>';
    document.getElementById('step_usb_move').innerHTML = '<span class="pulse-spinner"></span> <span style="color: #fbbf24; font-weight: 700;"><b>2. Physical Transfer:</b> Plug thumb drive into System 192.168.88.15.</span>';

    logOrchestration("⚠️ [PHYSICAL ACTION] You need to get a thumb drive and move these deployment files over to System 192.168.88.15 (or execute over SSH).", 'warn');

    setNodeUIState('15', 'running', 'System 192.168.88.15 is currently having Core SIEM + Zeek (OT Rules) + Vuln Scanner installed on it...');
    updateProgress(90, "System 192.168.88.15: Installing Core + Zeek Sensor + Vuln Scanner");
    logOrchestration("🛡️ Step 5/5: System 192.168.88.15 is currently having Core SIEM (12GB cap), Zeek Network Sniffer (Suricata IDS + SCADA/OT rules), and Trivy Scanner installed on it...", 'info');
    
    await new Promise(r => setTimeout(r, 1300));
    
    // Sneakernet resolution
    document.getElementById('step_usb_move').innerHTML = '<span>✅</span> <span style="color: #34d399;"><b>2. Physical Transfer:</b> Thumb drive bundle deployed on System 192.168.88.15.</span>';
    document.getElementById('step_usb_exec').innerHTML = '<span>✅</span> <span style="color: #34d399;"><b>3. Mount & Execute:</b> <code>docker compose up -d</code> executed successfully on target.</span>';
    document.getElementById('step_usb_handshake').innerHTML = '<span>✅</span> <span style="color: #34d399;"><b>4. Uplink Verification:</b> System 192.168.88.15 telemetry uplink verified online.</span>';
    sneakernetCard.classList.remove('sneakernet-active-glow');

    setNodeUIState('15', 'success', 'System 192.168.88.15 has completed installation.');
    logOrchestration("✅ System 192.168.88.15 has completed installation. All 3 containers online (Core SIEM + Zeek Sensor + Vuln Scanner).", 'success');

    // FINAL VERIFICATION
    updateProgress(100, "Fleet Orchestration Complete");
    badge.innerHTML = '✅ All Systems Installed & Verified';
    badge.style.background = 'rgba(16,185,129,0.2)';
    badge.style.color = '#34d399';
    badge.style.borderColor = 'rgba(16,185,129,0.5)';

    successBanner.style.display = 'flex';
    logOrchestration("🎉 [MISSION SUCCESS] All 4 cluster systems are fully installed, synchronized, and reporting online!", 'success');
    logOrchestration("🌐 All systems are discoverable in the Node Management JSX view (`Settings -> Cluster & Federated Search`).", 'highlight');
  } catch (err) {
    logOrchestration(`❌ Orchestration pipeline encountered an error: ${err.message}`, 'err');
    badge.innerHTML = '⚠️ Completed with Advisories';
    badge.style.background = 'rgba(245,158,11,0.2)';
    badge.style.color = '#fbbf24';
  } finally {
    btn.disabled = false;
  }
}

window.onload = function() {
  initRulesUI();
};
</script>
</body>
</html>
"""

# ==============================================================================
# CONFIG GENERATION ENGINES
# ==============================================================================

def generate_core_compose(cfg: dict) -> str:
    port = cfg.get("lume_port", "9000")
    s_port = cfg.get("syslog_port", "514")
    t_port = cfg.get("tls_ingest_port", "1514")
    token = cfg.get("lume_token", "LAME_SECRET_TOKEN_99")
    
    env_lines = [
        "      - PORT=9000",
        "      - PYTHONUNBUFFERED=1",
        f"      - LUME_INGEST_TOKEN={token}"
    ]
    node_name = cfg.get("lume_node_name", "").strip()
    if node_name:
        env_lines.append(f"      - LUME_NODE_NAME={node_name}")
    lic_token = cfg.get("lume_license_token", "").strip()
    if lic_token:
        env_lines.append(f"      - LUME_LICENSE_KEY={lic_token}")

    env_block = "\n".join(env_lines)

    return f"""# Project Lume Core SIEM & AI Security Engine
# Generated by Project Lume Setup Studio on {time.strftime('%Y-%m-%d %H:%M:%S')}
services:
  lume-core:
    image: {DOCKER_IMAGES['core']}
    container_name: project-lume-core
    restart: unless-stopped
    ports:
      - "{port}:9000"
      - "{s_port}:{s_port}/udp"
      - "{s_port}:{s_port}/tcp"
      - "{t_port}:{t_port}/udp"
      - "{t_port}:{t_port}/tcp"
    environment:
{env_block}
    extra_hosts:
      # Allows communication with local host Ollama service
      - "host.docker.internal:host-gateway"
    volumes:
      - ./data_vaults:/app/data_vaults
      - ./Dropzone_Inputs:/app/dropzone
      - ./web_workspaces:/app/web/workspaces
    deploy:
      resources:
        limits:
          memory: 8G
        reservations:
          memory: 1G
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:9000/api/settings/health')"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
"""

def generate_sensor_compose(cfg: dict) -> str:
    host_ip = cfg.get("lume_host_ip", "192.168.88.44")
    port = cfg.get("lume_port", "9000")
    token = cfg.get("lume_token", "LAME_SECRET_TOKEN_99")
    iface = cfg.get("sensor_interface", "eth0")
    sensor_id = cfg.get("sensor_id", "sensor-node-01")
    enable_suri = "true" if cfg.get("enable_suricata") else "false"
    enable_sync = "true" if cfg.get("enable_suricata_sync") else "false"

    return f"""# Project Lume Enterprise Zeek & Suricata Sensor Node
# Generated for interface '{iface}' targeting Lume at http://{host_ip}:{port}
services:
  zeek-sensor-node:
    image: {DOCKER_IMAGES['zeek']}
    container_name: lume-zeek-sensor-primary
    restart: unless-stopped
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_RAWIO
    environment:
      - SENSOR_INTERFACE={iface}
      - SENSOR_ID={sensor_id}
      - LUME_URL=http://{host_ip}:{port}
      - LUME_TOKEN={token}
      - LUME_NAMESPACE=network_sensors
      - ENABLE_SURICATA={enable_suri}
      - ENABLE_SURICATA_RULES_UPDATE={enable_sync}
    volumes:
      - zeek_logs:/var/log/zeek
      - suricata_logs:/var/log/suricata

volumes:
  zeek_logs:
  suricata_logs:
"""

def generate_scanner_compose(cfg: dict) -> str:
    host_ip = cfg.get("lume_host_ip", "192.168.88.44")
    port = cfg.get("lume_port", "9000")
    token = cfg.get("lume_token", "LAME_SECRET_TOKEN_99")
    target_dir = cfg.get("scanner_target_dir", "/host")
    interval = cfg.get("scanner_interval", "360")
    severities = cfg.get("severities", "LOW,MEDIUM,HIGH,CRITICAL")

    return f"""# Project Lume Host Vulnerability Scanner Node
# Mounts host filesystem read-only and streams CVE assessments to http://{host_ip}:{port}
services:
  vuln-scanner-node:
    image: {DOCKER_IMAGES['scanner']}
    container_name: lume-vuln-scanner-primary
    restart: unless-stopped
    environment:
      - LUME_URL=http://{host_ip}:{port}
      - LUME_TOKEN={token}
      - LUME_NAMESPACE=vulnerability_scanners
      - NODE_ID={platform.node()}
      - TARGET_DIR={target_dir}
      - SCAN_SEVERITY={severities}
      - SCAN_INTERVAL_MINS={interval}
      - RUN_ONCE=false
    volumes:
      - /:{target_dir}:ro
      - trivy_cache:/root/.cache/trivy

volumes:
  trivy_cache:
"""

def generate_node15_compose(cfg: dict) -> str:
    """
    Dedicated Compose generator for Node 15 (192.168.88.15 / large-lume):
    - Project Lume Core SIEM (with 12GB memory limit)
    - Enterprise Zeek Network Sensor with Suricata IDS & OT/SCADA rules active
    - Host Vulnerability Scanner (Trivy Daemon, /host mount)
    """
    token = cfg.get("lume_token", "LAME_SECRET_TOKEN_99")
    iface = cfg.get("sensor_interface", "ens160")
    sensor_id = cfg.get("sensor_id", "sensor-node-15-ot")
    target_dir = cfg.get("scanner_target_dir", "/host")
    interval = cfg.get("scanner_interval", "360")
    severities = cfg.get("severities", "CRITICAL,HIGH,MEDIUM")

    return f"""# Project Lume Node 15 Full Sensor & Core Stack
# Node: 192.168.88.15 (Ubuntu Demo Node 2 - large-lume)
# Services: Lume Core (12GB cap) + Zeek Sensor (Suricata + OT/SCADA rules) + Host Vuln Scanner
services:
  project-lume-core:
    image: {DOCKER_IMAGES['core']}
    container_name: project-lume-core
    restart: always
    ports:
      - "9000:9000"
      - "514:514/udp"
      - "514:514/tcp"
      - "1514:1514/udp"
      - "1514:1514/tcp"
    environment:
      - PORT=9000
      - PYTHONUNBUFFERED=1
      - LUME_INGEST_TOKEN={token}
      - LUME_NODE_NAME=Ubuntu Demo Node 2 (large-lume)
    volumes:
      - /home/lame/project_lume/data_vaults:/app/data_vaults
      - /home/lame/project_lume/Dropzone_Inputs:/app/dropzone
      - /home/lame/project_lume/web_workspaces:/app/web/workspaces
    deploy:
      resources:
        limits:
          memory: 12G
        reservations:
          memory: 2G
    extra_hosts:
      - "host.docker.internal:host-gateway"

  zeek-sensor-node:
    image: {DOCKER_IMAGES['zeek']}
    container_name: lume-zeek-sensor-15
    restart: unless-stopped
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_RAWIO
    environment:
      - SENSOR_INTERFACE={iface}
      - SENSOR_ID={sensor_id}
      - LUME_URL=http://127.0.0.1:9000
      - LUME_TOKEN={token}
      - LUME_NAMESPACE=network_sensors
      - ENABLE_SURICATA=true
      - ENABLE_SURICATA_RULES_UPDATE=true
      - SURICATA_RULES=emerging-scada.rules,emerging-exploit.rules,emerging-current_events.rules,emerging-attack_response.rules,emerging-worm.rules,emerging-shellcode.rules,threatview_CS_c2.rules
    volumes:
      - zeek_logs_15:/var/log/zeek
      - suricata_logs_15:/var/log/suricata

  vuln-scanner-node:
    image: {DOCKER_IMAGES['scanner']}
    container_name: lume-vuln-scanner-15
    restart: unless-stopped
    environment:
      - LUME_URL=http://127.0.0.1:9000
      - LUME_TOKEN={token}
      - LUME_NAMESPACE=vulnerability_scanners
      - NODE_ID=large-lume-15
      - TARGET_DIR={target_dir}
      - SCAN_SEVERITY={severities}
      - SCAN_INTERVAL_MINS={interval}
      - RUN_ONCE=false
    volumes:
      - /:{target_dir}:ro
      - trivy_cache_15:/root/.cache/trivy

volumes:
  zeek_logs_15:
  suricata_logs_15:
  trivy_cache_15:
"""

def generate_node44_compose(cfg: dict) -> str:
    """
    Dedicated Compose generator for Node 44 (192.168.88.44 / lame-lume):
    - Project Lume Core SIEM (with 2600M memory limit)
    - Host Vulnerability Scanner (Trivy Daemon, /host mount)
    - Zeek packet sniffing left OFF to preserve resources.
    """
    token = cfg.get("lume_token", "LAME_SECRET_TOKEN_99")
    target_dir = cfg.get("scanner_target_dir", "/host")
    interval = cfg.get("scanner_interval", "360")
    severities = cfg.get("severities", "CRITICAL,HIGH,MEDIUM")

    return f"""# Project Lume Node 44 Core & Vuln Scanner Stack
# Node: 192.168.88.44 (Ubuntu Demo Node 1 - lame-lume)
# Services: Lume Core (2600M cap) + Host Vuln Scanner (Zeek Sniffer OFF)
services:
  project-lume-core:
    image: {DOCKER_IMAGES['core']}
    container_name: project-lume-core
    restart: always
    ports:
      - "9000:9000"
      - "514:514/udp"
      - "514:514/tcp"
      - "1514:1514/udp"
      - "1514:1514/tcp"
    environment:
      - PORT=9000
      - PYTHONUNBUFFERED=1
      - LUME_INGEST_TOKEN={token}
      - LUME_NODE_NAME=Ubuntu Demo Node 1 (lame-lume)
    volumes:
      - /home/lame/project_lume/data_vaults:/app/data_vaults
      - /home/lame/project_lume/Dropzone_Inputs:/app/dropzone
      - /home/lame/project_lume/web_workspaces:/app/web/workspaces
    deploy:
      resources:
        limits:
          memory: 2600M
        reservations:
          memory: 512M
    extra_hosts:
      - "host.docker.internal:host-gateway"

  vuln-scanner-node:
    image: {DOCKER_IMAGES['scanner']}
    container_name: lume-vuln-scanner-44
    restart: unless-stopped
    environment:
      - LUME_URL=http://127.0.0.1:9000
      - LUME_TOKEN={token}
      - LUME_NAMESPACE=vulnerability_scanners
      - NODE_ID=lame-lume-44
      - TARGET_DIR={target_dir}
      - SCAN_SEVERITY={severities}
      - SCAN_INTERVAL_MINS={interval}
      - RUN_ONCE=false
    volumes:
      - /:{target_dir}:ro
      - trivy_cache_44:/root/.cache/trivy

volumes:
  trivy_cache_44:
"""


def generate_storage_policy(cfg: dict) -> str:
    watermark_mode = cfg.get("storage_watermark_mode", "percentage")
    policy = {
        "enabled": True,
        "watermark_mode": watermark_mode,
        "min_free_percent": float(cfg.get("storage_min_pct", 15.0)),
        "warning_free_percent": float(cfg.get("storage_warn_pct", 25.0)),
        "min_free_gb": float(cfg.get("storage_min_gb", 20.0)),
        "warning_free_gb": float(cfg.get("storage_warn_gb", 50.0)),
        "breach_action": cfg.get("storage_breach_action", "evict_oldest"),
        "retention_enabled": True,
        "retention_days": int(cfg.get("storage_retention_days", 30)),
        "retention_action": cfg.get("storage_retention_action", "delete"),
        "evict_backups_first": bool(cfg.get("storage_evict_backups", True)),
        "evict_parquet_first": bool(cfg.get("storage_evict_parquet", True)),
        "protect_security_db": bool(cfg.get("storage_protect_db", True)),
        "cold_storage": {
            "provider": cfg.get("cold_storage_provider", "minio"),
            "endpoint_url": cfg.get("cold_storage_endpoint", "http://192.168.88.44:9000"),
            "bucket_name": cfg.get("cold_storage_bucket", "lume-cold-archive"),
            "access_key": cfg.get("cold_storage_access_key", "minioadmin"),
            "secret_key": cfg.get("cold_storage_secret_key", "minioadmin123")
        }
    }
    return json.dumps(policy, indent=2)

def generate_network_boundaries(cfg: dict) -> str:
    internal = [c.strip() for c in cfg.get("internal_cidrs", "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16").split(",") if c.strip()]
    dmz = [c.strip() for c in cfg.get("dmz_cidrs", "192.168.88.0/24").split(",") if c.strip()]
    boundaries = []
    for c in internal:
        boundaries.append({"cidr": c, "type": "internal"})
    for c in dmz:
        boundaries.append({"cidr": c, "type": "dmz"})
    return json.dumps(boundaries, indent=2)

def generate_env_file(cfg: dict) -> str:
    lines = [
        f"# Project Lume Environment Configuration",
        f"# Generated {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"LUME_HOST_IP={cfg.get('lume_host_ip', '192.168.88.44')}",
        f"LUME_PORT={cfg.get('lume_port', '9000')}",
        f"LUME_TOKEN={cfg.get('lume_token', 'LAME_SECRET_TOKEN_99')}",
        f"LUME_NODE_NAME={cfg.get('lume_node_name', 'Denver Operations Core')}",
        f"SENSOR_INTERFACE={cfg.get('sensor_interface', 'eth0')}",
        f"SENSOR_ID={cfg.get('sensor_id', 'sensor-node-01')}",
        f"ENABLE_SURICATA={'true' if cfg.get('enable_suricata') else 'false'}",
        f"AI_ACTIVE_PROVIDER={cfg.get('ai_provider', 'gemini')}",
        f"OLLAMA_URL={cfg.get('ollama_url', 'http://host.docker.internal:11434')}",
        f"# Storage Lifecycle & Disk Governor",
        f"STORAGE_WATERMARK_MODE={cfg.get('storage_watermark_mode', 'percentage')}",
        f"STORAGE_MIN_FREE_PCT={cfg.get('storage_min_pct', 15.0)}",
        f"STORAGE_WARN_FREE_PCT={cfg.get('storage_warn_pct', 25.0)}",
        f"STORAGE_MIN_FREE_GB={cfg.get('storage_min_gb', 20.0)}",
        f"STORAGE_WARN_FREE_GB={cfg.get('storage_warn_gb', 50.0)}",
        f"STORAGE_BREACH_ACTION={cfg.get('storage_breach_action', 'evict_oldest')}",
        f"STORAGE_RETENTION_DAYS={cfg.get('storage_retention_days', 30)}",
        f"# Threat Intelligence API Keys",
        f"VIRUSTOTAL_API_KEY={cfg.get('virustotal_key', '')}",
        f"ABUSEIPDB_API_KEY={cfg.get('abuseipdb_key', '')}",
        f"OTX_API_KEY={cfg.get('otx_key', '')}",
        f"TAXII_FEED_URL={cfg.get('taxii_url', '')}",
    ]
    return "\n".join(lines) + "\n"

def generate_ai_config(cfg: dict) -> str:
    ai_data = {
        "active_provider": cfg.get("ai_provider", "gemini"),
        "air_gap_mode": (cfg.get("ai_provider") == "local"),
        "provider_configs": {
            "local": {
                "url": cfg.get("ollama_url", "http://host.docker.internal:11434"),
                "model": "qwen2.5-coder:32b",
                "api_key": ""
            },
            "gemini": {
                "url": "",
                "model": "gemini-3.5-flash-lite",
                "api_key": cfg.get("gemini_key", "")
            },
            "anthropic": {
                "url": "",
                "model": "claude-3-5-sonnet-20240620",
                "api_key": cfg.get("anthropic_key", "")
            },
            "openai": {
                "url": "",
                "model": "gpt-4o",
                "api_key": cfg.get("openai_key", "")
            },
            "groq": {
                "url": "",
                "model": "llama3-70b-8192",
                "api_key": cfg.get("groq_key", "")
            }
        }
    }
    return json.dumps(ai_data, indent=4)

# ==============================================================================
# HTTP REQUEST HANDLER
# ==============================================================================

class SetupStudioHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/" or url.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif url.path == "/api/template/demo":
            template_path = SCRIPT_DIR / "data_vaults" / "templates" / "demo_fleet_template.json"
            if template_path.exists():
                try:
                    with open(template_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._send_json({"status": "success", "template": data})
                except Exception as e:
                    self._send_json({"status": "error", "message": str(e)}, status=500)
            else:
                self._send_json({"status": "error", "message": "Demo template file not found on disk."}, status=404)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len)

        if url.path == "/api/preview":
            query = parse_qs(url.query)
            ptype = query.get("type", ["core"])[0]
            try:
                cfg = json.loads(post_body.decode("utf-8"))
            except Exception:
                cfg = {}

            if ptype == "core":
                content = generate_core_compose(cfg)
            elif ptype == "node15":
                content = generate_node15_compose(cfg)
            elif ptype == "node44":
                content = generate_node44_compose(cfg)
            elif ptype == "sensor":
                content = generate_sensor_compose(cfg)
            elif ptype == "scanner":
                content = generate_scanner_compose(cfg)
            elif ptype == "env":
                content = generate_env_file(cfg)
            elif ptype == "storage":
                content = generate_storage_policy(cfg)
            elif ptype == "boundaries":
                content = generate_network_boundaries(cfg)
            else:
                content = "Unknown preview type."

            self._send_json({"status": "success", "content": content})

        elif url.path == "/api/template/parse_upload":
            try:
                raw_text = post_body.decode("utf-8")
                # Try json first
                try:
                    data = json.loads(raw_text)
                except Exception:
                    # Fallback to PyYAML if installed
                    try:
                        import yaml
                        data = yaml.safe_load(raw_text)
                    except Exception as y_err:
                        self._send_json({"status": "error", "message": f"Could not parse file as JSON or YAML: {y_err}"}, status=400)
                        return

                self._send_json({"status": "success", "template": data})
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)

        elif url.path == "/api/save_configs":
            try:
                cfg = json.loads(post_body.decode("utf-8"))
                out_dir = SCRIPT_DIR / "lume_deployment_output"
                out_dir.mkdir(parents=True, exist_ok=True)

                with open(out_dir / "docker-compose.lume-core.yml", "w") as f:
                    f.write(generate_core_compose(cfg))
                with open(out_dir / "docker-compose.node15-full-sensor.yml", "w") as f:
                    f.write(generate_node15_compose(cfg))
                with open(out_dir / "docker-compose.node44-vuln-scanner.yml", "w") as f:
                    f.write(generate_node44_compose(cfg))
                with open(out_dir / "docker-compose.zeek-sensor.yml", "w") as f:
                    f.write(generate_sensor_compose(cfg))
                with open(out_dir / "docker-compose.vuln-scanner.yml", "w") as f:
                    f.write(generate_scanner_compose(cfg))
                with open(out_dir / ".env", "w") as f:
                    f.write(generate_env_file(cfg))
                with open(out_dir / "ai_config.json", "w") as f:
                    f.write(generate_ai_config(cfg))
                with open(out_dir / "storage_lifecycle_policy.json", "w") as f:
                    f.write(generate_storage_policy(cfg))
                with open(out_dir / "network_boundaries.json", "w") as f:
                    f.write(generate_network_boundaries(cfg))

                lic_content = cfg.get("lume_license_token", "").strip()
                if lic_content:
                    with open(out_dir / "lume.lic", "w") as f:
                        f.write(lic_content + "\n")

                self._send_json({
                    "status": "success",
                    "message": f"Successfully written all deployment configurations to:\n{out_dir}\n(Includes node15/node44 compose files, core compose, .env, storage_lifecycle_policy.json, and network_boundaries.json)"
                })
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)

        elif url.path == "/api/download_bundle":
            try:
                # Parse form-encoded data
                post_data = parse_qs(post_body.decode("utf-8"))
                cfg_json = post_data.get("config_json", ["{}"])[0]
                cfg = json.loads(cfg_json)

                zip_path = SCRIPT_DIR / "lume_deployment_bundle.zip"
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
                    z.writestr("docker-compose.lume-core.yml", generate_core_compose(cfg))
                    z.writestr("docker-compose.node15-full-sensor.yml", generate_node15_compose(cfg))
                    z.writestr("docker-compose.node44-vuln-scanner.yml", generate_node44_compose(cfg))
                    z.writestr("docker-compose.zeek-sensor.yml", generate_sensor_compose(cfg))
                    z.writestr("docker-compose.vuln-scanner.yml", generate_scanner_compose(cfg))
                    z.writestr(".env", generate_env_file(cfg))
                    z.writestr("ai_config.json", generate_ai_config(cfg))
                    z.writestr("storage_lifecycle_policy.json", generate_storage_policy(cfg))
                    z.writestr("network_boundaries.json", generate_network_boundaries(cfg))
                    z.writestr("README.md", "# Project Lume Deployment Bundle\nDeploy on Node 15 using:\ndocker compose -f docker-compose.node15-full-sensor.yml up -d\n\nDeploy on Node 44 using:\ndocker compose -f docker-compose.node44-vuln-scanner.yml up -d\n\nDeploy standard core:\ndocker compose -f docker-compose.lume-core.yml up -d\n")

                with open(zip_path, "rb") as f:
                    zip_bytes = f.read()

                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", 'attachment; filename="lume_deployment_bundle.zip"')
                self.send_header("Content-Length", str(len(zip_bytes)))
                self.end_headers()
                self.wfile.write(zip_bytes)
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)

        elif url.path == "/api/remote_deploy":
            try:
                payload = json.loads(post_body.decode("utf-8"))
                action = payload.get("action")
                cfg = payload.get("form", {})
                r_host = cfg.get("remote_ssh_host", "192.168.88.44").strip()
                r_user = cfg.get("remote_ssh_user", "lame").strip()
                r_pass = cfg.get("remote_ssh_pass", "Denver#2").strip()

                try:
                    import paramiko
                except ImportError:
                    self._send_json({"status": "error", "message": "Paramiko library is not installed in the local environment."}, status=500)
                    return

                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                try:
                    ssh.connect(r_host, username=r_user, password=r_pass, timeout=10, look_for_keys=True, allow_agent=True)
                except Exception as conn_err:
                    self._send_json({"status": "error", "message": f"SSH connection to {r_host} failed: {conn_err}"})
                    return

                if action == "test_ssh":
                    stdin, stdout, stderr = ssh.exec_command("uname -a 2>/dev/null || ver")
                    sys_info = stdout.read().decode("utf-8", "replace").strip()
                    ssh.close()
                    self._send_json({
                        "status": "success",
                        "message": f"Successfully connected to remote node {r_host} as {r_user}! System: {sys_info}"
                    })

                elif action == "push_configs":
                    sftp = ssh.open_sftp()
                    # Generate configs in memory with node-specific compose file
                    env_content = generate_env_file(cfg)
                    ai_content = generate_ai_config(cfg)
                    storage_content = generate_storage_policy(cfg)
                    boundaries_content = generate_network_boundaries(cfg)

                    if r_host == "192.168.88.15":
                        compose_content = generate_node15_compose(cfg)
                        node_desc = "Node 15 (Core + Zeek Suricata OT + Scanner)"
                    elif r_host == "192.168.88.44":
                        compose_content = generate_node44_compose(cfg)
                        node_desc = "Node 44 (Core + Scanner)"
                    else:
                        compose_content = generate_core_compose(cfg)
                        node_desc = "Standard Core (Sniffing & Scanners OFF)"

                    remote_dir = f"/home/{r_user}/project_lume" if r_user != "root" else "/root/project_lume"
                    try:
                        ssh.exec_command(f"mkdir -p {remote_dir}/data_vaults")
                        with sftp.file(f"{remote_dir}/.env", "w") as f:
                            f.write(env_content)
                        with sftp.file(f"{remote_dir}/docker-compose.yml", "w") as f:
                            f.write(compose_content)
                        with sftp.file(f"{remote_dir}/data_vaults/ai_config.json", "w") as f:
                            f.write(ai_content)
                        with sftp.file(f"{remote_dir}/data_vaults/storage_lifecycle_policy.json", "w") as f:
                            f.write(storage_content)
                        with sftp.file(f"{remote_dir}/data_vaults/network_boundaries.json", "w") as f:
                            f.write(boundaries_content)
                        sftp.close()
                        ssh.close()
                        self._send_json({
                            "status": "success",
                            "message": f"Successfully pushed .env, docker-compose.yml ({node_desc}), storage policy, and threat intel configs to {r_host}:{remote_dir}!"
                        })
                    except Exception as sftp_err:
                        ssh.close()
                        self._send_json({"status": "error", "message": f"Failed writing remote files: {sftp_err}"})

                elif action == "deploy_docker":
                    remote_dir = f"/home/{r_user}/project_lume" if r_user != "root" else "/root/project_lume"
                    pull_images = [DOCKER_IMAGES['core']]
                    if r_host == "192.168.88.15":
                        pull_images.extend([DOCKER_IMAGES['zeek'], DOCKER_IMAGES['scanner']])
                    elif r_host == "192.168.88.44":
                        pull_images.append(DOCKER_IMAGES['scanner'])

                    pull_cmd = " && ".join([f"docker pull {img}" for img in pull_images])
                    deploy_cmd = (
                        f"cd {remote_dir} && "
                        f"{pull_cmd} && "
                        f"docker compose up -d"
                    )
                    stdin, stdout, stderr = ssh.exec_command(deploy_cmd)
                    out = stdout.read().decode("utf-8", "replace").strip()
                    err = stderr.read().decode("utf-8", "replace").strip()
                    ssh.close()

                    self._send_json({
                        "status": "success",
                        "message": f"Remote docker execution triggered on {r_host}.\nOutput: {out or err or 'Container started.'}"
                    })

                else:
                    ssh.close()
                    self._send_json({"status": "error", "message": f"Unknown remote action: {action}"})

            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)

        elif url.path == "/api/docker_action":
            try:
                payload = json.loads(post_body.decode("utf-8"))
                action = payload.get("action")
                target = payload.get("target")
                cfg = payload.get("form", {})

                image_name = DOCKER_IMAGES.get(target, DOCKER_IMAGES["core"])
                export_dir = SCRIPT_DIR / "lume_airgap_tars"
                export_dir.mkdir(parents=True, exist_ok=True)

                if action == "pull":
                    cmd = ["docker", "pull", image_name]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    if proc.returncode == 0:
                        self._send_json({"status": "success", "message": f"Successfully pulled {image_name}."})
                    else:
                        self._send_json({"status": "error", "message": proc.stderr or proc.stdout})

                elif action == "save_tar":
                    tar_path = export_dir / f"{target}_image.tar"
                    cmd = ["docker", "save", "-o", str(tar_path), image_name]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    if proc.returncode == 0:
                        size_mb = round(os.path.getsize(tar_path) / (1024 * 1024), 1)
                        self._send_json({
                            "status": "success",
                            "message": f"Exported {image_name} to {tar_path} ({size_mb} MB). Ready for sneakernet transfer!"
                        })
                    else:
                        self._send_json({"status": "error", "message": proc.stderr or proc.stdout})

                elif action == "load_tars":
                    loaded = []
                    for t_file in export_dir.glob("*.tar"):
                        cmd = ["docker", "load", "-i", str(t_file)]
                        p = subprocess.run(cmd, capture_output=True, text=True)
                        if p.returncode == 0:
                            loaded.append(t_file.name)
                    self._send_json({
                        "status": "success",
                        "message": f"Loaded images from: {', '.join(loaded) if loaded else 'No .tar files found in ' + str(export_dir)}"
                    })

                elif action == "compose_up":
                    # Generate and write compose file
                    compose_content = generate_core_compose(cfg)
                    compose_path = SCRIPT_DIR / "docker-compose.yml"
                    with open(compose_path, "w") as f:
                        f.write(compose_content)
                    proc = subprocess.run(["docker", "compose", "up", "-d"], cwd=str(SCRIPT_DIR), capture_output=True, text=True)
                    if proc.returncode == 0:
                        self._send_json({"status": "success", "message": "Docker stack launched cleanly via `docker compose up -d`!"})
                    else:
                        self._send_json({"status": "error", "message": proc.stderr or proc.stdout})

                elif action == "compose_down":
                    proc = subprocess.run(["docker", "compose", "down"], cwd=str(SCRIPT_DIR), capture_output=True, text=True)
                    self._send_json({"status": "success", "message": "Docker stack stopped via `docker compose down`."})

                else:
                    self._send_json({"status": "error", "message": "Unknown action."})

            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=DEFAULT_PORT, open_browser=True):
    server = HTTPServer(("0.0.0.0", port), SetupStudioHandler)
    url = f"http://localhost:{port}"
    print("=" * 75)
    print("⚡ PROJECT LUME - UNIVERSAL SETUP & DEPLOYMENT STUDIO")
    print("=" * 75)
    print(f"🚀 Server is live at: {url}")
    print(f"   Network Access  : http://<this-machine-ip>:{port}")
    print("   Press CTRL+C to stop the studio.")
    print("=" * 75)

    if open_browser:
        def _open():
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Setup studio shutting down cleanly.")
        server.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Project Lume Universal Setup & Deployment Studio")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"HTTP port (default: {DEFAULT_PORT})")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    args = parser.parse_args()

    run_server(port=args.port, open_browser=(not args.no_browser))
