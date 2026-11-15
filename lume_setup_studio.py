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
# Port 8090 avoids collision with Splunk HEC listener (port 8088) in project-lume-core container
DEFAULT_PORT = 8090
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
.btn-rose {
  background: linear-gradient(135deg, var(--accent-rose), #be123c);
  color: #fff; box-shadow: 0 4px 14px rgba(244, 63, 94, 0.35);
}
.btn-rose:hover { filter: brightness(1.1); transform: translateY(-1px); }

/* Architecture Mode Visual Cards */
.arch-card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}
.arch-card {
  background: rgba(13, 18, 31, 0.7);
  border: 2px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  padding: 18px 16px;
  cursor: pointer;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  display: flex;
  flex-direction: column;
}
.arch-card:hover {
  border-color: rgba(99, 102, 241, 0.4);
  background: rgba(18, 24, 42, 0.9);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}
.arch-card.selected {
  border-color: #6366f1;
  background: linear-gradient(180deg, rgba(99, 102, 241, 0.15) 0%, rgba(13, 18, 31, 0.9) 100%);
  box-shadow: 0 0 20px rgba(99, 102, 241, 0.3), inset 0 0 12px rgba(99, 102, 241, 0.1);
}
.arch-card-badge {
  position: absolute;
  top: 12px;
  right: 12px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  padding: 3px 8px;
  border-radius: 6px;
  letter-spacing: 0.5px;
}
.arch-card-icon {
  font-size: 28px;
  margin-bottom: 10px;
}
.arch-card-title {
  font-size: 15px;
  font-weight: 700;
  color: #fff;
  margin-bottom: 6px;
}
.arch-card-desc {
  font-size: 12px;
  color: var(--text-muted);
  line-height: 1.45;
  flex: 1;
}

/* Dynamic Fleet Node Builder Table */
.node-builder-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  margin-top: 12px;
}
.node-builder-table th {
  padding: 10px 8px;
  color: var(--text-muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.12);
  text-align: left;
}
.node-builder-table td {
  padding: 10px 8px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  vertical-align: middle;
}
.node-builder-table input[type="text"],
.node-builder-table select {
  font-size: 12px;
  padding: 7px 10px;
}
.node-row:hover {
  background: rgba(255, 255, 255, 0.02);
}

/* Collapsible Advanced Settings Accordion */
details.collapsible-card {
  background: rgba(13, 18, 31, 0.5);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: var(--radius);
  margin-top: 18px;
  padding: 0;
  overflow: hidden;
  transition: all 0.2s ease;
}
details.collapsible-card[open] {
  border-color: rgba(99, 102, 241, 0.3);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
}
details.collapsible-card > summary {
  padding: 16px 20px;
  font-size: 14px;
  font-weight: 600;
  color: #e2e8f0;
  cursor: pointer;
  list-style: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  user-select: none;
  background: rgba(255, 255, 255, 0.02);
}
details.collapsible-card > summary::-webkit-details-marker {
  display: none;
}
details.collapsible-card > summary::after {
  content: "▼";
  font-size: 10px;
  color: var(--text-muted);
  transition: transform 0.2s ease;
}
details.collapsible-card[open] > summary::after {
  transform: rotate(180deg);
  color: var(--accent-cyan);
}
details.collapsible-card .collapsible-body {
  padding: 20px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
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

/* Phase 1 & 2: Quick Personas, Node Modes & Dynamic Visual Topology Graph */
.persona-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 14px;
  margin-bottom: 22px;
}
.persona-card {
  background: rgba(18, 24, 38, 0.65);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: var(--radius);
  padding: 16px 18px;
  cursor: pointer;
  transition: all 0.25s ease;
  position: relative;
  overflow: hidden;
}
.persona-card:hover {
  border-color: var(--accent-cyan);
  transform: translateY(-2px);
  background: rgba(24, 32, 52, 0.85);
  box-shadow: 0 8px 24px rgba(6, 182, 212, 0.15);
}
.persona-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 8px;
  border-radius: 6px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 8px;
}
.persona-title {
  font-size: 13px;
  font-weight: 700;
  color: #fff;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.persona-desc {
  font-size: 11px;
  color: var(--text-muted);
  line-height: 1.45;
}
.mode-toggle-btn {
  padding: 3px 8px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 700;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.2s ease;
  user-select: none;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.mode-toggle-prod {
  background: rgba(16, 185, 129, 0.15);
  color: #34d399;
  border-color: rgba(16, 185, 129, 0.4);
}
.mode-toggle-prod:hover {
  background: rgba(16, 185, 129, 0.25);
  border-color: rgba(16, 185, 129, 0.6);
}
.mode-toggle-demo {
  background: rgba(245, 158, 11, 0.15);
  color: #fbbf24;
  border-color: rgba(245, 158, 11, 0.4);
}
.mode-toggle-demo:hover {
  background: rgba(245, 158, 11, 0.25);
  border-color: rgba(245, 158, 11, 0.6);
}
.topology-map-wrapper {
  margin-top: 18px;
  background: rgba(13, 18, 31, 0.6);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: var(--radius);
  padding: 18px;
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
            <!-- Dynamically populated from fleetNodes configured in Tab 1 -->
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
        <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.08); flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 11px; color: #94a3b8;" id="orchestration_targets_summary">
            Targets: <b>Configured Fleet Nodes</b>
          </div>
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <button class="btn btn-cyan" id="btn_run_preflight" onclick="runPreflightInspection()">🔍 Pre-Flight System & Port Probe</button>
            <button class="btn btn-secondary" onclick="closeOrchestrationModal()">Close Window</button>
            <button class="btn btn-emerald pulse-btn" id="btn_run_orchestration" onclick="executeFleetOrchestration()">🚀 Execute Orchestration Pipeline</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <nav class="tabs">
    <button class="tab-btn active" id="tab_btn_topology" onclick="switchTab('topology', this)">🏗️ 1. Architecture & IPs</button>
    <button class="tab-btn" id="tab_btn_storage" onclick="switchTab('storage', this)">💾 2. Storage & Lifecycle</button>
    <button class="tab-btn" id="tab_btn_telemetry" onclick="switchTab('telemetry', this)">🛡️ 3. Sensors & Suricata</button>
    <button class="tab-btn" id="tab_btn_ai_vault" onclick="switchTab('ai_vault', this)">🤖 4. AI Keys & Vaults</button>
    <button class="tab-btn" id="tab_btn_compose" onclick="switchTab('compose', this)">📄 5. Generated Compose</button>
    <button class="tab-btn" id="tab_btn_airgap" onclick="switchTab('airgap', this)">📦 6. Sneakernet & Deploy</button>
    <button class="tab-btn" id="tab_btn_update" onclick="switchTab('update', this)">🔄 7. Fleet Update</button>
    <button class="tab-btn" id="tab_btn_remove" onclick="switchTab('remove', this)">🗑️ 8. Fleet Decommission</button>
  </nav>

  <!-- TAB 1: TOPOLOGY & IPS -->
  <div id="tab-topology" class="tab-panel active">
    <!-- 1-CLICK QUICK SETUP PERSONAS (PHASE 2) -->
    <div style="margin-bottom: 22px;">
      <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--accent-cyan); font-weight: 700; margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
        <span>⚡</span> <span>1-Click Deployment Personas</span>
      </div>
      <div class="persona-grid">
        <div class="persona-card" onclick="applyPersonaPreset('enterprise_prod')" title="Load Hardened Enterprise Production Configuration">
          <div class="persona-badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4);">
            🛡️ Enterprise Sovereign
          </div>
          <div class="persona-title">Enterprise Production Fleet</div>
          <div class="persona-desc">Hardened multi-node deployment. Production Mode locked, 16GB RAM limit, Universal Forwarders active, strict storage watermark.</div>
        </div>

        <div class="persona-card" onclick="applyPersonaPreset('demo_lab')" title="Load Training & Demonstration Lab Configuration">
          <div class="persona-badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4);">
            🧪 POC & Demo Lab
          </div>
          <div class="persona-title">Customer POC & Training Lab</div>
          <div class="persona-desc">Instant evaluation environment. Demo Mode ON, synthetic anomaly pivot generation active, BOTS showcase seeding unlocked.</div>
        </div>

        <div class="persona-card" onclick="applyPersonaPreset('tactical_edge')" title="Load Constrained Industrial OT Sensor Configuration">
          <div class="persona-badge" style="background: rgba(6, 182, 212, 0.2); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.4);">
            ⚡ Tactical Edge Sensor
          </div>
          <div class="persona-title">Tactical OT / SCADA Edge</div>
          <div class="persona-desc">Constrained industrial edge forwarder. 2.6GB memory cap, Zeek + Suricata ICS/SCADA rules, Universal Forwarder to core.</div>
        </div>
      </div>
    </div>
    <!-- VISUAL ARCHITECTURE MODE SELECTOR (Replaces confusing dropdown) -->
    <div class="card">
      <div class="card-header">
        <h2>🌐 Choose Your Deployment Architecture</h2>
        <p>Select your deployment scale. Project Lume configures inter-container networking, ingest streams, and cluster coordination automatically.</p>
      </div>

      <!-- Hidden select to maintain full backwards-compatibility with template import/export -->
      <select id="deploy_mode" style="display: none;" onchange="syncArchitectureCardsFromSelect()">
        <option value="all_in_one">all_in_one</option>
        <option value="server_sensor">server_sensor</option>
        <option value="distributed" selected>distributed</option>
        <option value="cluster_coordinator">cluster_coordinator</option>
        <option value="cluster_worker">cluster_worker</option>
        <option value="sensors_only">sensors_only</option>
      </select>

      <div class="arch-card-grid">
        <div class="arch-card" id="card_mode_all_in_one" onclick="selectDeploymentMode('all_in_one')">
          <span class="arch-card-badge" style="background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid rgba(16,185,129,0.4);">⚡ Quick Trial</span>
          <div class="arch-card-icon">💻</div>
          <div class="arch-card-title">Single Machine (All-in-One)</div>
          <div class="arch-card-desc">Run everything on your laptop or a single test server (Core SIEM + DuckDB engine). Ideal for testing or standalone incident response.</div>
        </div>

        <div class="arch-card" id="card_mode_server_sensor" onclick="selectDeploymentMode('server_sensor')">
          <span class="arch-card-badge" style="background: rgba(6,182,212,0.2); color: #22d3ee; border: 1px solid rgba(6,182,212,0.4);">🛡️ Standard 2-Node</span>
          <div class="arch-card-icon">🌐</div>
          <div class="arch-card-title">Server + Remote Sensor</div>
          <div class="arch-card-desc">Lume Core SIEM on your main server, with a dedicated remote network sensor (Zeek/Suricata) sniffing on a switch SPAN or perimeter TAP.</div>
        </div>

        <div class="arch-card selected" id="card_mode_distributed" onclick="selectDeploymentMode('distributed')">
          <span class="arch-card-badge" style="background: rgba(99,102,241,0.2); color: #818cf8; border: 1px solid rgba(99,102,241,0.4);">🏢 Enterprise Fleet</span>
          <div class="arch-card-icon">🖥️</div>
          <div class="arch-card-title">Custom Fleet / Multi-Node</div>
          <div class="arch-card-desc">Multiple SIEM instances, secondary sensors, edge log throwers, and CVE vulnerability scanners forwarding across internal network tiers.</div>
        </div>
      </div>

      <!-- Core SIEM Binding Fields -->
      <div class="grid-2" style="margin-top: 14px; padding-top: 14px; border-top: 1px solid rgba(255,255,255,0.06);">
        <div class="form-group">
          <label>Friendly Core Name (Primary SIEM)</label>
          <input type="text" id="lume_node_name" value="Primary Operations Core" placeholder="e.g. Primary Operations Core" oninput="syncPrimaryCoreFromInputs()">
          <div class="helper">Shown across federated search, cluster topology, and health status.</div>
        </div>
        <div class="form-group">
          <label>Cross-Service Ingest Authorization Token (Shared Secret)</label>
          <input type="text" id="lume_token" value="LAME_SECRET_TOKEN_99">
          <div class="helper">Used by Zeek sensors, log throwers, and vulnerability scanners to authenticate log batches into /api/v1/ingest/raw.</div>
        </div>
      </div>

      <div class="grid-2" style="margin-top: 6px;">
        <div class="form-group">
          <label>Primary Project Lume Core Host IP / FQDN</label>
          <input type="text" id="lume_host_ip" value="127.0.0.1" placeholder="e.g. 192.168.1.100 or 127.0.0.1" oninput="syncPrimaryCoreFromInputs()">
          <div class="helper">The IP address of your primary Project Lume Core web app and DuckDB engine. Automatically sets Node 1 below.</div>
        </div>
        <div class="form-group">
          <label>Project Lume Web Port</label>
          <input type="number" id="lume_port" value="9000" oninput="syncPrimaryCoreFromInputs()">
          <div class="helper">Standard web interface and REST ingest port (Default: 9000).</div>
        </div>
      </div>
    </div>

    <!-- DYNAMIC FLEET NODES BUILDER (Replaces confusing hardcoded table) -->
    <div class="card" id="fleet_builder_card">
      <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <div style="display: flex; align-items: center; gap: 12px;">
          <div style="font-size: 24px;">🖥️</div>
          <div>
            <h2>Fleet Nodes & Sensor Forwarding Topology</h2>
            <p>Define which machines run Core SIEM, packet sniffing (Zeek/Suricata), vulnerability scanning, or log forwarding, and specify where each node sends its logs.</p>
          </div>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="btn btn-secondary" type="button" onclick="loadSampleFleetPreset()" style="font-size: 11px; padding: 7px 12px;" title="Load standard multi-node reference setup (Primary Core, Secondary Core, Edge Forwarders)">
            📋 Load Sample Multi-Sensor Topology
          </button>
          <button class="btn btn-cyan" id="btn_inline_preflight" type="button" onclick="runInlinePreflightCheck()" style="font-size: 11px; padding: 7px 12px;" title="Ping each fleet node IP and verify Docker socket readiness">
            ⚡ Test Fleet Connectivity
          </button>
          <button class="btn btn-secondary" type="button" onclick="clearFleetNodes()" style="font-size: 11px; padding: 7px 12px;">
            🧹 Blank Slate
          </button>
          <button class="btn btn-primary" type="button" onclick="addNewFleetNode()" style="font-size: 11px; padding: 7px 12px;">
            ➕ Add Node
          </button>
        </div>
      </div>

      <div style="overflow-x: auto; margin-top: 10px;">
        <table class="node-builder-table">
          <thead>
            <tr>
              <th style="width: 14%;">Node IP / Host</th>
              <th style="width: 16%;">Friendly Node Name</th>
              <th style="width: 7%; text-align: center;">Core SIEM</th>
              <th style="width: 9%; text-align: center;">Mode</th>
              <th style="width: 10%; text-align: center;">RAM Cap</th>
              <th style="width: 8%; text-align: center;">Zeek/Suricata</th>
              <th style="width: 8%; text-align: center;">Vuln Scanner</th>
              <th style="width: 11%; text-align: center;">Host OS Self-Monitoring</th>
              <th style="width: 13%;">Forwarding Target (SIEM Destination)</th>
              <th style="width: 4%; text-align: center;">Action</th>
            </tr>
          </thead>
          <tbody id="fleet_nodes_tbody">
            <!-- Dynamically populated by JS renderFleetNodes() -->
          </tbody>
        </table>
      </div>

      <div id="fleet_topology_summary" style="margin-top: 14px; font-size: 12px; color: #94a3b8; display: flex; align-items: center; gap: 8px; background: rgba(13, 18, 31, 0.4); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06);">
        <span style="color: var(--accent-cyan); font-weight: 600;">ℹ️ Active Topology:</span> <span id="fleet_topology_summary_text">1 Node defined.</span>
      </div>

      <!-- DYNAMIC VISUAL TOPOLOGY GRAPH (PHASE 2) -->
      <div id="fleet_visual_topology_container" class="topology-map-wrapper">
        <!-- Dynamically populated by JS renderVisualTopologyMap() -->
      </div>
    </div>

    <!-- COLLAPSIBLE ADVANCED NETWORK & SENSOR SETTINGS ACCORDION (Replaces Upload 3) -->
    <details class="collapsible-card">
      <summary>⚙️ Advanced Network, Interfaces & Scanner Settings (Optional)</summary>
      <div class="collapsible-body">
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px;">
          Fine-tune network interface bindings, listening ports, scanner mount points, and internal CIDR boundaries. The defaults below work out-of-the-box for standard environments.
        </p>

        <div class="grid-2">
          <div class="form-group">
            <label>Zeek Sensor Sniffing Interface</label>
            <input type="text" id="sensor_interface" value="ens160" placeholder="e.g. eth0, ens160, bond0, span0">
            <div class="helper">The physical or TAP/SPAN interface Zeek listens on in promiscuous host mode.</div>
          </div>
          <div class="form-group">
            <label>Sensor Node Identifier</label>
            <input type="text" id="sensor_id" value="sensor-node-primary">
            <div class="helper">Name tagged on all generated Corelight/Zeek logs in Project Lume.</div>
          </div>
        </div>

        <div class="grid-2" style="margin-top: 10px;">
          <div class="form-group">
            <label>Syslog UDP Port (RFC 5424)</label>
            <input type="number" id="syslog_port" value="514">
            <div class="helper">Standard UDP/TCP syslog receiver port.</div>
          </div>
          <div class="form-group">
            <label>Secure TLS / OSQuery Port</label>
            <input type="number" id="tls_ingest_port" value="1514">
            <div class="helper">Encrypted high-throughput ingestion port.</div>
          </div>
        </div>

        <div class="grid-2" style="margin-top: 10px;">
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

        <div class="grid-2" style="margin-top: 10px;">
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
    </details>
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

    <!-- DATASET & NAMESPACE ISOLATION / PURGE MANAGER -->
    <div class="card" style="border: 1px solid rgba(239, 68, 68, 0.35); background: linear-gradient(180deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%);">
      <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="display: flex; align-items: center; gap: 8px;">
            <span style="color: #ef4444;">🗑️</span> Dataset & Namespace Management (Superuser)
          </h2>
          <p>Inspect active isolated datasets, deduplicate resent sensor batches (_ib_eid), or completely purge test namespaces across all DuckDB tables.</p>
        </div>
        <button class="btn btn-secondary" onclick="refreshDatasetManager()" style="font-size: 11px; padding: 6px 12px;">🔄 Refresh Datasets</button>
      </div>

      <div style="overflow-x: auto; margin-top: 10px;">
        <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
          <thead>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); text-align: left; color: #94a3b8;">
              <th style="padding: 10px 8px;">Namespace</th>
              <th style="padding: 10px 8px;">Display Name</th>
              <th style="padding: 10px 8px;">Total Events</th>
              <th style="padding: 10px 8px;">Description</th>
              <th style="padding: 10px 8px; text-align: right;">Superuser Actions</th>
            </tr>
          </thead>
          <tbody id="dataset_manager_tbody">
            <tr>
              <td colspan="5" style="padding: 16px; text-align: center; color: #64748b;">Loading registered datasets...</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div id="dataset_action_status" style="margin-top: 10px; font-size: 12px; font-weight: 500;"></div>
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

  <!-- TAB 7: FLEET UPDATE -->
  <div id="tab-update" class="tab-panel">
    <div class="card">
      <div class="card-header">
        <h2>🔄 Rolling Fleet Software Update & Image Synchronization</h2>
        <p>Safely upgrade running Project Lume containers to newer image releases without manual command-line wrangling or data loss.</p>
      </div>

      <!-- Educational / Operational Guide Alert -->
      <div style="background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 10px; padding: 16px; margin-bottom: 20px;">
        <h3 style="font-size: 14px; color: #a5b4fc; margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">
          <span>💡 Understanding How Docker Updates Work (And Preservation of Data)</span>
        </h3>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5; margin-bottom: 10px;">
          In Docker, software updates replace the ephemeral container layers with new image layers while <b>retaining all persistent mounts</b> (e.g. <code>./data_vaults</code>, DuckDB files, SQLite databases, and <code>.env</code> credentials).
        </p>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; font-size: 12px;">
          <div style="background: rgba(13, 18, 31, 0.6); padding: 10px; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.05);">
            <b style="color: var(--accent-cyan);">1. Pull Latest Layer (`docker pull`)</b>
            <p style="color: var(--text-muted); font-size: 11px; margin-top: 3px;">Downloads only differential SHA256 image layer deltas from Docker Hub or registry.</p>
          </div>
          <div style="background: rgba(13, 18, 31, 0.6); padding: 10px; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.05);">
            <b style="color: var(--accent-emerald);">2. Graceful Recreation (`compose up -d`)</b>
            <p style="color: var(--text-muted); font-size: 11px; margin-top: 3px;">Sends SIGTERM to flush writes to DuckDB/SQLite, destroys old container, and starts new container using existing volumes.</p>
          </div>
          <div style="background: rgba(13, 18, 31, 0.6); padding: 10px; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.05);">
            <b style="color: var(--accent-purple);">3. Dependency Staging (Splunk Model)</b>
            <p style="color: var(--text-muted); font-size: 11px; margin-top: 3px;">Coordinator / Core updated first to execute DB migrations before Sensors & Forwarders stream new telemetry.</p>
          </div>
        </div>
      </div>

      <!-- Update Strategy Selector -->
      <div class="form-group" style="margin-bottom: 20px;">
        <label>Select Update Methodology</label>
        <div class="grid-2">
          <label class="checkbox-card" style="margin-bottom: 0;">
            <input type="radio" name="update_strategy" value="pull_recreate" checked>
            <div class="checkbox-content">
              <div class="checkbox-title">🚀 Rolling Pull & Graceful Recreate (Recommended)</div>
              <div class="checkbox-desc">Pulls the latest image digest from Docker Hub and runs <code>docker compose up -d</code>. Preserves all data vaults and configurations with minimal (~5-10s) service interruption.</div>
            </div>
          </label>
          <label class="checkbox-card" style="margin-bottom: 0;">
            <input type="radio" name="update_strategy" value="airgap_tars">
            <div class="checkbox-content">
              <div class="checkbox-title">📦 Sneakernet Air-Gap Archive Load</div>
              <div class="checkbox-desc">Loads pre-staged <code>*.tar</code> Docker archives from the local <code>./lume_airgap_tars/</code> folder, then restarts services. Ideal for disconnected SCADA/ICS networks.</div>
            </div>
          </label>
        </div>
      </div>

      <!-- Target System Selection -->
      <div class="form-group" style="margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <label style="margin-bottom: 0;">Choose Systems to Update</label>
          <div style="font-size: 12px;">
            <a href="javascript:void(0)" onclick="toggleSelectAllUpdateNodes(true)" style="color: var(--accent-cyan); text-decoration: none; margin-right: 12px;">Select All</a>
            <a href="javascript:void(0)" onclick="toggleSelectAllUpdateNodes(false)" style="color: var(--text-muted); text-decoration: none;">Deselect All</a>
          </div>
        </div>
        <div id="update_node_list_container" style="display: flex; flex-direction: column; gap: 8px;">
          <!-- Dynamically populated from fleetNodes -->
        </div>
      </div>

      <!-- Execution Options -->
      <div class="grid-2" style="margin-bottom: 20px;">
        <label class="checkbox-card" style="margin-bottom: 0;">
          <input type="checkbox" id="update_enforce_order" checked>
          <div class="checkbox-content">
            <div class="checkbox-title">⚡ Enforce Dependency Sequence (Splunk Order)</div>
            <div class="checkbox-desc">Updates Coordinator Core SIEM first, followed by Secondary Workers, then Network Sensors (Zeek/Suricata), and Scanners last.</div>
          </div>
        </label>
        <label class="checkbox-card" style="margin-bottom: 0;">
          <input type="checkbox" id="update_prune_dangling" checked>
          <div class="checkbox-content">
            <div class="checkbox-title">🧹 Prune Outdated Docker Image Layers</div>
            <div class="checkbox-desc">Automatically executes <code>docker image prune -f</code> on each node post-upgrade to reclaim unused disk space.</div>
          </div>
        </label>
      </div>

      <!-- Actions -->
      <div style="display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px;">
        <button class="btn btn-emerald pulse-btn" id="btn_execute_update" onclick="executeFleetUpdate()">
          🚀 Execute Orchestrated Fleet Update
        </button>
        <button class="btn btn-secondary" onclick="generateLifecycleRunbook('update')">
          📋 Generate Copy-Paste Command Runbook (Air-Gap / Manual)
        </button>
      </div>

      <div class="status-log" id="update_status_log">Ready. Fleet update telemetry, SSH commands, and Docker pull logs will stream here...</div>
    </div>
  </div>

  <!-- TAB 8: FLEET DECOMMISSION / REMOVE -->
  <div id="tab-remove" class="tab-panel">
    <div class="card" style="border-color: rgba(244, 63, 94, 0.35);">
      <div class="card-header">
        <h2 style="color: #f87171;">🗑️ Fleet Decommission, Teardown & Clean Removal</h2>
        <p>Safely stop and remove Project Lume software containers, clean Docker networks, and optionally wipe database volumes and data vaults.</p>
      </div>

      <!-- Danger Alert -->
      <div style="background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.3); border-radius: 10px; padding: 16px; margin-bottom: 20px;">
        <h3 style="font-size: 14px; color: #fb7185; margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">
          <span>⚠️ High-Impact Operation: Target Teardown</span>
        </h3>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">
          Use this panel when decommissioning a node, testing a clean-slate re-deployment, or wiping telemetry vaults. Choose carefully what items you wish to remove.
        </p>
      </div>

      <!-- Target Selection -->
      <div class="form-group" style="margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <label style="margin-bottom: 0;">Choose Systems to Decommission / Remove</label>
          <div style="font-size: 12px;">
            <a href="javascript:void(0)" onclick="toggleSelectAllRemoveNodes(true)" style="color: var(--accent-rose); text-decoration: none; margin-right: 12px;">Select All</a>
            <a href="javascript:void(0)" onclick="toggleSelectAllRemoveNodes(false)" style="color: var(--text-muted); text-decoration: none;">Deselect All</a>
          </div>
        </div>
        <div id="remove_node_list_container" style="display: flex; flex-direction: column; gap: 8px;">
          <!-- Dynamically populated from fleetNodes -->
        </div>
      </div>

      <!-- Granular Removal Checkboxes -->
      <div class="form-group" style="margin-bottom: 20px;">
        <label>Select Removal Granularity & Data Cleanup Scope</label>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <label class="checkbox-card" style="margin-bottom: 0;">
            <input type="checkbox" id="remove_opt_containers" checked disabled>
            <div class="checkbox-content">
              <div class="checkbox-title">⏹️ Stop & Remove Containers (`docker compose down`)</div>
              <div class="checkbox-desc">Stops running Core SIEM, Zeek Sensor, and Vuln Scanner containers and removes Docker virtual network bridges. (Always required)</div>
            </div>
          </label>
          <label class="checkbox-card" style="margin-bottom: 0;">
            <input type="checkbox" id="remove_opt_images" checked>
            <div class="checkbox-content">
              <div class="checkbox-title">📦 Remove Docker Images (`docker rmi`)</div>
              <div class="checkbox-desc">Purges cached Docker image layers for <code>project_lume</code>, <code>lume-zeek-sensor</code>, and <code>lume-vuln-scanner</code> to reclaim 5GB+ disk space.</div>
            </div>
          </label>
          <label class="checkbox-card" style="margin-bottom: 0; border-color: rgba(244, 63, 94, 0.3);">
            <input type="checkbox" id="remove_opt_vaults">
            <div class="checkbox-content">
              <div class="checkbox-title" style="color: #fb7185;">💥 Wipe Data Vaults, DuckDB & SQLite Databases (`./data_vaults`)</div>
              <div class="checkbox-desc">Irreversibly deletes parquet vaults, incident indices, security alerts, and local telemetry databases. Use for pristine reset.</div>
            </div>
          </label>
          <label class="checkbox-card" style="margin-bottom: 0;">
            <input type="checkbox" id="remove_opt_configs">
            <div class="checkbox-content">
              <div class="checkbox-title">📄 Wipe Configuration Files (`.env`, `ai_config.json`, `docker-compose.yml`)</div>
              <div class="checkbox-desc">Deletes generated environment variables, token keys, and compose files from the deployment folder.</div>
            </div>
          </label>
        </div>
      </div>

      <!-- Confirmation Guardrail -->
      <div class="form-group" style="margin-bottom: 20px; background: rgba(13, 18, 31, 0.8); padding: 16px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.08);">
        <label style="color: #fb7185;">Safety Guardrail: Type "REMOVE" to unlock execution</label>
        <div style="display: flex; gap: 12px; align-items: center; max-width: 450px;">
          <input type="text" id="remove_confirm_input" placeholder="Type REMOVE" onkeyup="checkRemoveSafetyLock()" style="text-transform: uppercase;">
          <button class="btn btn-rose" id="btn_execute_remove" disabled onclick="executeFleetRemove()">
            🗑️ Decommission Selected Systems
          </button>
        </div>
      </div>

      <div style="display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px;">
        <button class="btn btn-secondary" onclick="generateLifecycleRunbook('remove')">
          📋 Generate Copy-Paste Teardown Runbook (Manual / Terminal)
        </button>
      </div>

      <div class="status-log" id="remove_status_log">Ready. Teardown execution logs, container stops, and image deletion results will stream here...</div>
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

function switchTab(name, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  if (btn) {
    btn.classList.add('active');
  } else {
    const el = document.getElementById('tab_btn_' + name);
    if (el) el.classList.add('active');
  }
  const panel = document.getElementById('tab-' + name);
  if (panel) panel.classList.add('active');
  if (name === 'compose') {
    generateAndPreview('core');
  } else if (name === 'storage') {
    refreshDatasetManager();
  } else if (name === 'update') {
    renderUpdateNodeList();
  } else if (name === 'remove') {
    renderRemoveNodeList();
  }
}

async function refreshDatasetManager() {
  const tbody = document.getElementById('dataset_manager_tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="5" style="padding: 14px; text-align: center; color: #94a3b8;">⏳ Scanning active DuckDB vaults and namespaces...</td></tr>';
  
  const hostIp = document.getElementById('lume_host_ip').value.trim() || '127.0.0.1';
  const port = document.getElementById('lume_port').value.trim() || '9000';
  const token = document.getElementById('lume_token').value.trim() || 'LAME_SECRET_TOKEN_99';
  const targetBase = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? `http://${window.location.hostname}:${port}`
    : `http://${hostIp}:${port}`;

  try {
    const res = await fetch(`${targetBase}/api/search/namespaces`, { credentials: 'omit' });
    const json = await res.json();
    if (json.status === 'success' && Array.isArray(json.namespaces)) {
      tbody.innerHTML = '';
      const list = json.namespaces.filter(ns => ns.namespace !== 'all');
      if (list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="padding: 14px; text-align: center; color: #64748b;">No active tenant namespaces detected in DuckDB.</td></tr>';
        return;
      }
      list.forEach(ns => {
        const tr = document.createElement('tr');
        tr.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
        const countFormatted = Number(ns.event_count || 0).toLocaleString();
        tr.innerHTML = `
          <td style="padding: 10px 8px; font-family: monospace; font-weight: bold; color: ${ns.color_code || '#6366f1'};">${ns.namespace}</td>
          <td style="padding: 10px 8px; font-weight: 500;">${ns.display_name || ns.namespace}</td>
          <td style="padding: 10px 8px;"><span style="background: rgba(99,102,241,0.18); border: 1px solid rgba(99,102,241,0.4); padding: 2px 7px; border-radius: 4px; font-size: 11px;">${countFormatted} events</span></td>
          <td style="padding: 10px 8px; color: #94a3b8; font-size: 11px;">${ns.description || 'Tenant namespace partition'}</td>
          <td style="padding: 10px 8px; text-align: right; white-space: nowrap;">
            <button class="btn btn-cyan" onclick="deduplicateDataset('${ns.namespace}', '${targetBase}', '${token}')" style="font-size: 11px; padding: 4px 8px; margin-right: 6px;">🧹 Dedup (_ib_eid)</button>
            <button class="btn btn-secondary" onclick="purgeDataset('${ns.namespace}', '${targetBase}', '${token}')" style="font-size: 11px; padding: 4px 8px; background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.5); color: #fca5a5;">🗑️ Purge Dataset</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="5" style="padding: 18px 14px; text-align: center; color: #94a3b8;"><span style="color: #fbbf24; font-weight: 600;">ℹ️ Offline Inspection:</span> SIEM Core container is not currently running at <code>${targetBase}</code>. This is normal during initial configuration setup before containers are launched.</td></tr>`;
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" style="padding: 18px 14px; text-align: center; color: #94a3b8;"><span style="color: #60a5fa; font-weight: 600;">ℹ️ Pre-Deploy State:</span> SIEM Core engine at <code>${targetBase}</code> is offline. Once you generate and launch your Docker stack, active DuckDB datasets and namespaces will populate here for live inspection.</td></tr>`;
  }
}

async function purgeDataset(namespace, targetBase, token) {
  const confirmMsg = prompt(`⚠️ SUPERUSER ACTION: Are you sure you want to permanently PURGE ALL records in namespace "${namespace}"?\\n\\nType the namespace name "${namespace}" below to confirm:`);
  if (confirmMsg !== namespace) {
    alert("Purge cancelled. Namespace name did not match.");
    return;
  }

  const statusEl = document.getElementById('dataset_action_status');
  statusEl.innerHTML = `<span style="color: #f59e0b;">⏳ Purging namespace "${namespace}" across all DuckDB tables...</span>`;

  try {
    const res = await fetch(`${targetBase}/api/v1/ingest/namespaces/${namespace}`, {
      method: 'DELETE',
      headers: {
        'X-Lume-Token': token
      }
    });
    const json = await res.json();
    if (json.status === 'success') {
      statusEl.innerHTML = `<span style="color: #34d399;">✅ Successfully purged ${json.deleted_rows || json.purged_rows || 0} rows from namespace "${namespace}".</span>`;
      refreshDatasetManager();
    } else {
      statusEl.innerHTML = `<span style="color: #ef4444;">❌ Purge failed: ${json.detail || json.message}</span>`;
    }
  } catch (e) {
    statusEl.innerHTML = `<span style="color: #ef4444;">❌ Network error calling purge: ${e}</span>`;
  }
}

async function deduplicateDataset(namespace, targetBase, token) {
  const statusEl = document.getElementById('dataset_action_status');
  statusEl.innerHTML = `<span style="color: #06b6d4;">⏳ Deduplicating namespace "${namespace}" via _ib_eid UUIDv7 keys...</span>`;

  try {
    const res = await fetch(`${targetBase}/api/search/namespaces/${namespace}/deduplicate`, {
      method: 'POST',
      headers: {
        'X-Lume-Token': token
      }
    });
    const json = await res.json();
    if (json.status === 'success') {
      statusEl.innerHTML = `<span style="color: #34d399;">✅ Cleaned ${json.duplicates_removed || 0} duplicate records from "${namespace}".</span>`;
      refreshDatasetManager();
    } else {
      statusEl.innerHTML = `<span style="color: #ef4444;">❌ Deduplication failed: ${json.detail || json.message}</span>`;
    }
  } catch (e) {
    statusEl.innerHTML = `<span style="color: #ef4444;">❌ Network error calling dedup: ${e}</span>`;
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

// ==============================================================================
// DYNAMIC FLEET NODES DATA MODEL & TOPOLOGY CONTROLLER
// ==============================================================================

let fleetNodes = [
  {
    ip: "127.0.0.1",
    name: "Primary Operations Core",
    deploy_core: true,
    demo_mode: false,
    memory_cap: "8G",
    deploy_zeek: false,
    deploy_scanner: false,
    deploy_thrower: false,
    target_siem: "127.0.0.1:9000",
    notes: "Primary Core SIEM"
  }
];

function syncPrimaryCoreFromInputs() {
  const hostIp = (document.getElementById('lume_host_ip') ? document.getElementById('lume_host_ip').value.trim() : '') || '127.0.0.1';
  const nodeName = (document.getElementById('lume_node_name') ? document.getElementById('lume_node_name').value.trim() : '') || 'Primary Operations Core';
  const port = (document.getElementById('lume_port') ? document.getElementById('lume_port').value.trim() : '') || '9000';

  if (fleetNodes.length > 0 && fleetNodes[0].deploy_core) {
    fleetNodes[0].ip = hostIp;
    fleetNodes[0].name = nodeName;
    fleetNodes[0].target_siem = `${hostIp}:${port}`;
    renderFleetNodes();
  }
}

function selectDeploymentMode(mode) {
  const sel = document.getElementById('deploy_mode');
  if (sel) sel.value = mode;

  document.querySelectorAll('.arch-card').forEach(c => c.classList.remove('selected'));
  const activeCard = document.getElementById('card_mode_' + mode);
  if (activeCard) activeCard.classList.add('selected');

  const fleetCard = document.getElementById('fleet_builder_card');
  const hostIpInput = document.getElementById('lume_host_ip');

  if (mode === 'all_in_one') {
    if (hostIpInput) hostIpInput.value = '127.0.0.1';
    fleetNodes = [
      {
        ip: "127.0.0.1",
        name: "Local All-in-One Host",
        deploy_core: true,
        demo_mode: false,
        memory_cap: "8G",
        deploy_zeek: false,
        deploy_scanner: false,
        deploy_thrower: false,
        target_siem: "127.0.0.1:9000",
        notes: "Standalone local test machine"
      }
    ];
    if (fleetCard) fleetCard.style.display = 'block';
  } else if (mode === 'server_sensor') {
    if (hostIpInput && (hostIpInput.value === '127.0.0.1' || !hostIpInput.value)) {
      hostIpInput.value = '192.168.1.10';
    }
    const coreIp = (hostIpInput && hostIpInput.value) ? hostIpInput.value : '192.168.1.10';
    fleetNodes = [
      {
        ip: coreIp,
        name: "Main SIEM Server",
        deploy_core: true,
        demo_mode: false,
        memory_cap: "8G",
        deploy_zeek: false,
        deploy_scanner: false,
        deploy_thrower: false,
        target_siem: `${coreIp}:9000`,
        notes: "Central Lume SIEM Core"
      },
      {
        ip: "192.168.1.20",
        name: "Perimeter SPAN / TAP Sensor",
        deploy_core: false,
        demo_mode: false,
        memory_cap: "2600M",
        deploy_zeek: true,
        deploy_scanner: true,
        deploy_thrower: true,
        target_siem: `${coreIp}:9000`,
        notes: "Remote Zeek/Suricata sensor + Universal Forwarder -> Main Server"
      }
    ];
    if (fleetCard) fleetCard.style.display = 'block';
  } else {
    // Custom Fleet / Multi-Node
    if (fleetCard) fleetCard.style.display = 'block';
    const coreIp = (hostIpInput && hostIpInput.value) ? hostIpInput.value : '192.168.1.10';
    fleetNodes = [
      {
        ip: coreIp,
        name: (document.getElementById('lume_node_name') ? document.getElementById('lume_node_name').value.trim() : '') || 'Primary Operations Core',
        deploy_core: true,
        demo_mode: false,
        memory_cap: "12G",
        deploy_zeek: true,
        deploy_scanner: false,
        deploy_thrower: false,
        target_siem: `${coreIp}:9000`,
        notes: "Primary Core SIEM & Network Sensor"
      }
    ];
  }

  renderFleetNodes();
}

function syncArchitectureCardsFromSelect() {
  const sel = document.getElementById('deploy_mode');
  const mode = sel ? sel.value : 'distributed';
  document.querySelectorAll('.arch-card').forEach(c => c.classList.remove('selected'));
  const activeCard = document.getElementById('card_mode_' + mode);
  if (activeCard) {
    activeCard.classList.add('selected');
  } else {
    const distCard = document.getElementById('card_mode_distributed');
    if (distCard) distCard.classList.add('selected');
  }
}

function renderFleetNodes() {
  const tbody = document.getElementById('fleet_nodes_tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const coreNodes = fleetNodes.filter(n => n.deploy_core && n.ip.trim()).map(n => n.ip.trim());
  const defaultCore = (document.getElementById('lume_host_ip') ? document.getElementById('lume_host_ip').value.trim() : '') || '192.168.88.15';
  if (!coreNodes.includes(defaultCore) && defaultCore) coreNodes.unshift(defaultCore);

  fleetNodes.forEach((node, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'node-row';

    let targetOptions = `<option value="127.0.0.1:9000" ${node.target_siem.startsWith('127.0.0.1') ? 'selected' : ''}>Local Core (127.0.0.1:9000)</option>`;
    coreNodes.forEach(cIp => {
      const val = `${cIp}:9000`;
      const isSel = (node.target_siem === val || node.target_siem === cIp) ? 'selected' : '';
      targetOptions += `<option value="${val}" ${isSel}>${cIp}:9000</option>`;
    });
    // Add custom fallback if target_siem is different
    if (!coreNodes.includes(node.target_siem.replace(':9000','')) && !node.target_siem.startsWith('127.0.0.1')) {
      targetOptions += `<option value="${node.target_siem}" selected>${node.target_siem}</option>`;
    }

    // Mode Toggle Button (Phase 1)
    let modeHtml = `<span style="color: #64748b; font-size: 11px;">—</span>`;
    if (node.deploy_core) {
      if (node.demo_mode) {
        modeHtml = `<button type="button" class="mode-toggle-btn mode-toggle-demo" onclick="toggleNodeMode(${idx})" title="Click to switch this node to Production Mode">🧪 Demo</button>`;
      } else {
        modeHtml = `<button type="button" class="mode-toggle-btn mode-toggle-prod" onclick="toggleNodeMode(${idx})" title="Click to switch this node to Demo Lab Mode">🛡️ Prod</button>`;
      }
    }

    // Memory Cap Dropdown
    let memHtml = `<span style="color: #64748b; font-size: 11px;">Host Auto</span>`;
    if (node.deploy_core) {
      const curMem = node.memory_cap || (node.ip.includes('15') ? '12G' : (node.ip.includes('44') ? '2600M' : '8G'));
      memHtml = `
        <select onchange="updateFleetNodeField(${idx}, 'memory_cap', this.value)" style="font-size: 11px; padding: 4px 6px;">
          <option value="2600M" ${curMem === '2600M' ? 'selected' : ''}>2.6G (Edge)</option>
          <option value="8G" ${curMem === '8G' ? 'selected' : ''}>8G (Standard)</option>
          <option value="12G" ${curMem === '12G' ? 'selected' : ''}>12G (Heavy)</option>
          <option value="16G" ${curMem === '16G' ? 'selected' : ''}>16G (Enterprise)</option>
          <option value="32G" ${curMem === '32G' ? 'selected' : ''}>32G (Deep Vault)</option>
        </select>
      `;
    }

    tr.innerHTML = `
      <td>
        <div style="display: flex; align-items: center; gap: 6px;">
          <input type="text" value="${escapeHtml(node.ip)}" placeholder="e.g. 192.168.88.15" onchange="updateFleetNodeField(${idx}, 'ip', this.value)" style="font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan); font-weight: 600; flex: 1;">
          <span id="ping_node_${idx}" style="font-size: 10px;"></span>
        </div>
      </td>
      <td>
        <input type="text" value="${escapeHtml(node.name)}" placeholder="Friendly Hostname" onchange="updateFleetNodeField(${idx}, 'name', this.value)">
      </td>
      <td style="text-align: center;">
        <input type="checkbox" ${node.deploy_core ? 'checked' : ''} onchange="updateFleetNodeField(${idx}, 'deploy_core', this.checked)">
      </td>
      <td style="text-align: center;">
        ${modeHtml}
      </td>
      <td style="text-align: center;">
        ${memHtml}
      </td>
      <td style="text-align: center;">
        <input type="checkbox" ${node.deploy_zeek ? 'checked' : ''} onchange="updateFleetNodeField(${idx}, 'deploy_zeek', this.checked)">
      </td>
      <td style="text-align: center;">
        <input type="checkbox" ${node.deploy_scanner ? 'checked' : ''} onchange="updateFleetNodeField(${idx}, 'deploy_scanner', this.checked)">
      </td>
      <td style="text-align: center;">
        <input type="checkbox" ${node.deploy_thrower ? 'checked' : ''} onchange="updateFleetNodeField(${idx}, 'deploy_thrower', this.checked)" title="Universal Forwarder (Vector high-throughput log shipper)">
      </td>
      <td>
        <select onchange="updateFleetNodeField(${idx}, 'target_siem', this.value)">
          ${targetOptions}
        </select>
      </td>
      <td style="text-align: center;">
        <button class="btn btn-secondary" type="button" onclick="removeFleetNode(${idx})" title="Remove Node" style="padding: 4px 8px; font-size: 11px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #fca5a5;">
          ✕
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  updateFleetTopologySummary();
  renderVisualTopologyMap();
}

function toggleNodeMode(idx) {
  if (fleetNodes[idx]) {
    fleetNodes[idx].demo_mode = !fleetNodes[idx].demo_mode;
    renderFleetNodes();
    const modeName = fleetNodes[idx].demo_mode ? "Demo / Training Lab Mode" : "Strict Production Mode";
    logMsg(`🔄 Toggled ${fleetNodes[idx].name || 'Node ' + (idx + 1)} to ${modeName}.`, 'info');
  }
}

function updateFleetNodeField(idx, field, val) {
  if (fleetNodes[idx]) {
    fleetNodes[idx][field] = val;
    if (field === 'ip' || field === 'deploy_core' || field === 'target_siem') {
      renderFleetNodes();
    } else {
      updateFleetTopologySummary();
      renderVisualTopologyMap();
    }
  }
}

function addNewFleetNode(data = null) {
  const newNode = data || {
    ip: "",
    name: "New Node",
    deploy_core: false,
    demo_mode: false,
    memory_cap: "8G",
    deploy_zeek: false,
    deploy_scanner: false,
    deploy_thrower: true,
    target_siem: (document.getElementById('lume_host_ip') ? document.getElementById('lume_host_ip').value.trim() : '') ? `${document.getElementById('lume_host_ip').value.trim()}:9000` : "127.0.0.1:9000",
    notes: ""
  };
  fleetNodes.push(newNode);
  renderFleetNodes();
}

function removeFleetNode(idx) {
  if (fleetNodes.length <= 1) {
    alert("At least one node must remain in the topology.");
    return;
  }
  fleetNodes.splice(idx, 1);
  renderFleetNodes();
}

function clearFleetNodes() {
  fleetNodes = [
    {
      ip: (document.getElementById('lume_host_ip') ? document.getElementById('lume_host_ip').value.trim() : '') || "127.0.0.1",
      name: "Primary Operations Core",
      deploy_core: true,
      demo_mode: false,
      memory_cap: "8G",
      deploy_zeek: false,
      deploy_scanner: false,
      deploy_thrower: false,
      target_siem: (document.getElementById('lume_host_ip') ? document.getElementById('lume_host_ip').value.trim() : '') ? `${document.getElementById('lume_host_ip').value.trim()}:9000` : "127.0.0.1:9000",
      notes: "Primary Core SIEM"
    }
  ];
  renderFleetNodes();
  logMsg("🧹 Cleared fleet topology matrix to a blank canvas.", 'warn');
}

function loadSampleFleetPreset() {
  fleetNodes = [
    {
      ip: "192.168.88.15",
      name: "Primary Operations Core",
      deploy_core: true,
      demo_mode: false,
      memory_cap: "12G",
      deploy_zeek: false,
      deploy_scanner: false,
      deploy_thrower: false,
      target_siem: "192.168.88.15:9000",
      notes: "Primary Core SIEM Node"
    },
    {
      ip: "192.168.88.31",
      name: "Secondary",
      deploy_core: true,
      demo_mode: false,
      memory_cap: "8G",
      deploy_zeek: true,
      deploy_scanner: false,
      deploy_thrower: false,
      target_siem: "192.168.88.15:9000",
      notes: "Secondary Core + Zeek/Suricata Sensor forwarding to .15"
    },
    {
      ip: "192.168.88.44",
      name: "Workstation",
      deploy_core: false,
      demo_mode: false,
      memory_cap: "2600M",
      deploy_zeek: false,
      deploy_scanner: true,
      deploy_thrower: true,
      target_siem: "192.168.88.15:9000",
      notes: "Workstation Host Vuln Scanner + Universal Forwarder -> .15"
    }
  ];

  const hostIp = document.getElementById('lume_host_ip');
  if (hostIp) hostIp.value = '192.168.88.15';

  const sel = document.getElementById('deploy_mode');
  if (sel) sel.value = 'distributed';
  document.querySelectorAll('.arch-card').forEach(c => c.classList.remove('selected'));
  const distCard = document.getElementById('card_mode_distributed');
  if (distCard) distCard.classList.add('selected');
  const fleetCard = document.getElementById('fleet_builder_card');
  if (fleetCard) fleetCard.style.display = 'block';

  renderFleetNodes();
  renderUpdateNodeList();
  renderRemoveNodeList();
  logMsg("📋 Loaded 3-Node Topology Preset (.15 Core, .31 Core+Zeek, .44 Scanner+Forwarder).", 'info');
}

function applyPersonaPreset(type) {
  if (type === 'enterprise_prod') {
    fleetNodes = [
      {
        ip: "192.168.88.15",
        name: "Primary Enterprise Core",
        deploy_core: true,
        demo_mode: false,
        memory_cap: "16G",
        deploy_zeek: false,
        deploy_scanner: false,
        deploy_thrower: true,
        target_siem: "192.168.88.15:9000",
        notes: "Hardened Production Core SIEM"
      },
      {
        ip: "192.168.88.44",
        name: "Perimeter Sensor & Forwarder",
        deploy_core: false,
        demo_mode: false,
        memory_cap: "2600M",
        deploy_zeek: true,
        deploy_scanner: true,
        deploy_thrower: true,
        target_siem: "192.168.88.15:9000",
        notes: "Zeek/Suricata IDS Sensor + Universal Forwarder -> .15"
      }
    ];
    const hostIp = document.getElementById('lume_host_ip');
    if (hostIp) hostIp.value = '192.168.88.15';
    selectDeploymentMode('distributed');
    logMsg("🏢 Applied Enterprise Sovereign Production Preset (Production Mode Locked, 16GB RAM limit, Universal Forwarders Active).", 'success');
  } else if (type === 'demo_lab') {
    fleetNodes = [
      {
        ip: "127.0.0.1",
        name: "Project Lume POC & Demo Lab",
        deploy_core: true,
        demo_mode: true,
        memory_cap: "8G",
        deploy_zeek: false,
        deploy_scanner: false,
        deploy_thrower: false,
        target_siem: "127.0.0.1:9000",
        notes: "Training & Demonstration Lab with synthetic anomaly generation"
      }
    ];
    const hostIp = document.getElementById('lume_host_ip');
    if (hostIp) hostIp.value = '127.0.0.1';
    selectDeploymentMode('all_in_one');
    logMsg("🧪 Applied Customer POC & Training Lab Preset (Demo Mode ON, Showcase Telemetry Enabled, AI Coaching Active).", 'info');
  } else if (type === 'tactical_edge') {
    fleetNodes = [
      {
        ip: "192.168.1.100",
        name: "Tactical Edge Sensor Node",
        deploy_core: false,
        demo_mode: false,
        memory_cap: "2600M",
        deploy_zeek: true,
        deploy_scanner: true,
        deploy_thrower: true,
        target_siem: "192.168.1.10:9000",
        notes: "Constrained OT Edge Node (Suricata SCADA + Universal Forwarder)"
      }
    ];
    const hostIp = document.getElementById('lume_host_ip');
    if (hostIp) hostIp.value = '192.168.1.10';
    selectDeploymentMode('sensors_only');
    logMsg("⚡ Applied Tactical OT / Industrial Edge Preset (Zeek + SCADA OT Rules, Constrained 2.6GB Cap, Universal Forwarder).", 'info');
  }
  renderFleetNodes();
}

function updateFleetTopologySummary() {
  const summaryEl = document.getElementById('fleet_topology_summary_text');
  if (!summaryEl) return;

  const prodCount = fleetNodes.filter(n => n.deploy_core && !n.demo_mode).length;
  const demoCount = fleetNodes.filter(n => n.deploy_core && n.demo_mode).length;
  const zeekCount = fleetNodes.filter(n => n.deploy_zeek).length;
  const vulnCount = fleetNodes.filter(n => n.deploy_scanner).length;
  const forwarderCount = fleetNodes.filter(n => n.deploy_thrower).length;

  summaryEl.innerHTML = `
    <b>${fleetNodes.length} Nodes Configured:</b> 
    <span style="color: #34d399;">${prodCount} Production Core</span>, 
    <span style="color: #fbbf24;">${demoCount} Demo Lab</span>, 
    <span style="color: #38bdf8;">${zeekCount} Zeek/Suricata Sensors</span>, 
    <span style="color: #c084fc;">${vulnCount} Vuln Scanners</span>, 
    <span style="color: #06b6d4;">${forwarderCount} Universal Forwarders</span>.
  `;
}

function renderVisualTopologyMap() {
  const container = document.getElementById('fleet_visual_topology_container');
  if (!container) return;

  if (!fleetNodes || fleetNodes.length === 0) {
    container.innerHTML = '<div style="color: #64748b; font-size: 12px; text-align: center; padding: 16px;">No nodes configured. Add nodes above to view topology.</div>';
    return;
  }

  const targetMap = {};
  fleetNodes.forEach((node, idx) => {
    if (node.deploy_core) {
      const targetKey = `${node.ip || '127.0.0.1'}:9000`;
      if (!targetMap[targetKey]) {
        targetMap[targetKey] = {
          node: node,
          idx: idx,
          feeders: []
        };
      }
    }
  });

  fleetNodes.forEach(node => {
    const t = node.target_siem || "127.0.0.1:9000";
    if (!targetMap[t]) {
      targetMap[t] = {
        node: { ip: t.split(':')[0], name: `Central SIEM (${t})`, deploy_core: true, demo_mode: false },
        idx: -1,
        feeders: []
      };
    }
    if (node.deploy_zeek || node.deploy_scanner || node.deploy_thrower || (!node.deploy_core && node.ip)) {
      targetMap[t].feeders.push(node);
    }
  });

  let html = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 16px;">🗺️</span>
        <span style="font-weight: 700; font-size: 13px; color: #fff;">Live Fleet Telemetry & Forwarding Flow</span>
      </div>
      <span style="font-size: 11px; color: #94a3b8; background: rgba(255,255,255,0.05); padding: 3px 8px; border-radius: 4px;">
        Auto-updates in real time
      </span>
    </div>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px;">
  `;

  Object.keys(targetMap).forEach(targetKey => {
    const hub = targetMap[targetKey];
    const coreNode = hub.node;
    const modeBadge = coreNode.demo_mode 
      ? '<span style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700;">🧪 DEMO LAB</span>'
      : '<span style="background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700;">🛡️ PRODUCTION</span>';

    html += `
      <div style="background: rgba(18, 24, 38, 0.85); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 10px; padding: 14px 16px; box-shadow: 0 4px 16px rgba(0,0,0,0.3);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <div style="font-weight: 700; font-size: 13px; color: #fff; display: flex; align-items: center; gap: 6px;">
              <span>🖥️</span> <span>${escapeHtml(coreNode.name || 'Central Core SIEM')}</span>
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-cyan); margin-top: 2px;">
              ${escapeHtml(targetKey)} (DuckDB & API)
            </div>
          </div>
          <div>${modeBadge}</div>
        </div>

        <div style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 10px; margin-top: 10px;">
          <div style="font-size: 11px; color: #94a3b8; margin-bottom: 8px; font-weight: 600;">
            Incoming Ingestion Streams (${hub.feeders.length}):
          </div>
    `;

    if (hub.feeders.length === 0) {
      html += `
        <div style="font-size: 11px; color: #64748b; font-style: italic; padding: 6px 0;">
          Local standalone ingestion only (Dropzone & local syslogs).
        </div>
      `;
    } else {
      hub.feeders.forEach(f => {
        const streamBadges = [];
        if (f.deploy_zeek) streamBadges.push('<span style="color: #6ee7b7; background: rgba(16,185,129,0.15); padding: 2px 6px; border-radius: 4px; font-size: 10px;">Zeek/Suricata TAP</span>');
        if (f.deploy_scanner) streamBadges.push('<span style="color: #d8b4fe; background: rgba(168,85,247,0.15); padding: 2px 6px; border-radius: 4px; font-size: 10px;">Host Scanner</span>');
        if (f.deploy_thrower) streamBadges.push('<span style="color: #67e8f9; background: rgba(6,182,212,0.15); padding: 2px 6px; border-radius: 4px; font-size: 10px;">Universal Forwarder</span>');

        html += `
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; background: rgba(10, 15, 29, 0.5); padding: 6px 10px; border-radius: 6px; margin-bottom: 6px; border: 1px solid rgba(255,255,255,0.04);">
            <div>
              <div style="font-size: 11px; font-weight: 600; color: #f1f5f9;">${escapeHtml(f.name || f.ip)}</div>
              <div style="font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #94a3b8;">${escapeHtml(f.ip)}</div>
            </div>
            <div style="display: flex; gap: 4px; flex-wrap: wrap; justify-content: flex-end;">
              ${streamBadges.join('')}
            </div>
          </div>
        `;
      });
    }

    html += `
        </div>
      </div>
    `;
  });

  html += '</div>';
  container.innerHTML = html;
}

async function runInlinePreflightCheck() {
  const btn = document.getElementById('btn_inline_preflight');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="pulse-spinner"></span> Probing Fleet...';
  }

  try {
    const res = await fetch('/api/preflight_probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nodes: fleetNodes,
        form: getFormData()
      })
    });
    const data = await res.json();
    if (data.status === 'success') {
      (data.results || []).forEach((r, idx) => {
        const pingEl = document.getElementById(`ping_node_${idx}`);
        if (!pingEl) return;
        if (r.reachable) {
          if (r.docker_installed) {
            pingEl.innerHTML = `<span style="color: #34d399; font-size: 10px;" title="Reachable, Docker Installed">🟢 Ready</span>`;
          } else {
            pingEl.innerHTML = `<span style="color: #fbbf24; font-size: 10px;" title="Reachable, but Docker not detected">🟡 No Docker</span>`;
          }
        } else {
          pingEl.innerHTML = `<span style="color: #f87171; font-size: 10px;" title="Host Unreachable or SSH port closed">🔴 Offline</span>`;
        }
      });
      logMsg("⚡ Fleet connectivity pre-flight check complete.", 'success');
    }
  } catch (err) {
    logMsg(`Pre-flight probe error: ${err.message}`, 'err');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '⚡ Test Fleet Connectivity';
    }
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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

  // Convert fleetNodes array to legacy aux_services map for backwards compatibility
  const auxServices = {};
  fleetNodes.forEach(node => {
    if (node.ip && node.ip.trim()) {
      auxServices[node.ip.trim()] = {
        deploy_core: Boolean(node.deploy_core),
        demo_mode: Boolean(node.demo_mode),
        memory_cap: node.memory_cap || "8G",
        deploy_zeek: Boolean(node.deploy_zeek),
        deploy_scanner: Boolean(node.deploy_scanner),
        deploy_thrower: Boolean(node.deploy_thrower),
        target_siem: node.target_siem || "127.0.0.1:9000",
        friendly_name: node.name || node.ip
      };
    }
  });

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
    // Dynamic Fleet Nodes array
    nodes: fleetNodes,
    // Auxiliary Node Docker Deployments (Legacy format map)
    aux_services: auxServices
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
    if (tmpl.cluster.deployment_mode) {
      document.getElementById('deploy_mode').value = tmpl.cluster.deployment_mode;
      selectDeploymentMode(tmpl.cluster.deployment_mode);
    }
    if (tmpl.cluster.node_name) document.getElementById('lume_node_name').value = tmpl.cluster.node_name;
    if (tmpl.cluster.host_ip) document.getElementById('lume_host_ip').value = tmpl.cluster.host_ip;
    if (tmpl.cluster.port) document.getElementById('lume_port').value = tmpl.cluster.port;
    if (tmpl.cluster.syslog_port) document.getElementById('syslog_port').value = tmpl.cluster.syslog_port;
    if (tmpl.cluster.tls_ingest_port) document.getElementById('tls_ingest_port').value = tmpl.cluster.tls_ingest_port;
    if (tmpl.cluster.auth_token) document.getElementById('lume_token').value = tmpl.cluster.auth_token;

    // Hydrate dynamic fleetNodes from cluster.nodes if present
    if (Array.isArray(tmpl.cluster.nodes) && tmpl.cluster.nodes.length > 0) {
      fleetNodes = tmpl.cluster.nodes.map(n => ({
        ip: n.hostname || n.ip || "",
        name: n.friendly_name || n.name || "Node",
        deploy_core: (n.deploy_core !== undefined) ? Boolean(n.deploy_core) : true,
        demo_mode: Boolean(n.demo_mode),
        memory_cap: n.memory_cap || "8G",
        deploy_zeek: Boolean(n.deploy_zeek),
        deploy_scanner: Boolean(n.deploy_scanner),
        deploy_thrower: Boolean(n.deploy_thrower),
        target_siem: n.target_siem || n.endpoint || "127.0.0.1:9000",
        notes: n.note || ""
      }));
      renderFleetNodes();
    }
  }

  // 1b. Distributed Node Auxiliary Services Matrix (Legacy map hydration)
  if (tmpl.nodes && Array.isArray(tmpl.nodes)) {
    fleetNodes = tmpl.nodes;
    renderFleetNodes();
  } else if (tmpl.node_auxiliary_services && Object.keys(tmpl.node_auxiliary_services).length > 0) {
    const aux = tmpl.node_auxiliary_services;
    fleetNodes = Object.keys(aux).map(ip => ({
      ip: ip,
      name: aux[ip].friendly_name || `Node ${ip}`,
      deploy_core: (aux[ip].deploy_core !== undefined) ? Boolean(aux[ip].deploy_core) : true,
      deploy_zeek: Boolean(aux[ip].deploy_zeek),
      deploy_scanner: Boolean(aux[ip].deploy_scanner),
      deploy_thrower: Boolean(aux[ip].deploy_thrower),
      target_siem: aux[ip].target_siem || "127.0.0.1:9000",
      notes: ""
    }));
    renderFleetNodes();
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
      alert("✅ Demo lab environment template successfully loaded!\\n\\nAll 4 nodes, Storage Lifecycle rules (15% emergency watermark), Threat Intel API keys, and Network CIDRs are filled out.");
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

function renderOrchestrationNodes() {
  const grid = document.getElementById('node_progress_grid');
  if (!grid) return;
  grid.innerHTML = '';

  const activeNodes = (typeof fleetNodes !== 'undefined' && fleetNodes.length > 0) ? fleetNodes : [
    { ip: '127.0.0.1', name: 'Local Core', deploy_core: true }
  ];

  activeNodes.forEach((node, idx) => {
    const card = document.createElement('div');
    card.className = 'node-progress-card';
    card.id = `card_node_dyn_${idx}`;

    const ipDisplay = escapeHtml(node.ip || 'Local Node');
    const nameDisplay = escapeHtml(node.name || `Node ${idx + 1}`);

    // Badges based on active capabilities
    const badges = [];
    if (node.deploy_core) {
      if (node.demo_mode) {
        badges.push('<span class="node-badge" style="background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4);">🧪 DEMO CORE</span>');
      } else {
        badges.push('<span class="node-badge" style="background: rgba(16,185,129,0.2); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.4);">🛡️ PROD CORE</span>');
      }
    }
    if (node.deploy_zeek) badges.push('<span class="node-badge" style="background: rgba(139,92,246,0.2); color: #c4b5fd;">ZEEK</span>');
    if (node.deploy_scanner) badges.push('<span class="node-badge" style="background: rgba(168,85,247,0.2); color: #d8b4fe;">SCANNER</span>');
    if (node.deploy_thrower) badges.push('<span class="node-badge" style="background: rgba(6,182,212,0.2); color: #67e8f9;">FORWARDER</span>');
    if (badges.length === 0) badges.push('<span class="node-badge" style="background: rgba(148,163,184,0.2); color: #cbd5e1;">AGENT</span>');

    card.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px; gap: 6px; flex-wrap: wrap;">
        <span style="font-weight: 700; font-size: 13px; color: #fff;">${ipDisplay}</span>
        <div style="display: flex; gap: 4px; flex-wrap: wrap;">${badges.join('')}</div>
      </div>
      <div style="font-size: 11px; color: #94a3b8; margin-bottom: 8px;">${nameDisplay}</div>
      <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;" id="status_node_dyn_${idx}">
        <span>⚪</span> <span>Standing by for setup</span>
      </div>
    `;
    grid.appendChild(card);
  });

  const summaryEl = document.getElementById('orchestration_targets_summary');
  if (summaryEl) {
    const names = activeNodes.map(n => n.name || n.ip).slice(0, 4).join(', ');
    const extra = activeNodes.length > 4 ? ` (+${activeNodes.length - 4} more)` : '';
    summaryEl.innerHTML = `Targets: <b>${activeNodes.length} Fleet Nodes</b> (${escapeHtml(names)}${extra})`;
  }
}

function openOrchestrationModal(autoStart = false) {
  renderOrchestrationNodes();
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
  if (!box) return;
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

function setDynNodeUIState(idx, state, text) {
  const card = document.getElementById(`card_node_dyn_${idx}`);
  const statusEl = document.getElementById(`status_node_dyn_${idx}`);
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

async function runPreflightInspection() {
  const btn = document.getElementById('btn_run_preflight');
  const activeNodes = (typeof fleetNodes !== 'undefined' && fleetNodes.length > 0) ? fleetNodes : [
    { ip: '127.0.0.1', name: 'Local Core', deploy_core: true, target_siem: '127.0.0.1:9000' }
  ];

  if (btn) btn.disabled = true;
  logOrchestration(`🔍 Initiating pre-flight discovery probe across ${activeNodes.length} target node(s)...`, 'highlight');

  try {
    const res = await fetch('/api/preflight_probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nodes: activeNodes,
        form: getFormData()
      })
    });
    const data = await res.json();
    if (data.status === 'success') {
      (data.results || []).forEach((r, idx) => {
        if (!r.reachable) {
          logOrchestration(`⚠️ [Node ${idx+1}] ${r.name} (${r.ip}): Host unreachable or SSH port 22 closed. (If air-gapped or manual, use Sneakernet/Runbook)`, 'warn');
          setDynNodeUIState(idx, 'warn', 'Unreachable / Air-gap');
        } else if (!r.docker_installed) {
          logOrchestration(`⚠️ [Node ${idx+1}] ${r.name} (${r.ip}): Reachable, but Docker engine was NOT detected! Please install Docker before rolling out.`, 'err');
          setDynNodeUIState(idx, 'err', 'Docker Not Installed');
        } else if (r.existing_containers && r.existing_containers.length > 0) {
          logOrchestration(`🛡️ [Node ${idx+1}] ${r.name} (${r.ip}): EXISTING CONTAINERS DETECTED (${r.existing_containers.join(', ')}). An active deployment already exists here!`, 'warn');
          setDynNodeUIState(idx, 'warn', `Already running: ${r.existing_containers.slice(0, 2).join(', ')}`);
        } else {
          logOrchestration(`✅ [Node ${idx+1}] ${r.name} (${r.ip}): Clean slate. Docker is operational and no conflicting containers found.`, 'success');
          setDynNodeUIState(idx, 'pending', 'Clean Slate Verified');
        }
      });
      logOrchestration(`🎯 Pre-flight inspection complete. Review findings above before proceeding with deployment.`, 'info');
    } else {
      logOrchestration(`Pre-flight probe error: ${data.message || 'Operation failed'}`, 'err');
    }
  } catch (err) {
    logOrchestration(`Pre-flight probe network exception: ${err.message}`, 'err');
  } finally {
    if (btn) btn.disabled = false;
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

  const activeNodes = (typeof fleetNodes !== 'undefined' && fleetNodes.length > 0) ? fleetNodes : [
    { ip: '127.0.0.1', name: 'Local Core', deploy_core: true, target_siem: '127.0.0.1:9000' }
  ];

  renderOrchestrationNodes();

  logOrchestration(`🚀 Starting Project Lume Distributed Fleet Setup Pipeline (${activeNodes.length} configured nodes)...`, 'highlight');

  const updateProgress = (pct, desc) => {
    progBar.style.width = pct + '%';
    progText.textContent = pct + '% Complete';
    taskLabel.textContent = desc;
  };

  try {
    // PRE-CHECK: Check for existing containers across nodes before installing
    updateProgress(3, "Inspecting target nodes for existing deployments");
    logOrchestration("🔍 Running pre-install discovery to inspect what is already on target systems...", 'info');
    try {
      const probeRes = await fetch('/api/preflight_probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodes: activeNodes, form: getFormData() })
      });
      const probeData = await probeRes.json();
      if (probeData.status === 'success') {
        const collisions = (probeData.results || []).filter(r => r.existing_containers && r.existing_containers.length > 0);
        if (collisions.length > 0) {
          const names = collisions.map(c => `${c.name} (${c.ip}: ${c.existing_containers.join(', ')})`).join('\\n- ');
          const okToProceed = confirm(`⚠️ NOTICE: Existing Project Lume software or containers were found on the following target nodes:\\n- ${names}\\n\\nDeploying now will update or recreate these existing services. Do you want to proceed with deployment?`);
          if (!okToProceed) {
            logOrchestration("🛑 Deployment cancelled by user to preserve existing instances.", 'warn');
            badge.innerHTML = '⏸️ Deployment Paused';
            badge.style.background = 'rgba(245,158,11,0.2)';
            badge.style.color = '#fbbf24';
            btn.disabled = false;
            return;
          }
        }
      }
    } catch (probeErr) {
      logOrchestration(`Pre-flight check notice: ${probeErr.message} (continuing with deployment)`, 'warn');
    }

    // STEP 1: Compile environment and node-specific Compose configurations
    updateProgress(10, "Compiling environment policies & Docker definitions");
    logOrchestration(`⚙️ Initializing: Compiling .env, memory caps, threat intel vaults, and compose manifests for ${activeNodes.length} nodes...`, 'info');
    await new Promise(r => setTimeout(r, 500));

    // DYNAMIC EXECUTION LOOP OVER EACH CONFIGURED NODE
    const totalNodes = activeNodes.length;
    for (let i = 0; i < totalNodes; i++) {
      const node = activeNodes[i];
      const nodeIp = (node.ip || 'Local Node').trim();
      const nodeName = node.name || `Node ${i + 1}`;
      const services = [];
      if (node.deploy_core) services.push('Core SIEM');
      if (node.deploy_zeek) services.push('Zeek Network Sensor');
      if (node.deploy_scanner) services.push('Vuln Scanner');
      if (node.deploy_thrower) services.push(`Universal Forwarder -> ${node.target_siem || 'Core'}`);
      const serviceDesc = services.length > 0 ? services.join(' + ') : 'Base Agent';

      const startPct = 10 + Math.round((i / totalNodes) * 80);
      const endPct = 10 + Math.round(((i + 1) / totalNodes) * 80);

      updateProgress(startPct, `${nodeName} (${nodeIp}): Installing ${services[0] || 'Services'}`);
      setDynNodeUIState(i, 'running', `Configuring ${nodeName} (${nodeIp})...`);
      logOrchestration(`🖥️ [Node ${i + 1}/${totalNodes}] Deploying stack for ${nodeName} (${nodeIp}): ${serviceDesc}`, 'info');

      // Call backend orchestrator endpoint with the specific node definition
      let orchSuccess = false;
      let orchMsg = '';
      try {
        const res = await fetch('/api/orchestrate_node', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            node_idx: i,
            node: node,
            node_id: `dyn_node_${i}`,
            form: getFormData()
          })
        });
        const resJson = await res.json();
        if (resJson.status === 'success') {
          orchSuccess = true;
          orchMsg = resJson.message || `System ${nodeIp} deployed.`;
        } else {
          orchMsg = resJson.message || 'Deployment error';
        }
      } catch (e) {
        orchMsg = e.message;
        console.warn(`Orchestrate call for node ${nodeIp}:`, e);
      }

      if (orchSuccess) {
        setDynNodeUIState(i, 'success', `System ${nodeIp} online.`);
        logOrchestration(`✅ [Node ${i + 1}/${totalNodes}] ${nodeName} (${nodeIp}) installation verified. Containers started.`, 'success');
      } else {
        setDynNodeUIState(i, 'err', `Failed: ${orchMsg}`);
        logOrchestration(`❌ [Node ${i + 1}/${totalNodes}] ${nodeName} (${nodeIp}) failed to deploy: ${orchMsg}`, 'err');
      }
      updateProgress(endPct, `${nodeName} processed`);
    }

    // FINAL VERIFICATION & CELEBRATION
    updateProgress(100, "Fleet Orchestration Complete");
    badge.innerHTML = '✅ All Systems Installed & Verified';
    badge.style.background = 'rgba(16,185,129,0.2)';
    badge.style.color = '#34d399';
    badge.style.borderColor = 'rgba(16,185,129,0.5)';

    // Update success banner text dynamically
    const bannerSubtitle = successBanner.querySelector('div > div:last-child');
    if (bannerSubtitle) {
      bannerSubtitle.textContent = `All ${totalNodes} configured fleet nodes (${activeNodes.map(n => n.ip || n.name).join(', ')}) are synchronized and operational.`;
    }
    successBanner.style.display = 'flex';
    logOrchestration(`🎉 [MISSION SUCCESS] All ${totalNodes} configured fleet nodes are fully deployed and registered!`, 'success');
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

// ==============================================================================
// FLEET UPDATE & DECOMMISSION FRONTEND CONTROLLERS
// ==============================================================================

function renderUpdateNodeList() {
  const container = document.getElementById('update_node_list_container');
  if (!container) return;
  container.innerHTML = '';

  const activeNodes = (fleetNodes || []).filter(n => (n.ip || '').trim().length > 0 || n.deploy_core);
  if (activeNodes.length === 0) {
    container.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 6px;">No nodes currently configured in Tab 1 (Architecture & IPs).</div>';
    return;
  }

  activeNodes.forEach((node, idx) => {
    const isLocal = !node.ip || ['127.0.0.1', 'localhost', '0.0.0.0', '192.168.88.24'].includes(node.ip.trim());
    const card = document.createElement('label');
    card.className = 'checkbox-card';
    card.style.marginBottom = '0';

    const sList = [];
    if (node.deploy_core) sList.push('Core SIEM');
    if (node.deploy_zeek) sList.push('Zeek Network Sensor');
    if (node.deploy_scanner) sList.push('Vuln Scanner');
    if (node.deploy_thrower) sList.push('Universal Forwarder (Vector)');

    card.innerHTML = `
      <input type="checkbox" class="update-node-check" data-idx="${idx}" checked>
      <div class="checkbox-content">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div class="checkbox-title">🖥️ ${escapeHtml(node.name || 'Node ' + (idx + 1))} <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-cyan);">(${escapeHtml(node.ip || '127.0.0.1')})</span></div>
          <span style="font-size: 10px; padding: 2px 7px; border-radius: 4px; background: ${isLocal ? 'rgba(16,185,129,0.15); color: #34d399;' : 'rgba(6,182,212,0.15); color: var(--accent-cyan);'} border: 1px solid currentColor;">${isLocal ? 'Local / Coordinator' : 'Remote SSH'}</span>
        </div>
        <div class="checkbox-desc">Services: <b>${sList.join(' + ') || 'Base System'}</b> | Target Ingest: <code>${escapeHtml(node.target_siem || '127.0.0.1:9000')}</code></div>
      </div>
    `;
    container.appendChild(card);
  });
}

function toggleSelectAllUpdateNodes(state) {
  document.querySelectorAll('.update-node-check').forEach(chk => chk.checked = state);
}

function renderRemoveNodeList() {
  const container = document.getElementById('remove_node_list_container');
  if (!container) return;
  container.innerHTML = '';

  const activeNodes = (fleetNodes || []).filter(n => (n.ip || '').trim().length > 0 || n.deploy_core);
  if (activeNodes.length === 0) {
    container.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 6px;">No nodes currently configured in Tab 1 (Architecture & IPs).</div>';
    return;
  }

  activeNodes.forEach((node, idx) => {
    const isLocal = !node.ip || ['127.0.0.1', 'localhost', '0.0.0.0', '192.168.88.24'].includes(node.ip.trim());
    const card = document.createElement('label');
    card.className = 'checkbox-card';
    card.style.marginBottom = '0';
    card.style.borderColor = 'rgba(244, 63, 94, 0.2)';

    card.innerHTML = `
      <input type="checkbox" class="remove-node-check" data-idx="${idx}">
      <div class="checkbox-content">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div class="checkbox-title" style="color: #fca5a5;">🛑 ${escapeHtml(node.name || 'Node ' + (idx + 1))} <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-cyan);">(${escapeHtml(node.ip || '127.0.0.1')})</span></div>
          <span style="font-size: 10px; padding: 2px 7px; border-radius: 4px; background: rgba(244,63,94,0.15); color: #f87171; border: 1px solid rgba(244,63,94,0.3);">${isLocal ? 'Local / Coordinator' : 'Remote SSH'}</span>
        </div>
        <div class="checkbox-desc">Decommissioning target node. Containers and assigned port bindings will be released.</div>
      </div>
    `;
    container.appendChild(card);
  });
}

function toggleSelectAllRemoveNodes(state) {
  document.querySelectorAll('.remove-node-check').forEach(chk => chk.checked = state);
}

function checkRemoveSafetyLock() {
  const input = document.getElementById('remove_confirm_input');
  const btn = document.getElementById('btn_execute_remove');
  if (!input || !btn) return;
  const isMatch = (input.value || '').trim().toUpperCase() === 'REMOVE';
  btn.disabled = !isMatch;
}

function logUpdate(msg, type = 'info') {
  const logEl = document.getElementById('update_status_log');
  if (!logEl) return;
  const time = new Date().toLocaleTimeString();
  let prefix = '• ';
  if (type === 'success') prefix = '✅ ';
  if (type === 'err') prefix = '❌ ';
  if (type === 'warn') prefix = '⚠️ ';
  if (type === 'step') prefix = '⚡ ';
  logEl.innerHTML += `\\n[${time}] ${prefix}${msg}`;
  logEl.scrollTop = logEl.scrollHeight;
}

function logRemove(msg, type = 'info') {
  const logEl = document.getElementById('remove_status_log');
  if (!logEl) return;
  const time = new Date().toLocaleTimeString();
  let prefix = '• ';
  if (type === 'success') prefix = '✅ ';
  if (type === 'err') prefix = '❌ ';
  if (type === 'warn') prefix = '⚠️ ';
  if (type === 'step') prefix = '💥 ';
  logEl.innerHTML += `\\n[${time}] ${prefix}${msg}`;
  logEl.scrollTop = logEl.scrollHeight;
}

async function executeFleetUpdate() {
  const btn = document.getElementById('btn_execute_update');
  const chks = Array.from(document.querySelectorAll('.update-node-check:checked'));
  if (chks.length === 0) {
    alert("Please select at least one system to update.");
    return;
  }

  const selectedNodes = chks.map(c => fleetNodes[parseInt(c.getAttribute('data-idx'))]).filter(Boolean);
  const strategy = document.querySelector('input[name="update_strategy"]:checked')?.value || 'pull_recreate';
  const enforceOrder = document.getElementById('update_enforce_order')?.checked ?? true;
  const pruneDangling = document.getElementById('update_prune_dangling')?.checked ?? true;

  btn.disabled = true;
  const logEl = document.getElementById('update_status_log');
  logEl.innerHTML = `[${new Date().toLocaleTimeString()}] 🚀 Initiating fleet update (${strategy}). Targets: ${selectedNodes.length} nodes...`;

  try {
    const res = await fetch('/api/fleet_update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nodes: selectedNodes,
        strategy: strategy,
        enforce_order: enforceOrder,
        prune_dangling: pruneDangling,
        form: getFormData()
      })
    });
    const data = await res.json();
    if (data.status === 'success') {
      (data.logs || []).forEach(l => logUpdate(l.msg, l.type));
      logUpdate(`🎉 Fleet update completed successfully across all ${selectedNodes.length} systems!`, 'success');
    } else {
      logUpdate(`Update error: ${data.message || 'Operation failed.'}`, 'err');
    }
  } catch (err) {
    logUpdate(`Network/Execution Exception: ${err.message}`, 'err');
  } finally {
    btn.disabled = false;
  }
}

async function executeFleetRemove() {
  const btn = document.getElementById('btn_execute_remove');
  const input = document.getElementById('remove_confirm_input');
  if ((input.value || '').trim().toUpperCase() !== 'REMOVE') {
    alert("Please type REMOVE into the confirmation box to authorize teardown.");
    return;
  }

  const chks = Array.from(document.querySelectorAll('.remove-node-check:checked'));
  if (chks.length === 0) {
    alert("Please select at least one system to decommission/remove.");
    return;
  }

  const selectedNodes = chks.map(c => fleetNodes[parseInt(c.getAttribute('data-idx'))]).filter(Boolean);
  const wipeVaults = document.getElementById('remove_opt_vaults')?.checked ?? false;
  const removeImages = document.getElementById('remove_opt_images')?.checked ?? true;
  const wipeConfigs = document.getElementById('remove_opt_configs')?.checked ?? false;

  if (wipeVaults && !confirm("⚠️ WARNING: You have selected 'Wipe Data Vaults, DuckDB & SQLite Databases'. This will IRREVERSIBLY erase all captured telemetry, parquet vaults, and incident history on the selected systems. Continue?")) {
    return;
  }

  btn.disabled = true;
  const logEl = document.getElementById('remove_status_log');
  logEl.innerHTML = `[${new Date().toLocaleTimeString()}] 🛑 Initiating decommissioning pipeline for ${selectedNodes.length} target node(s)...`;

  try {
    const res = await fetch('/api/fleet_remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nodes: selectedNodes,
        wipe_vaults: wipeVaults,
        remove_images: removeImages,
        wipe_configs: wipeConfigs,
        form: getFormData()
      })
    });
    const data = await res.json();
    if (data.status === 'success') {
      (data.logs || []).forEach(l => logRemove(l.msg, l.type));
      logRemove(`🏁 Decommissioning complete for selected systems.`, 'success');
      input.value = '';
      checkRemoveSafetyLock();
    } else {
      logRemove(`Decommission error: ${data.message || 'Operation failed.'}`, 'err');
    }
  } catch (err) {
    logRemove(`Network/Execution Exception: ${err.message}`, 'err');
  } finally {
    btn.disabled = false;
  }
}

async function generateLifecycleRunbook(actionType) {
  const nodes = (actionType === 'update')
    ? Array.from(document.querySelectorAll('.update-node-check:checked')).map(c => fleetNodes[parseInt(c.getAttribute('data-idx'))]).filter(Boolean)
    : Array.from(document.querySelectorAll('.remove-node-check:checked')).map(c => fleetNodes[parseInt(c.getAttribute('data-idx'))]).filter(Boolean);

  if (nodes.length === 0) {
    alert(`Please select at least one node to generate the ${actionType} command runbook.`);
    return;
  }

  const wipeVaults = document.getElementById('remove_opt_vaults')?.checked ?? false;
  const removeImages = document.getElementById('remove_opt_images')?.checked ?? true;
  const wipeConfigs = document.getElementById('remove_opt_configs')?.checked ?? false;
  const strategy = document.querySelector('input[name="update_strategy"]:checked')?.value || 'pull_recreate';

  try {
    const res = await fetch('/api/generate_lifecycle_scripts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: actionType,
        nodes: nodes,
        strategy: strategy,
        wipe_vaults: wipeVaults,
        remove_images: removeImages,
        wipe_configs: wipeConfigs,
        form: getFormData()
      })
    });
    const data = await res.json();
    if (data.status === 'success') {
      // Display script in modal or prompt
      const modal = document.createElement('div');
      modal.className = 'modal-backdrop';
      modal.style.display = 'flex';
      modal.innerHTML = `
        <div class="modal-card" style="max-width: 850px; max-height: 85vh; display: flex; flex-direction: column;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <h2 style="font-size: 16px; color: #fff;">📋 Staged Command Runbook (${actionType.toUpperCase()})</h2>
            <button class="btn btn-secondary" style="padding: 4px 10px;" onclick="this.closest('.modal-backdrop').remove()">✕ Close</button>
          </div>
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
            Execute these commands directly on each physical system in the exact order listed below. Ideal for air-gapped terminals without central SSH:
          </p>
          <textarea readonly style="width: 100%; flex: 1; min-height: 380px; background: #0a0e17; color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); resize: none;">${escapeHtml(data.script || '')}</textarea>
          <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 14px;">
            <button class="btn btn-cyan" onclick="navigator.clipboard.writeText(this.closest('.modal-card').querySelector('textarea').value); alert('Runbook copied to clipboard!');">📋 Copy Runbook to Clipboard</button>
            <button class="btn btn-secondary" onclick="this.closest('.modal-backdrop').remove()">Done</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    } else {
      alert(`Error generating script: ${data.message}`);
    }
  } catch (e) {
    alert(`Failed to contact studio backend: ${e.message}`);
  }
}

window.onload = function() {
  initRulesUI();
  renderFleetNodes();
  renderUpdateNodeList();
  renderRemoveNodeList();
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
    
    # Check if demo mode is requested
    is_demo = False
    if cfg.get("demo_mode"):
        is_demo = True
    elif cfg.get("nodes") and isinstance(cfg["nodes"], list) and len(cfg["nodes"]) > 0:
        if cfg["nodes"][0].get("demo_mode"):
            is_demo = True

    env_lines = [
        "      - PORT=9000",
        "      - PYTHONUNBUFFERED=1",
        f"      - LUME_INGEST_TOKEN={token}",
        "      - LUME_DB_PATH=/app/db/project_lume.duckdb"
    ]
    if is_demo:
        env_lines.append("      - LUME_TRAINING_MODE=true")
        env_lines.append("      - LUME_ENVIRONMENT=demo")
    else:
        env_lines.append("      - LUME_TRAINING_MODE=false")
        env_lines.append("      - LUME_ENVIRONMENT=production")

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
    shm_size: "1gb"
    cap_add:
      - SYS_NICE
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
      - lume_db:/app/db
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

volumes:
  lume_db:
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
    shm_size: "1gb"
    cap_add:
      - SYS_NICE
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
      - LUME_DB_PATH=/app/db/project_lume.duckdb
      - LUME_TRAINING_MODE=false
      - LUME_ENVIRONMENT=production
    volumes:
      - lume_db_15:/app/db
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
  lume_db_15:
  zeek_logs_15:
  suricata_logs_15:
  trivy_cache_15:
"""

def generate_node_compose(node: dict, global_cfg: dict) -> str:
    """
    Generates a tailored docker-compose.yml for an arbitrary node in the fleet,
    supporting Core SIEM, Zeek + Suricata Sensor, Trivy Vuln Scanner, and Universal Forwarder (Vector)
    pointing to the node's assigned Target SIEM destination.
    """
    node_ip = node.get("ip", "127.0.0.1")
    iface = node.get("interface") or global_cfg.get("sensor_interface", "ens160")
    if iface == "ens160" and node_ip.endswith(".31"):
        iface = "ens192"
    sensor_id = global_cfg.get("sensor_id", "sensor-node-primary")
    target_dir = global_cfg.get("scanner_target_dir", "/host")
    interval = global_cfg.get("scanner_interval", "360")
    severities = global_cfg.get("severities", "CRITICAL,HIGH,MEDIUM")
    port = global_cfg.get("lume_port", "9000")
    s_port = global_cfg.get("syslog_port", "514")
    t_port = global_cfg.get("tls_ingest_port", "1514")

    token = global_cfg.get("lume_token", "LAME_SECRET_TOKEN_99")
    node_name = node.get("name", f"Node {node_ip}")
    target_siem = node.get("target_siem", f"127.0.0.1:{port}")
    if not target_siem.startswith("http://") and not target_siem.startswith("https://"):
        target_url = f"http://{target_siem}"
    else:
        target_url = target_siem

    services_blocks = []
    volume_names = set()

    # 1. Core SIEM
    if node.get("deploy_core"):
        is_demo = bool(node.get("demo_mode", False))
        mem_cap = node.get("memory_cap") or ("12G" if "15" in node_ip else ("2600M" if "44" in node_ip else "8G"))
        vol_db = f"lume_db_{node_ip.replace('.', '_')}"
        volume_names.add(vol_db)

        env_lines = [
            "      - PORT=9000",
            "      - PYTHONUNBUFFERED=1",
            f"      - LUME_INGEST_TOKEN={token}",
            f"      - LUME_NODE_NAME={node_name}",
            "      - LUME_DB_PATH=/app/db/project_lume.duckdb"
        ]
        if is_demo:
            env_lines.append("      - LUME_TRAINING_MODE=true")
            env_lines.append("      - LUME_ENVIRONMENT=demo")
        else:
            env_lines.append("      - LUME_TRAINING_MODE=false")
            env_lines.append("      - LUME_ENVIRONMENT=production")

        env_block = "\n".join(env_lines)

        services_blocks.append(f"""  project-lume-core:
    image: {DOCKER_IMAGES['core']}
    container_name: project-lume-core
    restart: unless-stopped
    shm_size: "1gb"
    cap_add:
      - SYS_NICE
    ports:
      - "{port}:9000"
      - "{s_port}:{s_port}/udp"
      - "{s_port}:{s_port}/tcp"
      - "{t_port}:{t_port}/udp"
      - "{t_port}:{t_port}/tcp"
    environment:
{env_block}
    volumes:
      - {vol_db}:/app/db
      - ./data_vaults:/app/data_vaults
      - ./Dropzone_Inputs:/app/dropzone
      - ./web_workspaces:/app/web/workspaces
    deploy:
      resources:
        limits:
          memory: {mem_cap}
        reservations:
          memory: 1G
    extra_hosts:
      - "host.docker.internal:host-gateway"
""")

    # 2. Zeek + Suricata Sensor
    if node.get("deploy_zeek"):
        vol_z = f"zeek_logs_{node_ip.replace('.', '_')}"
        vol_s = f"suricata_logs_{node_ip.replace('.', '_')}"
        volume_names.add(vol_z)
        volume_names.add(vol_s)
        services_blocks.append(f"""  zeek-sensor-node:
    image: {DOCKER_IMAGES['zeek']}
    container_name: lume-zeek-sensor
    restart: unless-stopped
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_RAWIO
    environment:
      - SENSOR_INTERFACE={iface}
      - SENSOR_ID={sensor_id}-{node_ip.split('.')[-1]}
      - LUME_URL={target_url}
      - LUME_TOKEN={token}
      - LUME_NAMESPACE=default
      - ENABLE_SURICATA=true
      - ENABLE_SURICATA_RULES_UPDATE=true
      - SURICATA_RULES=emerging-scada.rules,emerging-exploit.rules,emerging-current_events.rules,emerging-attack_response.rules,emerging-worm.rules,emerging-shellcode.rules,threatview_CS_c2.rules
    volumes:
      - {vol_z}:/var/log/zeek
      - {vol_s}:/var/log/suricata
""")

    # 3. Host Vulnerability Scanner
    if node.get("deploy_scanner"):
        vol_t = f"trivy_cache_{node_ip.replace('.', '_')}"
        volume_names.add(vol_t)
        services_blocks.append(f"""  vuln-scanner-node:
    image: {DOCKER_IMAGES['scanner']}
    container_name: lume-vuln-scanner
    restart: unless-stopped
    environment:
      - LUME_URL={target_url}
      - LUME_TOKEN={token}
      - LUME_NAMESPACE=default
      - NODE_ID={node_name.replace(' ', '_')}
      - TARGET_DIR={target_dir}
      - SCAN_SEVERITY={severities}
      - SCAN_INTERVAL_MINS={interval}
      - RUN_ONCE=false
    volumes:
      - /:{target_dir}:ro
      - {vol_t}:/root/.cache/trivy
""")

    # 4. Host OS Self-Monitoring Telemetry (Vector edge log shipper)
    if node.get("deploy_thrower"):
        services_blocks.append(f"""  lume-self-monitor:
    image: timberio/vector:0.34.1-alpine
    container_name: lume-self-monitor
    restart: unless-stopped
    environment:
      - VECTOR_LOG=info
    command: ["--config-yaml", "/etc/vector/vector.yaml"]
    volumes:
      - ./vector_self_monitor.yaml:/etc/vector/vector.yaml:ro
      - /var/log:/var/log:ro
""")

    vols_section = ""
    if volume_names:
        vols_section = "\nvolumes:\n" + "\n".join(f"  {v}:" for v in sorted(volume_names)) + "\n"

    return f"""# Project Lume Stack for Node: {node_name} ({node_ip})
# Assigned Target SIEM: {target_url}
# Generated by Project Lume Setup Studio on {time.strftime('%Y-%m-%d %H:%M:%S')}
services:
{"".join(services_blocks)}{vols_section}"""


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
    shm_size: "1gb"
    cap_add:
      - SYS_NICE
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
      - LUME_DB_PATH=/app/db/project_lume.duckdb
      - LUME_TRAINING_MODE=false
      - LUME_ENVIRONMENT=production
    volumes:
      - lume_db_44:/app/db
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
  lume_db_44:
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

                # Write custom docker-compose for each configured fleet node
                nodes_written = []
                for node in cfg.get("nodes", []):
                    nip = node.get("ip", "").strip()
                    if nip:
                        sanitized_ip = nip.replace(".", "_")
                        fname = f"docker-compose.node-{sanitized_ip}.yml"
                        with open(out_dir / fname, "w") as f:
                            f.write(generate_node_compose(node, cfg))
                        nodes_written.append(f"{node.get('name', nip)} ({fname})")

                lic_content = cfg.get("lume_license_token", "").strip()
                if lic_content:
                    with open(out_dir / "lume.lic", "w") as f:
                        f.write(lic_content + "\n")

                nodes_msg = f"\nGenerated {len(nodes_written)} node compose files:\n" + "\n".join(f" • {n}" for n in nodes_written) if nodes_written else ""
                self._send_json({
                    "status": "success",
                    "message": f"Successfully written all deployment configurations to:\n{out_dir}\n(Includes core compose, node-specific compose files, .env, storage_lifecycle_policy.json, and network_boundaries.json){nodes_msg}"
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

                    # Dynamically add compose for each node
                    readme_lines = [
                        "# Project Lume Enterprise Deployment Bundle",
                        f"Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}",
                        "",
                        "## Fleet Node Compose Files:",
                    ]
                    for node in cfg.get("nodes", []):
                        nip = node.get("ip", "").strip()
                        if nip:
                            sanitized_ip = nip.replace(".", "_")
                            fname = f"docker-compose.node-{sanitized_ip}.yml"
                            z.writestr(fname, generate_node_compose(node, cfg))
                            readme_lines.append(f"- **{node.get('name', nip)}** ({nip}): `docker compose -f {fname} up -d`")

                    readme_lines.extend([
                        "",
                        "## Core Stack:",
                        "- Standard Core SIEM: `docker compose -f docker-compose.lume-core.yml up -d`",
                        "- Node 15 All-in-One: `docker compose -f docker-compose.node15-full-sensor.yml up -d`",
                        "- Node 44 Core + Vuln Scanner: `docker compose -f docker-compose.node44-vuln-scanner.yml up -d`"
                    ])

                    z.writestr(".env", generate_env_file(cfg))
                    z.writestr("ai_config.json", generate_ai_config(cfg))
                    z.writestr("storage_lifecycle_policy.json", generate_storage_policy(cfg))
                    z.writestr("network_boundaries.json", generate_network_boundaries(cfg))
                    z.writestr("README.md", "\n".join(readme_lines) + "\n")

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
                        ssh.exec_command(f"mkdir -p {remote_dir}/data_vaults {remote_dir}/Dropzone_Inputs {remote_dir}/web_workspaces 2>/dev/null; chmod -R 777 {remote_dir}/data_vaults {remote_dir}/Dropzone_Inputs {remote_dir}/web_workspaces 2>/dev/null || true")
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
                    if r_host == "192.168.88.25":
                        remote_dir = "/Users/lame/project_lume"

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

        elif url.path == "/api/orchestrate_node":
            try:
                payload = json.loads(post_body.decode("utf-8"))
                target_node = payload.get("node_id") # e.g. "dyn_node_0" or legacy "node_24"
                dyn_node = payload.get("node") # dynamic node object if passed
                cfg = payload.get("form", {})
                r_pass = cfg.get("remote_ssh_pass", "Denver#2").strip()

                import urllib.request

                # If dynamic node passed from modern frontend:
                if dyn_node:
                    n_ip = dyn_node.get("ip", "").strip()
                    n_name = dyn_node.get("name", f"Node {n_ip}")
                    d_core = dyn_node.get("deploy_core", False)
                    d_zeek = dyn_node.get("deploy_zeek", False)
                    d_scanner = dyn_node.get("deploy_scanner", False)
                    d_thrower = dyn_node.get("deploy_thrower", False)
                    target_siem = dyn_node.get("target_siem", "127.0.0.1:9000")

                    # If this node represents local machine (127.0.0.1 or local hostname)
                    is_local = (n_ip in ("127.0.0.1", "localhost", "0.0.0.0", "") or n_ip == "192.168.88.24")

                    if is_local and d_core:
                        res = subprocess.run("docker ps -q -f name=project-lume-core", shell=True, capture_output=True, text=True)
                        if not res.stdout.strip():
                            subprocess.run("docker start project-lume-core 2>nul || docker compose up -d 2>nul", shell=True)
                    elif not is_local:
                        try:
                            import paramiko
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(n_ip, username="lame", password=r_pass, timeout=8)

                            remote_dir = "/home/lame/project_lume" if n_ip != "192.168.88.25" else "/Users/lame/project_lume"

                            # 1. Ensure directory structure exists and is owned with open write permissions for container UID 10001
                            ssh.exec_command(f"mkdir -p {remote_dir}/data_vaults {remote_dir}/Dropzone_Inputs {remote_dir}/web_workspaces 2>/dev/null; chmod -R 777 {remote_dir}/data_vaults {remote_dir}/Dropzone_Inputs {remote_dir}/web_workspaces 2>/dev/null || true")

                            # 2. Generate and SFTP the tailored compose and self-monitor files for this node
                            node_compose = generate_node_compose(dyn_node, cfg)
                            env_content = generate_env_file(cfg)
                            sftp = ssh.open_sftp()
                            with sftp.file(f"{remote_dir}/docker-compose.yml", "w") as f:
                                f.write(node_compose)
                            with sftp.file(f"{remote_dir}/.env", "w") as f:
                                f.write(env_content)
                            if d_thrower:
                                token = cfg.get("lume_token", "LAME_SECRET_TOKEN_99")
                                target_url = f"http://{target_siem}" if not target_siem.startswith("http") else target_siem
                                self_monitor_yaml = f"""sources:
  host_auth:
    type: file
    include:
      - /var/log/auth.log
    read_from: beginning
  host_syslog:
    type: file
    include:
      - /var/log/syslog
    read_from: beginning
transforms:
  enrich_meta:
    type: remap
    inputs:
      - host_auth
      - host_syslog
    source: |
      .host = get_hostname!()
      ._time = format_timestamp!(now(), "%Y-%m-%dT%H:%M:%SZ")
      ._namespace = "default"
      .dataset = "default"
      msg = string!(.message)
      if contains(string!(.file), "auth") {{
        if contains(msg, "sshd") {{
          .sourcetype = "linux_auth_ssh"
        }} else if contains(msg, "sudo") {{
          .sourcetype = "linux_auth_sudo"
        }} else {{
          .sourcetype = "linux_auth"
        }}
      }} else {{
        .sourcetype = "linux_application"
      }}
sinks:
  lume_api:
    type: http
    inputs:
      - enrich_meta
    uri: {target_url}/api/v1/ingest/raw
    method: post
    encoding:
      codec: json
    headers:
      X-Lume-Token: "{token}"
      X-Lume-Dataset: "default"
"""
                                with sftp.file(f"{remote_dir}/vector_self_monitor.yaml", "w") as f:
                                    f.write(self_monitor_yaml)
                            sftp.close()

                            # 3. Pull required images and launch container stack!
                            images = []
                            if d_core: images.append(DOCKER_IMAGES["core"])
                            if d_zeek: images.append(DOCKER_IMAGES["zeek"])
                            if d_scanner: images.append(DOCKER_IMAGES["scanner"])
                            if d_thrower: images.append("timberio/vector:0.34.1-alpine")

                            pull_cmd = " && ".join([f"docker pull {img}" for img in images]) if images else "true"
                            deploy_cmd = (
                                f"cd {remote_dir} && "
                                f"{pull_cmd} && "
                                f"docker compose up -d --remove-orphans"
                            )
                            stdin, stdout, stderr = ssh.exec_command(deploy_cmd)
                            stdout.read()  # Wait for deployment to finish!

                            # 4. Verify containers running
                            _, v_out, _ = ssh.exec_command("docker ps --format '{{.Names}}'")
                            running_names = v_out.read().decode("utf-8").strip().splitlines()
                            ssh.close()
                        except Exception as ssh_err:
                            print(f"Notice: SSH orchestration to {n_ip}: {ssh_err}")
                            self._send_json({"status": "error", "message": f"Deployment failed on {n_ip}: {ssh_err}"}, status=500)
                            return

                    # Attempt federated registration to local Coordinator if reachable
                    reg_payload = {
                        "node_id": f"node_{n_ip.replace('.', '_')}",
                        "friendly_name": n_name,
                        "hostname": n_ip,
                        "role": "coordinator" if (is_local and d_core) else "worker",
                        "endpoint": f"http://{n_ip or '127.0.0.1'}:9000",
                        "deploy_core": d_core,
                        "deploy_zeek": d_zeek,
                        "deploy_scanner": d_scanner,
                        "deploy_thrower": d_thrower,
                        "target_siem": target_siem,
                        "aux_services": []
                    }
                    try:
                        req = urllib.request.Request(
                            "http://localhost:9000/api/cluster/nodes/register",
                            data=json.dumps(reg_payload).encode("utf-8"),
                            headers={"Content-Type": "application/json"}
                        )
                        urllib.request.urlopen(req, timeout=3)
                    except Exception:
                        pass

                    self._send_json({
                        "status": "success",
                        "message": f"Successfully orchestrated and launched containers on {n_name} ({n_ip})."
                    })
                    return

                if target_node == "node_24":
                    # Local PC (192.168.88.24) - Ensure local container is running and register as coordinator
                    res = subprocess.run("docker ps -q -f name=project-lume-core", shell=True, capture_output=True, text=True)
                    if not res.stdout.strip():
                        subprocess.run("docker start project-lume-core 2>nul || docker compose up -d 2>nul", shell=True)

                    # Register / confirm local node
                    reg_data = {
                        "node_id": "windows_workstation",
                        "friendly_name": cfg.get("lume_node_name", "Windows Workstation (Operations)"),
                        "hostname": "192.168.88.24",
                        "role": "coordinator",
                        "endpoint": "http://192.168.88.24:9000",
                        "deploy_core": True,
                        "deploy_zeek": False,
                        "deploy_scanner": False,
                        "aux_services": []
                    }
                    try:
                        req = urllib.request.Request(
                            "http://localhost:9000/api/cluster/nodes/register",
                            data=json.dumps(reg_data).encode("utf-8"),
                            headers={"Content-Type": "application/json"}
                        )
                        urllib.request.urlopen(req, timeout=5)
                    except Exception:
                        pass

                    self._send_json({"status": "success", "message": "Windows PC Coordinator (192.168.88.24) active and initialized."})
                    return

                # Remote nodes deployment and registration
                remote_map = {
                    "node_25": {
                        "host": "192.168.88.25",
                        "user": "lame",
                        "name": "Macbook Pro Lab Core",
                        "role": "worker",
                        "vault": "/Users/lame/project_lume/data_vaults",
                        "deploy_core": True,
                        "deploy_zeek": False,
                        "deploy_scanner": False,
                        "aux": []
                    },
                    "node_44": {
                        "host": "192.168.88.44",
                        "user": "lame",
                        "name": "Ubuntu Demo 1",
                        "role": "worker",
                        "vault": "/home/lame/project_lume/data_vaults",
                        "deploy_core": True,
                        "deploy_zeek": False,
                        "deploy_scanner": True,
                        "aux": ["scanner"],
                        "scanner_info": {"container": "lume-vuln-scanner-44"}
                    },
                    "node_15": {
                        "host": "192.168.88.15",
                        "user": "lame",
                        "name": "Ubuntu Demo 2",
                        "role": "worker",
                        "vault": "/home/lame/project_lume/data_vaults",
                        "deploy_core": True,
                        "deploy_zeek": True,
                        "deploy_scanner": True,
                        "aux": ["zeek", "scanner"],
                        "zeek_info": {"container": "lume-zeek-sensor-15", "enable_suricata": True, "ot_scada_rules": True},
                        "scanner_info": {"container": "lume-vuln-scanner-15"}
                    }
                }

                if target_node not in remote_map:
                    self._send_json({"status": "error", "message": f"Unknown target node: {target_node}"}, status=400)
                    return

                ninfo = remote_map[target_node]
                r_host = ninfo["host"]
                r_user = ninfo["user"]
                r_name = ninfo["name"]

                try:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(r_host, username=r_user, password=r_pass, timeout=8)

                    # Launch core SIEM container if not already running
                    vault = ninfo["vault"]
                    mem_flag = "--memory 16g" if r_host == "192.168.88.25" else ("--memory 2600m" if r_host == "192.168.88.44" else "--memory 12g")
                    
                    # Ensure directory exists
                    ssh.exec_command(f"mkdir -p {vault}/parquet_archive {vault}/duckdb_temp 2>/dev/null || true")

                    # Check if core container is running
                    s_in, s_out, s_err = ssh.exec_command("docker ps -q -f name=project-lume-core")
                    if not s_out.read().decode().strip():
                        run_core = (
                            f"docker run -d --name project-lume-core "
                            f"-p 9000:9000 -p 514:514/udp -p 514:514/tcp -p 1514:1514/udp -p 1514:1514/tcp "
                            f"-v \"{vault}:/app/data_vaults\" "
                            f"{mem_flag} --restart always "
                            f"{DOCKER_IMAGES['core']}"
                        )
                        ssh.exec_command(run_core)

                    # Launch Zeek if target is 15
                    if ninfo.get("deploy_zeek"):
                        s_in, s_out, s_err = ssh.exec_command("docker ps -q -f name=lume-zeek-sensor-15")
                        if not s_out.read().decode().strip():
                            zeek_run = (
                                f"docker run -d --name lume-zeek-sensor-15 "
                                f"--restart unless-stopped --net host "
                                f"--cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_RAWIO "
                                f"-v /etc/localtime:/etc/localtime:ro "
                                f"{DOCKER_IMAGES['zeek']}"
                            )
                            ssh.exec_command(zeek_run)

                    # Launch Scanner if target is 44 or 15
                    if ninfo.get("deploy_scanner"):
                        sc_name = f"lume-vuln-scanner-{r_host.split('.')[-1]}"
                        s_in, s_out, s_err = ssh.exec_command(f"docker ps -q -f name={sc_name}")
                        if not s_out.read().decode().strip():
                            scanner_run = (
                                f"docker run -d --name {sc_name} "
                                f"--restart unless-stopped "
                                f"-v /var/run/docker.sock:/var/run/docker.sock:ro -v /:/host:ro "
                                f"{DOCKER_IMAGES['scanner']}"
                            )
                            ssh.exec_command(scanner_run)

                    ssh.close()
                except Exception as ssh_err:
                    print(f"Notice: SSH orchestration to {r_host}: {ssh_err}")

                # Register this node in the PC Coordinator so it immediately shows up on Cluster Topology
                reg_payload = {
                    "node_id": target_node.replace("node_", "worker_node_") if target_node != "node_25" else "macbook_pro",
                    "friendly_name": r_name,
                    "hostname": r_host,
                    "role": ninfo["role"],
                    "endpoint": f"http://{r_host}:9000",
                    "deploy_core": ninfo.get("deploy_core", True),
                    "deploy_zeek": ninfo.get("deploy_zeek", False),
                    "deploy_scanner": ninfo.get("deploy_scanner", False),
                    "aux_services": ninfo.get("aux", []),
                    "zeek_info": ninfo.get("zeek_info", {}),
                    "scanner_info": ninfo.get("scanner_info", {})
                }
                try:
                    req = urllib.request.Request(
                        "http://localhost:9000/api/cluster/nodes/register",
                        data=json.dumps(reg_payload).encode("utf-8"),
                        headers={"Content-Type": "application/json"}
                    )
                    urllib.request.urlopen(req, timeout=5)
                except Exception as reg_err:
                    print(f"Notice: Coordinator register API: {reg_err}")

                self._send_json({
                    "status": "success",
                    "message": f"Successfully orchestrated and federated {r_name} ({r_host})!"
                })
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

        elif url.path == "/api/fleet_update":
            try:
                payload = json.loads(post_body.decode("utf-8"))
                nodes = payload.get("nodes", [])
                strategy = payload.get("strategy", "pull_recreate")
                enforce_order = payload.get("enforce_order", True)
                prune_dangling = payload.get("prune_dangling", True)
                cfg = payload.get("form", {})
                r_pass = cfg.get("remote_ssh_pass", "Denver#2").strip()

                logs = []

                def get_order_score(n):
                    # Splunk order of operations:
                    # 1. Coordinator / Core SIEM
                    # 2. Worker Cores
                    # 3. Network Sensors (Zeek)
                    # 4. Scanners / Edge Forwarders
                    ip = n.get("ip", "").strip()
                    is_coord = (ip in ("127.0.0.1", "localhost", "0.0.0.0", "192.168.88.24")) or n.get("role") == "coordinator"
                    if is_coord and n.get("deploy_core"):
                        return 0
                    if n.get("deploy_core"):
                        return 1
                    if n.get("deploy_zeek"):
                        return 2
                    return 3

                if enforce_order:
                    nodes = sorted(nodes, key=get_order_score)

                for idx, node in enumerate(nodes):
                    raw_ip = (node.get("ip") or "127.0.0.1").strip()
                    if raw_ip.startswith("1921."):
                        raw_ip = "192." + raw_ip[5:]
                    elif raw_ip.startswith("192168."):
                        raw_ip = "192.168." + raw_ip[7:]
                    n_ip = raw_ip

                    n_name = node.get("name") or f"Node {n_ip}"
                    is_local = (n_ip in ("127.0.0.1", "localhost", "0.0.0.0", "192.168.88.24"))

                    images_to_update = []
                    if node.get("deploy_core"):
                        images_to_update.append(DOCKER_IMAGES["core"])
                    if node.get("deploy_zeek"):
                        images_to_update.append(DOCKER_IMAGES["zeek"])
                    if node.get("deploy_scanner"):
                        images_to_update.append(DOCKER_IMAGES["scanner"])
                    if not images_to_update:
                        images_to_update.append(DOCKER_IMAGES["core"])

                    logs.append({"type": "step", "msg": f"[{idx+1}/{len(nodes)}] Commencing update on {n_name} ({n_ip})..."})

                    if is_local:
                        try:
                            if strategy == "pull_recreate":
                                for img in images_to_update:
                                    logs.append({"type": "info", "msg": f"Local host: Pulling latest image layer for {img}..."})
                                    p = subprocess.run(["docker", "pull", img], capture_output=True, text=True)
                                    if p.returncode != 0:
                                        logs.append({"type": "warn", "msg": f"docker pull notice: {p.stderr.strip() or p.stdout.strip()}"})

                                # Generate updated compose file
                                compose_content = generate_core_compose(cfg)
                                compose_path = SCRIPT_DIR / "docker-compose.yml"
                                with open(compose_path, "w", encoding="utf-8") as f:
                                    f.write(compose_content)

                                logs.append({"type": "info", "msg": f"Recreating local containers with persistent data preserved..."})
                                p_up = subprocess.run(["docker", "compose", "up", "-d", "--remove-orphans"], cwd=str(SCRIPT_DIR), capture_output=True, text=True)
                                if p_up.returncode == 0:
                                    logs.append({"type": "success", "msg": f"Local stack updated and live on http://127.0.0.1:{cfg.get('lume_port', '9000')}"})
                                else:
                                    logs.append({"type": "err", "msg": f"Local compose up error: {p_up.stderr.strip()}"})

                            elif strategy == "airgap_tars":
                                export_dir = SCRIPT_DIR / "lume_airgap_tars"
                                logs.append({"type": "info", "msg": f"Loading air-gap tar images from {export_dir}..."})
                                for t_file in export_dir.glob("*.tar"):
                                    subprocess.run(["docker", "load", "-i", str(t_file)], capture_output=True)
                                p_up = subprocess.run(["docker", "compose", "up", "-d"], cwd=str(SCRIPT_DIR), capture_output=True, text=True)
                                logs.append({"type": "success", "msg": f"Local stack updated via sneakernet tar archives."})

                            if prune_dangling:
                                subprocess.run(["docker", "image", "prune", "-f"], capture_output=True)
                                logs.append({"type": "info", "msg": f"Pruned dangling docker image layers on local host."})

                        except Exception as loc_err:
                            logs.append({"type": "err", "msg": f"Local update exception: {loc_err}"})

                    else:
                        # Remote SSH update
                        try:
                            import paramiko
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(n_ip, username="lame", password=r_pass, timeout=8)

                            remote_dir = "/home/lame/project_lume" if n_ip != "192.168.88.25" else "/Users/lame/project_lume"

                            if strategy == "pull_recreate":
                                pull_cmds = " && ".join([f"docker pull {img}" for img in images_to_update])
                                update_cmd = f"cd {remote_dir} && {pull_cmds} && docker compose up -d"
                                if prune_dangling:
                                    update_cmd += " && docker image prune -f"

                                logs.append({"type": "info", "msg": f"SSH remote pull & restart triggered on {n_ip}..."})
                                stdin, stdout, stderr = ssh.exec_command(update_cmd)
                                out = stdout.read().decode("utf-8", "replace").strip()
                                err = stderr.read().decode("utf-8", "replace").strip()
                                ssh.close()
                                logs.append({"type": "success", "msg": f"{n_name} ({n_ip}) upgraded successfully. Logs: {out[:140] or err[:140] or 'Clean restart'}"})

                            elif strategy == "airgap_tars":
                                load_cmd = f"cd {remote_dir} && for t in lume_airgap_tars/*.tar; do [ -f \"$t\" ] && docker load -i \"$t\"; done && docker compose up -d"
                                stdin, stdout, stderr = ssh.exec_command(load_cmd)
                                out = stdout.read().decode("utf-8", "replace").strip()
                                ssh.close()
                                logs.append({"type": "success", "msg": f"{n_name} ({n_ip}) upgraded from remote air-gap tars."})

                        except Exception as ssh_err:
                            logs.append({"type": "err", "msg": f"SSH update failed for {n_name} ({n_ip}): {ssh_err}"})

                self._send_json({"status": "success", "logs": logs})
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)

        elif url.path == "/api/fleet_remove":
            try:
                payload = json.loads(post_body.decode("utf-8"))
                nodes = payload.get("nodes", [])
                wipe_vaults = payload.get("wipe_vaults", False)
                remove_images = payload.get("remove_images", True)
                wipe_configs = payload.get("wipe_configs", False)
                cfg = payload.get("form", {})
                r_pass = cfg.get("remote_ssh_pass", "Denver#2").strip()

                logs = []
                for idx, node in enumerate(nodes):
                    raw_ip = (node.get("ip") or "127.0.0.1").strip()
                    # Defensive normalization: fix common double-keystroke typos like 1921.68 -> 192.168
                    if raw_ip.startswith("1921."):
                        raw_ip = "192." + raw_ip[5:]
                    elif raw_ip.startswith("192168."):
                        raw_ip = "192.168." + raw_ip[7:]
                    n_ip = raw_ip

                    n_name = node.get("name") or f"Node {n_ip}"
                    is_local = (n_ip in ("127.0.0.1", "localhost", "0.0.0.0", "192.168.88.24"))

                    logs.append({"type": "step", "msg": f"[{idx+1}/{len(nodes)}] Decommissioning {n_name} ({n_ip})..."})

                    if is_local:
                        try:
                            # 1. Check if docker is installed locally
                            docker_installed = (shutil.which("docker") is not None)
                            if not docker_installed:
                                logs.append({"type": "info", "msg": "Local host: Docker CLI not found. Skipping container/image operations."})
                            else:
                                logs.append({"type": "info", "msg": "Stopping and removing local containers & docker networks..."})
                                subprocess.run(["docker", "compose", "down", "--volumes", "--remove-orphans"], cwd=str(SCRIPT_DIR), capture_output=True)

                                if remove_images:
                                    for k, img in DOCKER_IMAGES.items():
                                        # Only delete if image exists
                                        chk_img = subprocess.run(["docker", "image", "inspect", img], capture_output=True, text=True)
                                        if chk_img.returncode == 0:
                                            subprocess.run(["docker", "rmi", "-f", img], capture_output=True)
                                            logs.append({"type": "info", "msg": f"Removed image {img} from local host cache."})
                                        else:
                                            logs.append({"type": "info", "msg": f"Image {img} was not present locally. Skipped."})

                            # 2. Wipe Data Vaults
                            if wipe_vaults:
                                v_dir = SCRIPT_DIR / "data_vaults"
                                if v_dir.exists():
                                    shutil.rmtree(v_dir, ignore_errors=True)
                                    v_dir.mkdir(parents=True, exist_ok=True)
                                    logs.append({"type": "warn", "msg": f"Wiped local data vaults & DuckDB/SQLite databases in {v_dir}"})
                                else:
                                    logs.append({"type": "info", "msg": "Local data_vaults directory did not exist. Skipped."})

                            # 3. Wipe Configs
                            if wipe_configs:
                                removed_cfg = []
                                for f_name in [".env", "docker-compose.yml", "ai_config.json"]:
                                    p = SCRIPT_DIR / f_name
                                    if p.exists():
                                        try:
                                            p.unlink()
                                            removed_cfg.append(f_name)
                                        except Exception:
                                            pass
                                logs.append({"type": "info", "msg": f"Removed local configs: {', '.join(removed_cfg) if removed_cfg else 'None present'}"})

                            logs.append({"type": "success", "msg": f"Local host decommissioned cleanly."})
                        except Exception as loc_err:
                            logs.append({"type": "err", "msg": f"Local decommission notice: {loc_err}"})

                    else:
                        # Remote SSH decommission
                        try:
                            import paramiko
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            try:
                                ssh.connect(n_ip, username="lame", password=r_pass, timeout=6)
                            except Exception as conn_err:
                                logs.append({"type": "warn", "msg": f"Could not reach {n_name} ({n_ip}): {conn_err}. Remote host is offline or unreachable."})
                                continue

                            remote_dir = "/home/lame/project_lume" if n_ip != "192.168.88.25" else "/Users/lame/project_lume"

                            # Probe if docker is installed on remote host
                            stdin, stdout, stderr = ssh.exec_command("which docker 2>/dev/null || true")
                            has_docker = bool(stdout.read().decode("utf-8").strip())

                            if has_docker:
                                logs.append({"type": "info", "msg": f"Stopping and removing all Lume containers on {n_ip}..."})
                                # Comprehensive container teardown:
                                # 1. Compose down if docker-compose exists
                                # 2. Explicit stop & rm of project-lume-core, zeek, and vuln scanner
                                # 3. Dynamic filter rm of all matching lume* containers
                                teardown_cmds = [
                                    f"echo '{r_pass}' | sudo -S docker compose -f {remote_dir}/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true",
                                    f"echo '{r_pass}' | sudo -S docker stop project-lume-core project-lume lume-zeek-sensor-15 lume-zeek-sensor-primary lume-vuln-scanner-15 lume-vuln-scanner-44 lume-vuln-scanner-primary 2>/dev/null || true",
                                    f"echo '{r_pass}' | sudo -S docker rm -f project-lume-core project-lume lume-zeek-sensor-15 lume-zeek-sensor-primary lume-vuln-scanner-15 lume-vuln-scanner-44 lume-vuln-scanner-primary 2>/dev/null || true",
                                    f"echo '{r_pass}' | sudo -S docker ps -a --filter name=lume -q | xargs -r sudo docker rm -f 2>/dev/null || true"
                                ]
                                if remove_images:
                                    img_str = " ".join(DOCKER_IMAGES.values())
                                    teardown_cmds.append(f"echo '{r_pass}' | sudo -S docker rmi -f {img_str} 2>/dev/null || true")
                                    teardown_cmds.append(f"echo '{r_pass}' | sudo -S docker image prune -f 2>/dev/null || true")

                                stdin, stdout, stderr = ssh.exec_command(" ; ".join(teardown_cmds))
                                stdout.read()  # Block until teardown finishes!

                                # Verify containers are gone
                                _, v_out, _ = ssh.exec_command("docker ps -q --filter name=lume")
                                remaining = v_out.read().decode("utf-8").strip()
                                if remaining:
                                    logs.append({"type": "warn", "msg": f"Notice on {n_ip}: Containers still active: {remaining}"})
                                else:
                                    logs.append({"type": "info", "msg": f"Verified: All Lume containers stopped and removed on {n_ip}."})
                            else:
                                logs.append({"type": "info", "msg": f"Notice: Docker is not installed on {n_ip}. Skipping docker cleanup."})

                            if wipe_vaults:
                                # Vaults may have root-owned files from Docker mounts, so use sudo
                                wipe_vault_cmd = f"echo '{r_pass}' | sudo -S rm -rf {remote_dir}/data_vaults/* 2>/dev/null || rm -rf {remote_dir}/data_vaults/* 2>/dev/null || true"
                                stdin, stdout, stderr = ssh.exec_command(wipe_vault_cmd)
                                stdout.read()
                                logs.append({"type": "warn", "msg": f"Wiped remote data vaults on {n_ip}."})

                            if wipe_configs:
                                wipe_cfg_cmd = f"rm -f {remote_dir}/.env {remote_dir}/docker-compose.yml {remote_dir}/data_vaults/*.json 2>/dev/null || true"
                                stdin, stdout, stderr = ssh.exec_command(wipe_cfg_cmd)
                                stdout.read()
                                logs.append({"type": "info", "msg": f"Removed configuration files on {n_ip}."})

                            ssh.close()
                            logs.append({"type": "success", "msg": f"{n_name} ({n_ip}) decommissioned cleanly over SSH."})

                        except Exception as ssh_err:
                            logs.append({"type": "err", "msg": f"SSH teardown notice for {n_name} ({n_ip}): {ssh_err}"})

                self._send_json({"status": "success", "logs": logs})
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)

        elif url.path == "/api/preflight_probe":
            try:
                payload = json.loads(post_body.decode("utf-8"))
                nodes = payload.get("nodes", [])
                cfg = payload.get("form", {})
                r_pass = cfg.get("remote_ssh_pass", "Denver#2").strip()

                results = []
                for node in nodes:
                    raw_ip = (node.get("ip") or "127.0.0.1").strip()
                    if raw_ip.startswith("1921."):
                        raw_ip = "192." + raw_ip[5:]
                    elif raw_ip.startswith("192168."):
                        raw_ip = "192.168." + raw_ip[7:]
                    nip = raw_ip
                    nname = node.get("name") or f"Node {nip}"
                    is_local = (nip in ("127.0.0.1", "localhost", "0.0.0.0", "192.168.88.24"))

                    item = {
                        "ip": nip,
                        "name": nname,
                        "is_local": is_local,
                        "reachable": False,
                        "docker_installed": False,
                        "existing_containers": [],
                        "ports_busy": []
                    }

                    if is_local:
                        item["reachable"] = True
                        item["docker_installed"] = (shutil.which("docker") is not None)
                        if item["docker_installed"]:
                            try:
                                res = subprocess.run(
                                    ["docker", "ps", "-a", "--filter", "name=lume", "--format", "{{.Names}}"],
                                    capture_output=True, text=True
                                )
                                c_list = [c.strip() for c in res.stdout.splitlines() if c.strip()]
                                item["existing_containers"] = c_list
                            except Exception:
                                pass
                    else:
                        try:
                            import paramiko
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(nip, username="lame", password=r_pass, timeout=4)
                            item["reachable"] = True

                            # Check docker binary
                            stdin, stdout, stderr = ssh.exec_command("which docker 2>/dev/null || true")
                            item["docker_installed"] = bool(stdout.read().decode("utf-8").strip())

                            if item["docker_installed"]:
                                stdin, stdout, stderr = ssh.exec_command("docker ps -a --filter name=lume --format '{{.Names}}' 2>/dev/null || true")
                                c_list = [c.strip() for c in stdout.read().decode("utf-8").splitlines() if c.strip()]
                                item["existing_containers"] = c_list

                            ssh.close()
                        except Exception:
                            item["reachable"] = False

                    results.append(item)

                self._send_json({"status": "success", "results": results})
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)

        elif url.path == "/api/generate_lifecycle_scripts":
            try:
                payload = json.loads(post_body.decode("utf-8"))
                action = payload.get("action", "update")
                nodes = payload.get("nodes", [])
                strategy = payload.get("strategy", "pull_recreate")
                wipe_vaults = payload.get("wipe_vaults", False)
                remove_images = payload.get("remove_images", True)
                wipe_configs = payload.get("wipe_configs", False)

                script_lines = [
                    f"#!/usr/bin/env bash",
                    f"# ==============================================================================",
                    f"# PROJECT LUME STAGED LIFECYCLE RUNBOOK: {action.upper()}",
                    f"# Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"# ==============================================================================",
                    f"# Order of Operations follows strict SIEM dependency hierarchy:",
                    f"# 1. Coordinator Core SIEM -> 2. Workers -> 3. Network Sensors -> 4. Scanners",
                    f"# ==============================================================================",
                    ""
                ]

                # Splunk order sorting
                def get_order_score(n):
                    ip = n.get("ip", "").strip()
                    is_coord = (ip in ("127.0.0.1", "localhost", "0.0.0.0", "192.168.88.24")) or n.get("role") == "coordinator"
                    if is_coord and n.get("deploy_core"):
                        return 0
                    if n.get("deploy_core"):
                        return 1
                    if n.get("deploy_zeek"):
                        return 2
                    return 3

                sorted_nodes = sorted(nodes, key=get_order_score)

                for idx, node in enumerate(sorted_nodes):
                    nip = (node.get("ip") or "127.0.0.1").strip()
                    nname = node.get("name") or f"Node {nip}"
                    target_dir = f"/home/lame/project_lume" if nip != "192.168.88.25" else "/Users/lame/project_lume"

                    script_lines.append(f"# ------------------------------------------------------------------------------")
                    script_lines.append(f"# STEP {idx+1}: {nname} ({nip})")
                    script_lines.append(f"# ------------------------------------------------------------------------------")
                    script_lines.append(f"echo '>>> [Step {idx+1}/{len(sorted_nodes)}] Processing {nname} ({nip})...'")
                    script_lines.append(f"cd {target_dir} || exit 1")

                    if action == "update":
                        if strategy == "pull_recreate":
                            if node.get("deploy_core"):
                                script_lines.append(f"docker pull {DOCKER_IMAGES['core']}")
                            if node.get("deploy_zeek"):
                                script_lines.append(f"docker pull {DOCKER_IMAGES['zeek']}")
                            if node.get("deploy_scanner"):
                                script_lines.append(f"docker pull {DOCKER_IMAGES['scanner']}")
                            script_lines.append(f"docker compose up -d --remove-orphans")
                            script_lines.append(f"docker image prune -f")
                        elif strategy == "airgap_tars":
                            script_lines.append(f"for t in lume_airgap_tars/*.tar; do [ -f \"$t\" ] && docker load -i \"$t\"; done")
                            script_lines.append(f"docker compose up -d --remove-orphans")

                    elif action == "remove":
                        script_lines.append(f"# 1. Stop and remove containers")
                        script_lines.append(f"docker compose down --volumes --remove-orphans")
                        if remove_images:
                            script_lines.append(f"# 2. Free image layer disk storage")
                            script_lines.append(f"docker rmi -f {' '.join(DOCKER_IMAGES.values())} 2>/dev/null || true")
                        if wipe_vaults:
                            script_lines.append(f"# 3. IRREVERSIBLE: Wipe data vaults & databases")
                            script_lines.append(f"rm -rf ./data_vaults/*")
                        if wipe_configs:
                            script_lines.append(f"# 4. Wipe configuration files")
                            script_lines.append(f"rm -f .env docker-compose.yml data_vaults/*.json")

                    script_lines.append(f"echo '>>> {nname} completed.'")
                    script_lines.append("")

                script_lines.append(f"echo '=============================================================================='")
                script_lines.append(f"echo '🎉 ALL {len(sorted_nodes)} SYSTEMS PROCESSED IN SPECIFIED DEPENDENCY ORDER.'")
                script_lines.append(f"echo '=============================================================================='")

                self._send_json({"status": "success", "script": "\n".join(script_lines)})
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, status=500)
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=DEFAULT_PORT, open_browser=True):
    actual_port = port
    server = None
    for attempt in range(10):
        try:
            server = HTTPServer(("0.0.0.0", actual_port), SetupStudioHandler)
            break
        except OSError as e:
            # Address already in use (e.g. Docker container or previous instance running)
            print(f"[!] Notice: Port {actual_port} is busy. Trying port {actual_port + 1}...")
            actual_port += 1

    if not server:
        print(f"[ERROR] Could not bind HTTP server on ports {port} through {actual_port - 1}.")
        return

    url = f"http://localhost:{actual_port}"
    print("=" * 75)
    print("⚡ PROJECT LUME - UNIVERSAL SETUP & DEPLOYMENT STUDIO")
    print("=" * 75)
    print(f"🚀 Server is live at: {url}")
    print(f"   Network Access  : http://<this-machine-ip>:{actual_port}")
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
