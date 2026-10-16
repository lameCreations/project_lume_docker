# ⚡ Project Lume

> **High-Performance Autonomous Security Operations & Log Intelligence**  
> *Enterprise visibility without the enterprise hardware bloat or licensing tax.*

Project Lume is a next-generation security and log analytics engine engineered from the ground up for modern networks, OT/ICS enclaves, and distributed edge environments. 

Traditional SIEM platforms punish organizations with crushing hardware footprints, complex cluster management, and exorbitant per-gigabyte ingest fees. Project Lume flips the script: delivering sub-second queries, massive compression, and out-of-the-box threat detection on a fraction of the hardware—whether deployed on an air-gapped forensic laptop, an on-prem server, or a tactical edge sensor.

---

## 🌟 Why Project Lume?

- **⚡ Hardware Efficiency That Defies Gravity:** Ingest and search millions of events across network, host, and telemetry streams on standard hardware without needing a multi-node cluster or endless memory.
- **📉 Radical Storage Reduction:** Advanced columnar deduplication and compaction reduce raw log footprints by up to 90%, eliminating runaway disk and cloud storage costs.
- **🛡️ Built for Hybrid IT & Industrial OT:** Native awareness for deep network protocol telemetry (Zeek, Suricata, NetFlow, WireGuard), ICS/SCADA industrial protocols, and host audit feeds.
- **🎯 Low-Overhead Autonomous Triage:** Designed specifically for teams that don't have a 10-person security engineering staff just to write query syntax and maintain databases. Instant answers out of the box.
- **🔒 Complete Data Sovereignty:** 100% self-contained. Runs anywhere Docker runs—fully capable in air-gapped, classified, or zero-trust enclaves with zero external cloud dependencies.

---

## 🚀 Quickstart: Deploy in Seconds

This repository provides everything you need to bootstrap and evaluate a live Project Lume instance in two minutes.

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) installed and running:
  - **Linux:** Native Docker Engine (`docker compose`)
  - **macOS & Windows:** Docker Desktop

---

### Option A: Instant 1-Command Launch

If you want standard defaults and immediate access:

1. Download or clone this repository:
```bash
git clone https://github.com/<your-org>/project-lume-docker.git
cd project-lume-docker
```

2. Start the container stack:
```bash
docker compose up -d
```

3. Open your browser to the Project Lume Command Center:
```text
http://localhost:9000
```

*(All telemetry, configurations, and forensic vaults persist safely in your local directory).*

---

### Option B: Interactive Deployment Studio (`lume_setup_studio.py`)

Need to customize ports, allocate specific memory caps, configure remote sensor forwarders, or generate tailored compose stacks for specific environments?

We include a visual deployment utility right in this repository:

1. Run the interactive setup studio:
```bash
python3 lume_setup_studio.py
```

2. Open your browser to `http://localhost:5002` (or the terminal-provided link).

3. Visually configure:
   - System memory limits & multi-core resource allocation
   - Syslog ports (UDP/TCP 514 & 1514)
   - Host filesystem sensor attachments & live network interfaces
   - Single-click generation of hardened `docker-compose.yml` configurations tailored to your host OS (Linux, macOS, Windows)

---

## 📊 Default Ports & Services

| Port / Protocol | Service | Purpose |
| :--- | :--- | :--- |
| **9000 / TCP** | **Lume Command Center & API** | Interactive UI, search console, threat investigations |
| **514 / UDP & TCP** | **Standard Syslog Receiver** | Ingest network switch, firewall, and host syslog |
| **1514 / UDP & TCP** | **High-Volume Extended Telemetry** | High-throughput sensor feeds & agent log streams |

---

## 📦 What's Under the Hood?

Project Lume packages:
- **Autonomous Core Engine:** Real-time log ingestion, compaction, and columnar indexing.
- **Integrated Threat Intelligence:** Instant matching against emerging C2 traffic, CVEs, and anomalous activity.
- **Interactive Command Center:** Unified dashboard for threat hunting, incident investigation, and asset discovery.
- **Plug-and-Play Ingestion:** Compatible with standard forwarders (Vector, Fluent Bit, Syslog-ng, Rsyslog) and network inspection tools (Zeek, Suricata).

---

## 🛠️ Stopping or Updating

To cleanly stop the engine without losing any vault data:
```bash
docker compose down
```

To pull the latest engine updates published to Docker Hub:
```bash
docker compose pull
docker compose up -d
```

---

<p align="center">
  <b>Project Lume</b> — <i>The SIEM you didn't know you couldn't live without.</i>
</p>
