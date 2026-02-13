<div align="center">
  <h1>AEGIS FORTRESS XDR</h1>
  <p>
    <strong>The World's First Open‑Source, Kernel‑Native Extended Detection and Response Platform for Critical Infrastructure</strong>
  </p>
  <p>
    <a href="https://github.com/ss7zx/aegis-fortress-xdr/actions"><img src="https://img.shields.io/github/actions/workflow/status/ss7zx/aegis-fortress-xdr/ci.yml?branch=main&style=flat-square" alt="Build Status"></a>
    <a href="https://github.com/ss7zx/aegis-fortress-xdr/releases"><img src="https://img.shields.io/github/v/release/ss7zx/aegis-fortress-xdr?style=flat-square" alt="Release"></a>
    <a href="https://github.com/ss7zx/aegis-fortress-xdr/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ss7zx/aegis-fortress-xdr?style=flat-square" alt="License"></a>
    <a href="https://discord.gg/your-invite"><img src="https://img.shields.io/discord/1234567890?style=flat-square&logo=discord" alt="Discord"></a>
    <a href="https://twitter.com/aegisfortress"><img src="https://img.shields.io/twitter/follow/aegisfortress?style=flat-square&logo=twitter" alt="Twitter"></a>
  </p>
  <p>
    <a href="#-features">Features</a> •
    <a href="#-architecture">Architecture</a> •
    <a href="#-quick-start">Quick Start</a> •
    <a href="#-documentation">Documentation</a> •
    <a href="#-community">Community</a> •
    <a href="#-contributing">Contributing</a>
  </p>
  <br>
  <img src="docs/images/dashboard-preview.png" alt="AEGIS FORTRESS XDR Dashboard" width="800">
  <br>
  <em>Real‑time threat detection and automated response for critical infrastructure</em>
</div>

---

## 🌟 Introduction

**AEGIS FORTRESS XDR** is an advanced, open‑source Extended Detection and Response platform purpose‑built to protect the world’s most critical infrastructure—power grids, water treatment plants, healthcare systems, and financial networks. It combines **kernel‑level visibility** (eBPF), **AI‑driven analytics**, **automated response orchestration**, and **deception technologies** into a unified, scalable, and transparent defense system.

Born from the **AEGIS FORTRESS EDR v5.1** kernel sensor, this project expands to cover networks, cloud workloads, and identity systems, providing defenders with a single pane of glass and the ability to stop sophisticated adversaries before they cause harm.

**Why AEGIS FORTRESS XDR?**
- **Kernel‑Native**: eBPF sensors provide unparalleled visibility with minimal overhead.
- **Critical Infrastructure Focus**: Deep ICS protocol support (Modbus, DNP3, IEC 104) and OT‑specific detection.
- **AI‑Powered**: Machine learning models detect unknown threats and reduce false positives.
- **Automated Response**: SOAR playbooks contain threats in seconds—isolate endpoints, block IPs, rotate credentials.
- **Deception**: Honeypots and honeytokens lure attackers and gather intelligence.
- **Open & Auditable**: No black boxes; fully transparent code you can trust.

---

## ✨ Features

| Area | Capabilities |
|------|--------------|
| **Endpoint** | eBPF sensors for file, process, network, and registry events on Linux & Windows (eBPF for Windows). Real‑time blocking of malicious activity. |
| **Network** | Zeek metadata, Suricata IDS, custom ICS protocol dissectors (Rust) for Modbus, DNP3, IEC 104. Flow analytics for beaconing detection. |
| **Cloud** | Ingests AWS CloudTrail, Azure Monitor, GCP Audit Logs. Detects misconfigurations and anomalous API calls. |
| **Detection Engine** | Unsupervised (autoencoders) and supervised (XGBoost) ML models. Time‑series forecasting for ransomware. Explainable AI (SHAP). |
| **SOAR** | TheHive for case management, Cortex for enrichment, Shuffle for playbooks. Automated actions: process kill, network isolation, honeypot deployment. |
| **Deception** | Conpot (ICS honeypots), Cowrie (SSH), custom decoys. Adaptive deployment upon scan detection. |
| **Threat Intel** | MISP integration – consume and share IOCs (STIX/TAXII). |
| **Dashboard** | Real‑time React UI with graphs, process trees, incident timelines, and reporting (PDF/CSV). |
| **Self‑Healing** | Golden images, Infrastructure as Code (Terraform) to rebuild compromised assets automatically. |

---

## 🏗️ Architecture

A high‑level view of the platform components:
┌─────────────────────────────────────────────────────────────────┐
│ AEGIS FORTRESS XDR │
├───────────────┬────────────────┬───────────────┬───────────────┤
│ Endpoint │ Network │ Cloud │ Identity │
│ Agents │ Sensors │ Logs │ Logs │
├───────────────┴────────────────┴───────────────┴───────────────┤
│ Data Ingestion & Normalization │
│ (Kafka + ECS) │
├───────────────┬────────────────┬───────────────┬───────────────┤
│ AI/ML │ Deception │ SOAR │ Threat Intel │
│ Detection │ Fabric │ (TheHive, │ (MISP) │
│ Engine │ │ Shuffle) │ │
├───────────────┴────────────────┴───────────────┴───────────────┤
│ Unified Dashboard & API │
│ (React + Go) │
└─────────────────────────────────────────────────────────────────┘

For detailed component diagrams and data flows, see our [Architecture Documentation](docs/ARCHITECTURE.md).

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose (for local testing)
- Linux kernel ≥ 5.4 (for eBPF features)
- 8 GB RAM, 4 CPUs recommended

### One‑Command Lab Deployment
```bash
git clone https://github.com/ss7zx/aegis-fortress-xdr.git
cd aegis-fortress-xdr
docker-compose up -d
```

This spins up:

A minimal Kafka cluster

Zeek + Suricata sensors

TheHive, Cortex, Shuffle

A sample dashboard (React)

One simulated endpoint with the eBPF agent

Access the dashboard at http://localhost:3000 (default credentials: admin / aegis123).

⚠️ This is a development environment. For production deployment, see our Installation Guide.

📚 Documentation
Full documentation is available in the docs/ folder:

Installation Guide – bare‑metal, Kubernetes, cloud

User Manual – using the dashboard, creating playbooks

Agent Deployment – deploying eBPF agents on endpoints

API Reference – REST & GraphQL endpoints

Contributing Guide – how to get involved

Security Policies – reporting vulnerabilities

We also maintain a Wiki with tutorials and best practices.

📚 Documentation
Full documentation is available in the docs/ folder:

Installation Guide – bare‑metal, Kubernetes, cloud

User Manual – using the dashboard, creating playbooks

Agent Deployment – deploying eBPF agents on endpoints

API Reference – REST & GraphQL endpoints

Contributing Guide – how to get involved

Security Policies – reporting vulnerabilities

We also maintain a Wiki with tutorials and best practices.

🧑‍🤝‍🧑 Community
Join our growing community of defenders, developers, and researchers:

💬 Discord – real‑time chat

🐦 Twitter – project updates

📧 Mailing List – announcements

🗓️ Community Calls – monthly video meetings

We welcome contributors of all skill levels. Check out our good first issues to get started.

🤝 Contributing
We believe that open source security is stronger together. Whether you’re fixing a bug, writing documentation, or proposing a new feature, your help is appreciated.

Read the Contributing Guide.

Fork the repository and create a feature branch.

Make your changes, ensuring tests pass (make test).

Open a pull request with a clear description.

By participating, you agree to abide by our Code of Conduct.

📄 License
AEGIS FORTRESS XDR is dual‑licensed:

Core components (agent, sensors, detection engine) are under Apache License 2.0.

Enterprise plugins (optional) are under a commercial license.

See LICENSE for details.

🌍 Impact & Vision
Our mission is to democratize advanced cybersecurity for the organizations that protect our society. By open‑sourcing AEGIS FORTRESS XDR, we enable:

Utilities to defend against nation‑state attacks.

Hospitals to ensure patient safety.

Manufacturing to prevent costly downtime.

Governments to build sovereign security capabilities.

We collaborate with CERTs, ISACs, and academic institutions to share threat intelligence and advance the state of the art. Together, we can build a safer digital world.

🙏 Acknowledgements
This project builds upon the incredible work of the open‑source community:

eBPF – kernel instrumentation

Zeek – network analysis

Suricata – intrusion detection

TheHive – incident response

Cortex – observable analysis

Shuffle – SOAR workflows

MISP – threat intelligence

Elastic Common Schema – data normalization

And countless others…

<div align="center"> <strong>Defend the future. Join AEGIS FORTRESS XDR.</strong><br> <a href="https://github.com/ss7zx/aegis-fortress-xdr">GitHub</a> • <a href="https://discord.gg/your-invite">Discord</a> • <a href="https://twitter.com/aegisfortress">Twitter</a> </div> 
