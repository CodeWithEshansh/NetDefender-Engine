# Firewall Engine Simulator

> A stateful firewall engine with intrusion detection, payload inspection, and a real-time GUI dashboard — built for cybersecurity education and demonstration.

<br>

![Python](https://img.shields.io/badge/Python-3.10-4B8BBE?style=flat-square&logo=python&logoColor=white)
![Type](https://img.shields.io/badge/Type-Simulator-6A5ACD?style=flat-square)
![Security](https://img.shields.io/badge/Security-IDS%2FIPS-B22222?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-2E8B57?style=flat-square)
![License](https://img.shields.io/badge/License-Educational-DAA520?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Core Concepts](#core-concepts)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Sample Output](#sample-output)
- [Feature Status](#feature-status)
- [Limitations & Roadmap](#limitations--roadmap)
- [Author](#author)

---

## Overview

The **Firewall Engine Simulator** is a Python-based educational tool that replicates the behavior of a modern stateful firewall. It tracks TCP/UDP sessions, inspects packet payloads for known attack signatures, and surfaces all activity through an interactive GUI dashboard.

This project is intended for students, educators, and cybersecurity enthusiasts who want a hands-on look at how firewalls and intrusion detection systems (IDS) function at a conceptual level.

---

## Features

| Category | Capability |
|---|---|
| Packet Inspection | Stateful TCP & UDP tracking |
| Session Management | Connection tracking with timeout handling |
| Threat Detection | SQL Injection, XSS, Command Injection |
| Network Attacks | DDoS threshold detection, Port scan detection |
| Access Control | IP blocking & whitelisting |
| Simulation | Real-time traffic generation & attack simulation |
| Interface | Interactive GUI dashboard |

---

## Core Concepts

- **Stateful Firewall Architecture** — tracks the state of active connections rather than inspecting each packet in isolation
- **Intrusion Detection System (IDS)** — monitors traffic for known malicious patterns
- **Packet Filtering & Validation** — enforces structural correctness before deeper inspection
- **TCP State Management** — models the SYN → ESTABLISHED → ACK handshake lifecycle
- **Signature-based Detection** — matches payloads against a library of known attack strings

---

## Project Structure

```
firewall-simulator/
├── main.py               # Entry point
├── firewall/             # Core firewall engine
├── detector/             # IDS / signature matching
├── simulator/            # Traffic & attack simulation
├── utils/                # Shared utilities
├── assets/               # Screenshots, demo GIF
└── README.md
```

---

## Installation

**Prerequisites:** Python 3.10+

```bash
# Clone the repository
git clone https://github.com/CodeWithEshansh/firewall-simulator.git

# Navigate into the project directory
cd firewall-simulator

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py
```

### GUI Controls

| Control | Action |
|---|---|
| Start | Begin real-time packet simulation |
| Stop | Halt the simulation |
| Simulate Attack → SQL Injection | Fire a SQL injection payload |
| Simulate Attack → XSS | Fire a cross-site scripting payload |
| Simulate Attack → Command Injection | Fire a shell command injection payload |

---

## How It Works

The simulator processes each packet through a sequential pipeline:

**1. Packet Generation**
Synthetic traffic is generated to mimic real-world network behavior across a range of source IPs and destination ports.

**2. Validation Layer**
Each packet is checked for structural integrity before being passed deeper into the engine.

**3. Security Checks**
- High-frequency traffic from a single source triggers DDoS detection
- Rapid sequential port access triggers port scan detection

**4. Payload Inspection**
Packet payloads are scanned against known malicious signatures, including:
- `DROP TABLE` — SQL injection
- `<script>` — Cross-site scripting
- `rm -rf` — Command injection

**5. Stateful Handling**
TCP connections are tracked across states: `SYN` → `ESTABLISHED` → `ACK`

**6. Decision Engine**
Based on all prior checks, each packet is either allowed or blocked. Results are logged and reflected live in the dashboard.

---

## Sample Output

```
[ALLOWED]  192.168.1.10  →  Port 80    HTTP request
[BLOCKED]  1.1.1.1       →  Port 443   SQL Injection detected
[BLOCKED]  5.5.5.5       →  Port 80    DDoS threshold exceeded
[BLOCKED]  9.9.9.9       →  Port 22    Port scan detected
```

---

## Feature Status

| Feature | Status |
|---|---|
| Stateful packet inspection | Complete |
| Payload signature matching | Complete |
| DDoS detection | Complete |
| Port scan detection | Complete |
| GUI dashboard | Complete |
| Real packet capture (Scapy/pcap) | Planned |
| ML-based anomaly detection | Planned |
| Rule-based configuration UI | Planned |
| Database logging | Planned |
| Web-based dashboard | Planned |

---

## Limitations & Roadmap

**Current Limitations**

- Operates in a fully simulated environment — no live packet capture
- Detection is signature-based only; no behavioral or anomaly analysis
- No Deep Packet Inspection (DPI) support

**Planned Improvements**

- Integrate Scapy or libpcap for real network traffic capture
- Add machine learning-based anomaly detection
- Build a rule engine for user-defined firewall policies
- Persistent logging to file or database
- Replace the desktop GUI with a web-based dashboard

---

## Author

**Eshansh Verma**
Engineering Student · Cybersecurity Enthusiast

---

*If this project was useful to you, consider starring the repository.*
