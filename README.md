# 🔥 Firewall Engine Simulator

A **stateful firewall engine simulator** with built-in **attack detection** and a **real-time GUI dashboard**.  
This project demonstrates how modern firewalls track connections, inspect packets, and block malicious traffic.

---

## 🚀 Features

- ✅ Stateful packet inspection (TCP & UDP)
- ✅ Session tracking with timeout handling
- ✅ Payload inspection for:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
- ✅ DDoS detection (packet threshold-based)
- ✅ Port scan detection
- ✅ IP blocking & whitelisting
- ✅ Real-time traffic simulation
- ✅ Interactive GUI dashboard
- ✅ Attack simulation (SQL, XSS, CMD)

---

## 🧠 Core Concepts Implemented

- Stateful Firewall Architecture  
- Intrusion Detection Techniques  
- Packet Filtering & Validation  
- Connection State Management (SYN, ACK, etc.)  
- Basic Network Attack Detection  

---

## 📁 Project Structure
.
├── main.py # Main application (Firewall + GUI)
├── device/ # (Optional modular components)
├── server/ # (Optional server integration)
└── README.md


---

## ⚙️ Installation

1. Clone the repository:

2. Install dependencies (if needed):
pip install -r requirements.txt

3. ▶️ Usage
Run the application:
python main.py

4. 🖥️ GUI Controls
Start → Begin packet simulation
Stop → Stop simulation
Simulate Attack → Trigger:
SQL Injection
XSS Attack
Command Injection

5. How It Works
Packet Generation
   a. Simulated traffic mimics real network packets
Validation Layer
   a. Ensures packet structure is correct
Security Checks
  Detects:
    a. DDoS (high packet rate)
    b. Port scanning
Payload Inspection
  Blocks malicious patterns:
    a. DROP TABLE
    b. <script>
    c. rm -rf
Stateful Handling
   Tracks TCP states:
    a. SYN → ESTABLISHED → ACK
Decision Engine
    a. Allows or blocks packet
    b. Updates stats & logs

6. 📊 Output
Allowed Packets → Green log panel
Blocked Packets → Red log panel
Live Stats → Allowed vs Blocked count

7. 🎯 Use Cases
Learning firewall internals
Cybersecurity demonstrations
Academic projects
IDS/IPS concept visualization

8. ⚠️ Limitations
Simulated environment (not real packet capture)
Basic pattern-based detection (no ML)
No deep packet inspection (DPI)

9. 🔮 Future Improvements
Real packet capture (Scapy / pcap)
Machine Learning-based detection
Rule-based firewall configuration
Logging to files / database
Web-based dashboard

10. 👨‍💻 Author
Eshansh Verma

11. 📄 License
This project is for educational purposes.
