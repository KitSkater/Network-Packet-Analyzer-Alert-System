# Network-Packet-Analyzer-Alert-System
# 🕵️ Raspberry Pi Network Analyzer

A lightweight, real-time network traffic analyzer built with Python and Scapy — designed to run on a Raspberry Pi connected via Ethernet or Wi-Fi. This tool captures and analyzes live packet data to help you monitor your home or lab network like a pro.

---

## 📊 Project Roadmap (Progress: **Level 1 - Basic Packet Capture**)

| Level | Milestone | Description | Status |
|-------|-----------|-------------|--------|
| 1️⃣ | **Basic Packet Capture** | Scapy-based CLI tool for capturing and parsing live traffic. | 🟢 Done |
| 2️⃣ | **Protocol Breakdown** | Identify TCP, UDP, ICMP, DNS; log counts and IPs. | ⚪ Planned |
| 3️⃣ | **Real-Time Stats** | Print rolling summaries every 10s (packets, IPs, ports). | ⚪ Planned |
| 4️⃣ | **Web API** | Flask-based backend to serve live traffic stats via JSON. | ⚪ Planned |
| 5️⃣ | **Live Dashboard** | Web UI with Chart.js showing live protocol/IP/port stats. | ⚪ Planned |
| 6️⃣ | **Export & Alerts** | Export logs to CSV & raise alerts on anomalies. | ⚪ Planned |

---

## ⚙️ Setup Instructions

### 🔧 Requirements

- Raspberry Pi (3 or later)
- Python 3.7+
- OS: Raspberry Pi OS or Debian-based distro
- Internet connection for installing dependencies

### 📦 Installation

```bash
sudo apt update
sudo apt install python3-pip tshark -y
pip3 install scapy pyshark matplotlib flask
