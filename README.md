# LanScope

**LanScope is a lightweight Windows-focused local network device analyzer written in Python.**

It provides visibility into the current network, discovers devices on the local subnet, collects IP/MAC information, attempts hostname and vendor identification, tracks previously observed devices, and exports scan results to structured files.

The project was created as a cybersecurity and networking portfolio project focused on local asset discovery and network visibility.

---

## Features

- Automatic detection of the active network interface
- Local IPv4 address and subnet information
- Default gateway detection
- DNS server information
- Network profile information
- Wi-Fi information when available:
  - SSID
  - BSSID
  - signal strength
  - channel
  - radio type
  - authentication method
  - cipher
- Local subnet device discovery
- IP address discovery
- MAC address discovery
- Hostname resolution
- MAC vendor lookup when available
- Basic device-type estimation
- Neighbor/ARP state information
- Ping latency measurement
- Detection of newly observed devices
- Tracking of previously discovered devices
- CSV export
- JSON device history
- No packet-sniffing driver required

---


## How It Works

LanScope follows a simple discovery workflow:

```text
Active Windows Network Interface
            ↓
Determine Local IP / Gateway / DNS
            ↓
Select Local Scan Range
            ↓
Probe Local Addresses
            ↓
Windows Neighbor / ARP Table
            ↓
IP + MAC Discovery
            ↓
Hostname / Vendor Enrichment
            ↓
Device Classification
            ↓
Terminal Table
            ↓
CSV / JSON Export
```

The project intentionally avoids low-level packet sniffing and does not require Npcap or Scapy.

---

## Example Output

```text
LanScope
Local Network Device Analyzer

Interface: Wi-Fi
Local IP: 192.168.1.42
Gateway: 192.168.1.1
Scan Network: 192.168.1.0/24

Detected Network Devices

Status   IP             MAC                Hostname      Device Type
KNOWN    192.168.1.1    AA:BB:CC:DD:EE:01 router        Router / Gateway
NEW      192.168.1.20   AA:BB:CC:DD:EE:02 laptop        Computer
NEW      192.168.1.31   AA:BB:CC:DD:EE:03 Unknown       Mobile / IoT
```

The values above are examples and do not represent a real network.

---

## Installation

### Requirements

- Windows 10 / Windows 11
- Python 3.12+
- pip

Clone the repository:

```bash
git clone https://github.com/GGtascher/lanscope.git
cd lanscope
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

---

## Usage

Run:

```powershell
python lanscope.py
```

LanScope will:

1. identify the active network interface;
2. determine the local network;
3. scan the local subnet;
4. read Windows neighbor information;
5. enrich discovered devices;
6. display the result in a terminal table;
7. save scan information locally.

Runtime files may include:

```text
known_devices.json
network_scan.csv
```

These files are excluded from Git because they may contain local network information.

---

## Security and Privacy

LanScope performs local network discovery.

It does not:

- upload scan results to external services;
- capture network payloads;
- execute code on discovered devices;
- exploit vulnerabilities;
- attempt authentication against discovered systems.

Scan results remain on the local machine.

Only use network discovery on networks you own or are authorized to analyze.

---

## Limitations

LanScope is a portfolio and learning project, not an enterprise network discovery platform.

Important limitations include:

- primarily designed for Windows;
- some devices may ignore ICMP requests;
- enterprise, university, hotel, or dormitory networks may use client isolation;
- devices behind another router cannot normally expose their MAC address through local ARP;
- vendor detection may be unavailable or incomplete;
- hostname resolution depends on the local network configuration;
- device-type classification is heuristic and may be inaccurate.

LanScope is not a vulnerability scanner.

---

## Technology Stack

- Python
- psutil
- Rich
- Windows PowerShell / networking commands
- ARP / Neighbor discovery
- TCP/IP networking
- CSV / JSON

---

## Project Goals

This project was built to practice:

- network discovery;
- TCP/IP fundamentals;
- Windows networking;
- asset visibility;
- Python automation;
- defensive security tooling;
- structured security reporting.

---

## Future Improvements

Possible future improvements:

- continuous monitoring mode;
- device connect/disconnect alerts;
- improved local MAC vendor database;
- historical scan comparison;
- network visualization;
- configurable scan ranges;
- IPv6 discovery;
- optional GUI.

---

## Author

**Dmytro Oliinyk**

Computer Science student focused on cybersecurity, SOC operations, network security, and defensive security development.

GitHub: [GGtascher](https://github.com/GGtascher)

---

## License

MIT License
