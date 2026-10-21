# LanScope

**LanScope is a lightweight Windows-focused local network device analyzer written in Python.**

It provides visibility into the active local network, discovers devices on the current subnet, collects IP and MAC information, attempts hostname and vendor identification, compares discovered devices with the previous scan, and exports results to structured files.

The project was created as a cybersecurity and networking portfolio project focused on local asset discovery, Windows networking, and network visibility.

## Features

- Automatic detection of the active network interface
- Local IPv4 address and subnet information
- Default gateway detection
- DNS server information
- Windows network profile information
- Wi-Fi information when available:
  - SSID
  - BSSID
  - signal strength
  - channel
  - radio type
  - authentication method
  - cipher
- Local subnet discovery
- IP and MAC address collection
- Hostname resolution
- MAC vendor lookup when available
- Basic device-type estimation
- Windows Neighbor / ARP state information
- Ping reachability and approximate probe timing
- Detection of devices not present in the previous scan
- Comparison with previous scan state
- CSV export
- JSON scan state
- No packet-sniffing driver required

## How It Works

LanScope follows a local discovery workflow:

```text
Active Windows Network Interface
            ↓
Local IP / Gateway / DNS
            ↓
Local Scan Range
            ↓
Address Probing
            ↓
Windows Neighbor / ARP Table
            ↓
IP + MAC Discovery
            ↓
Hostname / Vendor Enrichment
            ↓
Device Classification
            ↓
Previous Scan Comparison
            ↓
Terminal Output
            ↓
CSV / JSON Export
```

LanScope intentionally avoids low-level packet sniffing and does not require Npcap or Scapy.

## Example Output

```text
LanScope 2.0
Windows Local Network Analyzer

Interface: Wi-Fi
Local IPv4: 192.168.1.42
Gateway: 192.168.1.1
Scan Network: 192.168.1.0/24

Detected Network Devices

Status   IP             MAC                Hostname      Device Type
KNOWN    192.168.1.1    AA:BB:CC:DD:EE:01 router        Router / Gateway
NEW      192.168.1.20   AA:BB:CC:DD:EE:02 laptop        Computer
NEW      192.168.1.31   AA:BB:CC:DD:EE:03 Unknown       Mobile / IoT
```

The values above are fictional examples and do not represent a real network.

## Installation

### Requirements

- Windows 10 or Windows 11
- Python 3.12 or newer
- pip

Clone the repository:

```bash
git clone https://github.com/dmytrooliinyk-cyber/lanscope.git
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

Install the dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Run LanScope from the project directory:

```powershell
python lanscope.py
```

During a scan, LanScope:

1. identifies the active Windows network interface;
2. determines the local IPv4 network;
3. reads gateway and DNS information;
4. probes addresses on the local subnet;
5. reads Windows Neighbor / ARP information;
6. collects IP and MAC addresses;
7. attempts hostname and vendor enrichment;
8. estimates basic device types;
9. compares discovered devices with the previous scan state;
10. displays the results in the terminal;
11. saves local scan information.

Runtime files may include:

```text
known_devices.json
network_scan.csv
```

These files are excluded from Git because they may contain information about the user's local network.

### Output Files

`known_devices.json` stores the device state written by the most recent scan and is used for comparison during the next run.

`network_scan.csv` contains the structured results of the current scan.

These files are runtime data and should not be committed to the repository.

## Security and Privacy

LanScope performs local network discovery only.

It does not:

- upload scan results to external services;
- capture packet payloads;
- intercept network traffic;
- execute code on discovered devices;
- exploit vulnerabilities;
- attempt authentication against discovered systems;
- modify discovered devices.

Scan results remain on the local machine.

Only use network discovery on networks you own or are authorized to analyze.

## Limitations

LanScope is a portfolio and learning project, not an enterprise asset-discovery or network-monitoring platform.

Current limitations include:

- primarily designed for Windows;
- discovery depends on information visible from the current local network;
- some devices may ignore ICMP probes;
- university, hotel, dormitory, guest, and enterprise networks may use client isolation;
- devices behind another router normally do not expose their MAC addresses through local ARP;
- MAC vendor identification may be unavailable or incomplete;
- hostname resolution depends on local DNS and network configuration;
- device-type classification is heuristic and can be inaccurate;
- ping timing is an approximate probe measurement rather than a dedicated latency-monitoring system;
- JSON state is used for comparison with the previous scan rather than as a complete long-term asset history;
- IPv6 discovery is not currently implemented.

LanScope is not a vulnerability scanner.

## Technology Stack

- Python
- psutil
- Rich
- mac-vendor-lookup
- Windows PowerShell and networking commands
- Windows Neighbor / ARP discovery
- TCP/IP networking
- CSV and JSON

## Skills Demonstrated

The project demonstrates practical work with:

- TCP/IP fundamentals
- IPv4 networks and subnets
- ARP and neighbor discovery
- default gateways and DNS
- Windows network interfaces
- Wi-Fi information
- local asset discovery
- IP and MAC addressing
- hostname and vendor enrichment
- Python automation
- structured data export
- defensive network visibility

## Future Improvements

Possible future improvements include:

- persistent long-term device history
- historical scan comparison
- continuous monitoring mode
- device connect and disconnect alerts
- improved MAC vendor data
- configurable scan ranges
- network visualization
- IPv6 discovery
- optional graphical interface

## Author

**Dmytro Oliinyk**

Computer Science student focused on cybersecurity, networking, defensive security, and IT infrastructure.

GitHub: [dmytrooliinyk-cyber](https://github.com/dmytrooliinyk-cyber)

## License

MIT License
