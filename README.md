# Network-Analyser

Network Packet Analyzer - Project Roadmap

CORE FEATURES (Must Be Implemented)

1. Live Packet Capture

- Capture packets from live network interfaces
- Display TCP and UDP traffic in real time

2. Protocol Detection

- Detect and classify TCP, UDP, DNS, and ICMP packets
- Display protocol type for each packet

3. DNS Monitoring

- Capture DNS queries and responses
- Show queried domains (e.g., youtube.com)

4. Packet/Header Inspection

- Extract Source IP
- Extract Destination IP
- Extract Source Port
- Extract Destination Port
- Extract protocol metadata

5. Protocol Filtering

- Filter by protocol (--tcp, --udp, --dns)
- Filter by IP (--ip)
- Filter by port (--port)

6. Traffic Statistics

- Total packets captured
- TCP packet count
- UDP packet count
- DNS packet count
- ICMP packet count

7. Protocol Distribution

- Percentage breakdown of protocols

8. Traffic Analytics

- Top destination IPs
- Top source IPs
- Top ports
- Most active endpoints

9. Interactive CLI Dashboard

- Built using Rich
- Live updating statistics
- Protocol distribution
- Packet counters
- Top IPs and ports

RESUME FEATURES MAPPING

Claim 1:
Built a real-time packet analyzer capable of monitoring TCP, UDP and DNS traffic.

Claim 2:
Implemented packet filtering, traffic analytics and packet inspection.

Claim 3:
Developed an interactive CLI dashboard with live packet statistics and protocol distribution.

OPTIONAL / ADVANCED FEATURES

10. Bandwidth Statistics
11. Packet Logging
12. Promiscuous Mode
13. TCP Flag Analysis
14. TTL Analysis

SYSTEMS / IMPRESSIVE PHASE

15. Raw Socket Engine

- Capture packets using socket.socket(...)

16. Manual Packet Parsing

- Parse IP/TCP/UDP/DNS headers manually

17. Dual Capture Backends

- Scapy Backend
- Raw Socket Backend

FINAL GOAL

A real-time CLI network analysis tool capable of:

- Capturing TCP, UDP, DNS traffic
- Inspecting packet headers
- Filtering traffic
- Monitoring DNS activity
- Showing live analytics and statistics
- Running through an interactive dashboard
- Optionally using raw sockets and manual packet parsing

Getting started — Tech, install & run

This repository provides a live, Rich-powered CLI network packet analyzer written for Python 3.12 using Scapy for capture and Rich for the terminal dashboard.

Tech stack

- Python 3.12
- Scapy (packet capture and parsing)
- Rich (live terminal dashboard)
- Poetry (dependency management & CLI entry)

Quick start

1. Clone the repo:

```bash
git clone https://github.com/youruser/network-analyser.git
cd network-analyser
```

2. Install dependencies with Poetry:

```bash
poetry install
```

3. Run the CLI dashboard (recommended):

```bash
poetry run sniffer
```

Run with filters (examples):

```bash
# show only TCP traffic
poetry run sniffer --tcp

# show only UDP traffic on port 53 (DNS)
poetry run sniffer --udp --port 53

# filter by IP and port
poetry run sniffer --ip 192.168.1.10 --port 443
```

Notes

- Capturing packets may require elevated privileges (raw sockets). Use the appropriate elevated command for your OS:
  - Linux / macOS: `sudo poetry run sniffer` (or `sudo python -m sniffer.main`)
  - Windows: run the terminal as Administrator and use `poetry run sniffer` (no `sudo` on Windows)
- Alternatively grant the process CAP_NET_RAW on Linux instead of running as root.
- If your system uses PEP 668 or restricts system installs, use the Poetry environment (`poetry run ...`) or a virtualenv.

CLI filters and packet parsing

- Protocol filters: `--tcp`, `--udp`, `--dns` — limit captured packets to the selected protocol(s).
- IP filter: `--ip <IP>` — only include packets where the source or destination matches the IP.
- Port filter: `--port <PORT>` — only include packets where the source or destination port matches.

Packet parsing

- Packets are parsed using Scapy into a `PacketSummary` dataclass with fields:
  - `timestamp` — epoch timestamp when the packet was seen
  - `packet_size` — total packet size in bytes
  - `protocol` — detected protocol (TCP, UDP, DNS, ICMP, OTHER)
  - `src_ip`, `dst_ip` — source and destination IPs
  - `src_port`, `dst_port` — source and destination ports when available
  - `summary` / `info` — human-readable summary for quick inspection

Traffic aggregation

- The dashboard aggregates counts, bytes transferred, top IPs and ports, protocol distribution, and recent packets in a live-updating Rich layout.

Troubleshooting

- If the dashboard appears frozen, verify the capture thread started and check permissions.
- Use `python -m sniffer.main` when debugging instead of the installed entrypoint.

Contributing

- Fork, make changes, and open a PR. Tests and CI are welcome.
