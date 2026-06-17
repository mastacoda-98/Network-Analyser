# Network-Analyser

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
git clone https://github.com/mastacoda-98/Network-Analyser.git
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
