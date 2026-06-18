# Network-Analyser

A real-time CLI network packet analyzer built with Python, Scapy, and Rich. Captures live network traffic and provides an interactive terminal dashboard for packet inspection and traffic analytics.

## Features

- Live packet capture
- TCP, UDP, DNS, and ICMP parsing
- Protocol, IP, and port filtering
- Real-time Rich dashboard
- Protocol distribution analytics
- Top destination IPs and ports
- Recent packet activity feed
- Throughput monitoring

## Tech Stack

- Python 3.12
- Scapy
- Rich
- Poetry

## Requirements

### Linux / macOS

- Python 3.12+
- Poetry

### Windows

- Python 3.12+
- Poetry
- Npcap

Install Npcap:

https://npcap.com/

## Install Poetry

### Linux / macOS

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

### Windows (PowerShell)

```powershell
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```

Verify:

```bash
poetry --version
```

## Installation

```bash
git clone https://github.com/mastacoda-98/Network-Analyser.git
cd Network-Analyser
poetry install
```

## Usage

Linux / macOS:

```bash
sudo poetry run sniffer
```

Windows (Administrator terminal):

```bash
poetry run sniffer
```

Examples:

```bash
sudo poetry run sniffer --tcp
sudo poetry run sniffer --dns
sudo poetry run sniffer --port 443
sudo poetry run sniffer --ip 8.8.8.8
sudo poetry run sniffer --tcp --port 443
```

## CLI Options

| Option          | Description           |
| --------------- | --------------------- |
| `--tcp`         | Show only TCP packets |
| `--udp`         | Show only UDP packets |
| `--dns`         | Show only DNS packets |
| `--ip <IP>`     | Filter by IP address  |
| `--port <PORT>` | Filter by port        |

Press `Ctrl + C` to stop capturing.
