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
