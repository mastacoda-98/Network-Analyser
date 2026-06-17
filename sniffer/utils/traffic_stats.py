from time import time
from collections import Counter, deque
from dataclasses import dataclass, field


COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    25: "SMTP",
}


def _format_top_entries(counter, label):
    entries = counter.most_common(3)

    if not entries:
        return f"{label}: none"

    formatted_entries = ", ".join(f"{value} ({count})" for value, count in entries)
    return f"{label}: {formatted_entries}"


def _format_port_label(port_value):
    if port_value is None:
        return "unknown"

    protocol_name = COMMON_PORTS.get(port_value)

    if protocol_name:
        return f"{port_value} ({protocol_name})"

    return str(port_value)


def _format_endpoint(ip_value, port_value):
    if port_value is None:
        return ip_value

    return f"{ip_value}:{port_value}"


@dataclass
class TrafficStats:
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    dns_packets: int = 0
    icmp_packets: int = 0
    bytes_transferred: int = 0
    recent_packets: deque = field(default_factory=lambda: deque(maxlen=20))
    last_packet_ts: float = 0.0
    capture_started: bool = False
    capture_error: str | None = None
    source_ips: Counter = field(default_factory=Counter)
    destination_ips: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    endpoints: Counter = field(default_factory=Counter)

    def record(self, protocol):
        self.total_packets += 1

        protocol = (protocol or "OTHER").upper()

        if protocol == "TCP":
            self.tcp_packets += 1
        elif protocol == "UDP":
            self.udp_packets += 1
        elif protocol == "DNS":
            self.dns_packets += 1
        elif protocol == "ICMP":
            self.icmp_packets += 1

    def record_packet(self, summary, packet_filter: dict | None = None):
        if packet_filter:
            pf = packet_filter
            if pf.get("tcp") and summary.protocol != "TCP":
                return
            if pf.get("udp") and summary.protocol != "UDP":
                return
            if pf.get("dns") and summary.protocol != "DNS":
                return
            ip_value = pf.get("ip_value")
            if ip_value and ip_value not in (summary.src_ip, summary.dst_ip):
                return
            port_value = pf.get("port_value")
            if port_value and port_value not in (summary.src_port, summary.dst_port):
                return

        self.record(summary.protocol.upper())
        self.bytes_transferred += summary.packet_size
        self.last_packet_ts = time()
        try:
            self.recent_packets.appendleft((summary.protocol, summary.src_ip or "", summary.dst_ip or "", summary.packet_size, summary.src_port, summary.dst_port))
        except Exception:
            pass

        if summary.src_ip:
            self.source_ips[summary.src_ip] += 1

        if summary.dst_ip:
            self.destination_ips[summary.dst_ip] += 1

        if summary.src_ip and summary.src_port:
            self.ports[summary.src_port] += 1

        if summary.dst_ip and summary.dst_port:
            self.ports[summary.dst_port] += 1

        if summary.src_ip:
            self.endpoints[_format_endpoint(summary.src_ip, summary.src_port)] += 1

        if summary.dst_ip:
            self.endpoints[_format_endpoint(summary.dst_ip, summary.dst_port)] += 1

    def protocol_distribution(self):
        if self.total_packets == 0:
            return {
                "TCP": 0.0,
                "UDP": 0.0,
                "DNS": 0.0,
                "ICMP": 0.0,
            }

        return {
            "TCP": (self.tcp_packets / self.total_packets) * 100,
            "UDP": (self.udp_packets / self.total_packets) * 100,
            "DNS": (self.dns_packets / self.total_packets) * 100,
            "ICMP": (self.icmp_packets / self.total_packets) * 100,
        }

    def format_output(self):
        if self.bytes_transferred < 1024:
            bytes_str = f"{self.bytes_transferred}B"
        elif self.bytes_transferred < 1024 * 1024:
            bytes_str = f"{self.bytes_transferred / 1024:.1f}KB"
        else:
            bytes_str = f"{self.bytes_transferred / (1024 * 1024):.1f}MB"

        return (
            "Packets: "
            f"total={self.total_packets} "
            f"TCP={self.tcp_packets} "
            f"UDP={self.udp_packets} "
            f"DNS={self.dns_packets} "
            f"ICMP={self.icmp_packets} "
            f"| Bytes: {bytes_str}"
        )

    def format_distribution_output(self):
        distribution = self.protocol_distribution()

        return (
            "Distribution: "
            f"TCP={distribution['TCP']:.1f}% "
            f"UDP={distribution['UDP']:.1f}% "
            f"DNS={distribution['DNS']:.1f}% "
            f"ICMP={distribution['ICMP']:.1f}%"
        )

    def format_analytics_output(self):
        port_entries = self.ports.most_common(3)
        formatted_ports = ", ".join(
            f"{_format_port_label(port)} ({count})" for port, count in port_entries
        )

        if not formatted_ports:
            formatted_ports = "none"

        return (
            "Analytics: "
            f"{_format_top_entries(self.destination_ips, 'top_dst_ips')} | "
            f"{_format_top_entries(self.source_ips, 'top_src_ips')} | "
            f"top_ports: {formatted_ports} | "
            f"{_format_top_entries(self.endpoints, 'active_endpoints')}"
        )