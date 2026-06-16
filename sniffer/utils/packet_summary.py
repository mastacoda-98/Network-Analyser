from dataclasses import asdict, dataclass

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP

from sniffer.utils.process_lookup import find_process_by_port


@dataclass
class PacketSummary:
    protocol: str = "OTHER"
    src_ip: str = "Not Found"
    dst_ip: str = "Not Found"
    src_port: int | None = None
    dst_port: int | None = None
    src_process: str | None = None
    dst_process: str | None = None
    dns_query: str | None = None
    raw_summary: str | None = None

    def load_from_packet(self, packet):
        self.raw_summary = packet.summary()

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            self.src_ip = ip_layer.src
            self.dst_ip = ip_layer.dst

        if packet.haslayer(DNS):
            self.protocol = "DNS"

            if packet.haslayer(DNSQR):
                query_name = packet[DNSQR].qname
                self.dns_query = query_name.decode().rstrip(".")

        elif packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            self.protocol = "TCP"
            self.src_port = tcp_layer.sport
            self.dst_port = tcp_layer.dport

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            self.protocol = "UDP"
            self.src_port = udp_layer.sport
            self.dst_port = udp_layer.dport

        elif packet.haslayer(ICMP):
            self.protocol = "ICMP"

        self.src_process = find_process_by_port(self.src_port, self.protocol)
        self.dst_process = find_process_by_port(self.dst_port, self.protocol)

        return self

    def to_dict(self):
        return (
            "protocol: \t{protocol}\n"
            "src_ip: \t{src_ip}\n"
            "dst_ip: \t{dst_ip}\n"
            "src_port: \t{src_port}\n"
            "src_process: \t{src_process}\n"
            "dst_port: \t{dst_port}\n"
            "dst_process: \t{dst_process}\n"
            "dns_query: \t{dns_query}\n"
            "raw_summary:\t{raw_summary}\n"
        ).format(**asdict(self))
