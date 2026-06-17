from dataclasses import asdict, dataclass


@dataclass
class PacketSummary:
    protocol: str = "OTHER"
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    dns_query: str | None = None
    raw_summary: str | None = None

    def load_from_packet(self, packet):
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import ICMP, IP, TCP, UDP

        self.raw_summary = packet.summary()

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            self.src_ip = ip_layer.src
            self.dst_ip = ip_layer.dst

        if packet.haslayer(DNS):
            self.protocol = "DNS"

            if packet.haslayer(UDP):
                self.src_port = packet[UDP].sport
                self.dst_port = packet[UDP].dport
                
            if packet.haslayer(DNSQR):
                query_name = packet[DNSQR].qname
                self.dns_query = query_name.decode(errors="ignore").rstrip(".")

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

        return self

    def to_dict(self):
        return asdict(self)

    def format_output(self):
        source = self.format_endpoint(self.src_ip, self.src_port)
        destination = self.format_endpoint(self.dst_ip, self.dst_port)
        output = f"{self.protocol:<5} {source} -> {destination}"

        if self.dns_query:
            output = f"{output} | DNS: {self.dns_query}"

        return output

    def format_endpoint(self, ip_value, port):
        endpoint = ip_value

        if port:
            endpoint = f"{endpoint}:{port}"

        return endpoint
