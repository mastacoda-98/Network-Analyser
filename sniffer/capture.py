from scapy.all import sniff

from sniffer.utils.packet_summary import PacketSummary
from sniffer.utils.traffic_stats import TrafficStats


traffic_stats = TrafficStats()


def build_packet_filter(tcp=False, udp=False, dns=False, ip_value=None, port_value=None):
    return {
        "tcp": tcp,
        "udp": udp,
        "dns": dns,
        "ip_value": ip_value,
        "port_value": port_value,
    }


def should_include_packet(summary, packet_filter):
    if packet_filter["tcp"] and summary.protocol != "TCP":
        return False

    if packet_filter["udp"] and summary.protocol != "UDP":
        return False

    if packet_filter["dns"] and summary.protocol != "DNS":
        return False

    ip_value = packet_filter["ip_value"]

    if ip_value and ip_value not in (summary.src_ip, summary.dst_ip):
        return False

    port_value = packet_filter["port_value"]

    if port_value and port_value not in (summary.src_port, summary.dst_port):
        return False

    return True


def handle_packet(packet, packet_filter):
    summary = PacketSummary()
    summary.load_from_packet(packet)

    if not should_include_packet(summary, packet_filter):
        return

    traffic_stats.record_packet(summary)
    print(summary.format_output())


def start_capture(tcp=False, udp=False, dns=False, ip_value=None, port_value=None):
    packet_filter = build_packet_filter(
        tcp=tcp,
        udp=udp,
        dns=dns,
        ip_value=ip_value,
        port_value=port_value,
    )

    print("Starting packet capture...")
    sniff(prn=lambda packet: handle_packet(packet, packet_filter), store=False, count=50)
    print(traffic_stats.format_output())
    print(traffic_stats.format_distribution_output())
    print(traffic_stats.format_analytics_output())
