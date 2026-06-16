from scapy.all import sniff

from sniffer.utils.packet_summary import PacketSummary


def handle_packet(packet):
    summary = PacketSummary()
    summary.load_from_packet(packet)
    print(summary.to_dict())


def start_capture():
    print("Starting packet capture...")
    sniff(prn=handle_packet, store=False, count=5)
