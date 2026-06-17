import argparse

from sniffer.capture import start_capture
from sniffer import dashboard


def build_parser():
    parser = argparse.ArgumentParser(description="Network packet analyzer")
    parser.add_argument("--tcp", action="store_true", help="Show only TCP packets")
    parser.add_argument("--udp", action="store_true", help="Show only UDP packets")
    parser.add_argument("--dns", action="store_true", help="Show only DNS packets")
    parser.add_argument("--ip", dest="ip_value", help="Filter packets by IP address")
    parser.add_argument("--port", dest="port_value", type=int, help="Filter packets by port")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    packet_filter = None
    if args.tcp or args.udp or args.dns or args.ip_value or args.port_value:
        packet_filter = {
            "tcp": args.tcp,
            "udp": args.udp,
            "dns": args.dns,
            "ip_value": args.ip_value,
            "port_value": args.port_value,
        }
    dashboard.run_dashboard(packet_filter=packet_filter)

