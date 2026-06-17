from threading import Thread
import time
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Group
from rich import box
from rich.align import Align
from sniffer.capture import start_capture
from sniffer.utils.traffic_stats import TrafficStats, _format_port_label


def build_protocol_table(stats: TrafficStats):
    table = Table(title="Protocols", box=box.SIMPLE)
    table.add_column("Protocol", style="bold")
    table.add_column("%", justify="right")

    dist = stats.protocol_distribution()
    rows = [
        ("TCP", dist.get("TCP", 0.0), "green"),
        ("UDP", dist.get("UDP", 0.0), "yellow"),
        ("DNS", dist.get("DNS", 0.0), "cyan"),
        ("ICMP", dist.get("ICMP", 0.0), "red"),
        ("OTHER", 100.0 - sum((dist.get(k, 0.0) for k in ("TCP", "UDP", "DNS", "ICMP"))), "white"),
    ]

    rows.sort(key=lambda r: r[1], reverse=True)

    for name, pct, style in rows:
        table.add_row(name, f"{pct:.1f}%", style=style)
    return table


def build_top_ports_panel(stats: TrafficStats):
    table = Table(title="Top Destination Ports", box=box.SIMPLE)
    table.add_column("Port", style="bold")
    table.add_column("Count", justify="right")
    for port, count in stats.ports.most_common(5):
        label = _format_port_label(port)
        table.add_row(label, str(count))
    return table


def build_top_ips_panel(stats: TrafficStats):
    table = Table(title="Top Destination IPs", box=box.SIMPLE)
    table.add_column("IP", style="bold")
    for ip, _ in stats.destination_ips.most_common(5):
        table.add_row(ip)
    return table

def build_recent_panel(stats: TrafficStats):
    table = Table(title="Recent Packets", box=box.SIMPLE)
    table.add_column("Proto", justify="center", width=8)
    table.add_column("Source", justify="left")
    table.add_column("Destination", justify="left")
    table.add_column("Size", justify="right", width=8)
    for item in list(stats.recent_packets):
        if len(item) == 6:
            proto, src, dst, size, src_port, dst_port = item
        else:
            proto, src, dst, size = item
            src_port = None
            dst_port = None
        style = ""
        if proto == "TCP":
            style = "green"
        elif proto == "UDP":
            style = "yellow"
        elif proto == "DNS":
            style = "cyan"
        elif proto == "ICMP":
            style = "red"

        src_display = f"{src}:{src_port}" if src_port else src
        dst_display = f"{dst}:{dst_port}" if dst_port else dst
        table.add_row(proto, src_display, dst_display, f"{size}B", style=style)

    return table


def run_dashboard(packet_filter: dict | None = None):
    stats = TrafficStats()

    # start capture in a background thread and share stats
    # prepare capture kwargs and start capture thread
    capture_kwargs = {
        "tcp": False,
        "udp": False,
        "dns": False,
        "ip_value": None,
        "port_value": None,
        "traffic_stats": stats,
        "suppress_stdout": True,
    }

    if packet_filter:
        capture_kwargs["tcp"] = packet_filter.get("tcp", False)
        capture_kwargs["udp"] = packet_filter.get("udp", False)
        capture_kwargs["dns"] = packet_filter.get("dns", False)
        capture_kwargs["ip_value"] = packet_filter.get("ip_value")
        capture_kwargs["port_value"] = packet_filter.get("port_value")

    capture_thread = Thread(target=start_capture, kwargs=capture_kwargs, daemon=True)
    capture_thread.start()

    layout = Layout()
    if packet_filter:
        layout.split_column(Layout(name="header", size=5), Layout(name="recent", size=0))
        layout["recent"].split_row(Layout(name="recent_table"))
    else:
        layout.split_column(Layout(name="header", size=3), Layout(name="upper", size=12), Layout(name="lower", size=20))
        layout["upper"].split_row(Layout(name="protocols"), Layout(name="ports"), Layout(name="ips"))
        layout["lower"].split_row(Layout(name="recent"))

    with Live(layout, refresh_per_second=10, screen=True):
        try:
            prev_bytes = stats.bytes_transferred
            interval = 0.5
            while True:
                if packet_filter:
                    layout["recent_table"].update(Panel(Align.center(build_recent_panel(stats))))
                else:
                    layout["protocols"].update(Panel(Align.center(build_protocol_table(stats))))
                    layout["ports"].update(Panel(Align.center(build_top_ports_panel(stats))))
                    layout["ips"].update(Panel(Align.center(build_top_ips_panel(stats))))
                    layout["recent"].update(Panel(Align.center(build_recent_panel(stats))))
                current_bytes = stats.bytes_transferred
                delta = current_bytes - prev_bytes
                prev_bytes = current_bytes
                bps = delta / interval
                if bps < 1024:
                    rate_str = f"{bps:.0f} B/s"
                elif bps < 1024 * 1024:
                    rate_str = f"{bps/1024:.1f} KB/s"
                else:
                    rate_str = f"{bps/(1024*1024):.1f} MB/s"

                
                if packet_filter:
                    filters = []
                    if packet_filter.get("tcp"):
                        filters.append("TCP")
                    if packet_filter.get("udp"):
                        filters.append("UDP")
                    if packet_filter.get("dns"):
                        filters.append("DNS")
                    if packet_filter.get("ip_value"):
                        filters.append(f"IP={packet_filter['ip_value']}")
                    if packet_filter.get("port_value"):
                        filters.append(f"Port={packet_filter['port_value']}")
                    filter_str = ", ".join(filters) if filters else "No filters"
                    header_text = (
                        f"Filtered: {filter_str}\nPackets: {stats.total_packets:,}   Traffic: {stats.bytes_transferred / (1024*1024):.1f} MB   Rate: {rate_str}\n"
                    )
                else:
                    header_text = (
                        f"Live Network Traffic Analysis   Packets: {stats.total_packets:,}   Traffic: {stats.bytes_transferred / (1024*1024):.1f} MB   Rate: {rate_str}\n"
                    )
                layout["header"].update(Panel(header_text, style="bold"))
                time.sleep(interval)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    run_dashboard()
