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
from sniffer.utils.traffic_stats import TrafficStats


def build_protocol_table(stats: TrafficStats):
    table = Table(title="Protocols", box=box.SIMPLE)
    table.add_column("Protocol", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("TCP", str(stats.tcp_packets))
    table.add_row("UDP", str(stats.udp_packets), style="yellow")
    table.add_row("DNS", str(stats.dns_packets), style="cyan")
    table.add_row("ICMP", str(stats.icmp_packets), style="red")
    return table


def build_top_ports_panel(stats: TrafficStats):
    table = Table(title="Top Destination Ports", box=box.SIMPLE)
    table.add_column("Port", style="bold")
    table.add_column("Count", justify="right")
    for port, count in stats.ports.most_common(3):
        table.add_row(str(port), str(count))
    return table


def build_top_ips_panel(stats: TrafficStats):
    table = Table(title="Top Destination IPs", box=box.SIMPLE)
    table.add_column("IP", style="bold")
    for ip, _ in stats.destination_ips.most_common(3):
        table.add_row(ip)
    return table

#centre the table in the panel 
def build_recent_panel(stats: TrafficStats):
    table = Table(title="Recent Packets", box=box.SIMPLE)
    table.add_column("Proto", justify="center", width=8)
    table.add_column("Source", justify="left")
    table.add_column("Destination", justify="left")
    table.add_column("Size", justify="right", width=8)
    for proto, src, dst, size in list(stats.recent_packets):
        style = ""
        if proto == "TCP":
            style = "green"
        elif proto == "UDP":
            style = "yellow"
        elif proto == "DNS":
            style = "cyan"
        elif proto == "ICMP":
            style = "red"

        table.add_row(proto, src, dst, f"{size}B", style=style)

    return table


def run_dashboard():
    stats = TrafficStats()

    # start capture in a background thread and share stats
    capture_thread = Thread(
        target=start_capture,
        kwargs={
            "tcp": False,
            "udp": False,
            "dns": False,
            "ip_value": None,
            "port_value": None,
            "traffic_stats": stats,
            "suppress_stdout": True,
        },
        daemon=True,
    )
    capture_thread.start()

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="upper", size=10),
        Layout(name="lower", size=20),
    )

    layout["upper"].split_row(Layout(name="protocols"), Layout(name="ports"), Layout(name="ips"))
    layout["lower"].split_row(Layout(name="recent"))

    with Live(layout, refresh_per_second=10, screen=False):
        try:
            while True:
                layout["protocols"].update(Panel(Align.center(build_protocol_table(stats))))
                layout["ports"].update(Panel(Align.center(build_top_ports_panel(stats))))
                layout["ips"].update(Panel(Align.center(build_top_ips_panel(stats))))
                layout["recent"].update(Panel(Align.center(build_recent_panel(stats))))
                # header with totals
                header_text = (
                    f"Packets Seen: {stats.total_packets:,}   Bytes Seen: {stats.bytes_transferred / (1024*1024):.1f} MB\n"
                )
                layout["header"].update(Panel(header_text, style="bold"))
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    run_dashboard()
