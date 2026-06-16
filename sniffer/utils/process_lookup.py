from pathlib import Path


PROC_NET_FILES = {
    "TCP": ("/proc/net/tcp", "/proc/net/tcp6"),
    "UDP": ("/proc/net/udp", "/proc/net/udp6"),
    "DNS": ("/proc/net/udp", "/proc/net/udp6"),
}


def find_process_by_port(port, protocol):
    if port is None:
        return None

    protocol = protocol.upper()
    inodes = find_socket_inodes(port, protocol)

    if not inodes:
        return None

    return find_process_by_inode(inodes)


def find_socket_inodes(port, protocol):
    inodes = set()
    net_files = PROC_NET_FILES.get(protocol, ())

    for net_file in net_files:
        path = Path(net_file)

        if not path.exists():
            continue

        for line in path.read_text().splitlines()[1:]:
            parts = line.split()

            if len(parts) < 10:
                continue

            local_address = parts[1]
            inode = parts[9]
            local_port = int(local_address.split(":")[1], 16)

            if local_port == port:
                inodes.add(inode)

    return inodes


def find_process_by_inode(inodes):
    for process_dir in Path("/proc").iterdir():
        if not process_dir.name.isdigit():
            continue

        fd_dir = process_dir / "fd"

        if not fd_dir.exists():
            continue

        try:
            for fd_path in fd_dir.iterdir():
                target = fd_path.readlink()
                target_text = str(target)

                for inode in inodes:
                    if target_text == f"socket:[{inode}]":
                        return read_process_name(process_dir)
        except (FileNotFoundError, PermissionError):
            continue

    return None


def read_process_name(process_dir):
    try:
        process_name = (process_dir / "comm").read_text().strip()
        return f"{process_name} (pid {process_dir.name})"
    except (FileNotFoundError, PermissionError):
        return f"pid {process_dir.name}"
