from ipaddress import ip_address

import netifaces


def get_local_ips():
    local_ips = {"127.0.0.1", "::1"}

    try:
        interfaces = netifaces.interfaces()
    except PermissionError:
        return local_ips

    for interface in interfaces:
        try:
            addresses = netifaces.ifaddresses(interface)
        except PermissionError:
            continue

        for family in (netifaces.AF_INET, netifaces.AF_INET6):
            for address in addresses.get(family, []):
                ip_value = address.get("addr")

                if ip_value:
                    local_ips.add(ip_value.split("%")[0])

    return local_ips


def is_local_ip(ip_value):
    try:
        parsed_ip = ip_address(ip_value)
    except ValueError:
        return False

    return parsed_ip.is_loopback or str(parsed_ip) in get_local_ips()
