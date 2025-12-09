import ipaddress
import re


def validate_ip_address(ip: str) -> bool:
    """Validate if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Validate if string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_mac_address(mac: str) -> bool:
    """Validate if string is a valid MAC address."""
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac))


def validate_port(port: int) -> bool:
    """Validate if port number is valid (1-65535)."""
    return 1 <= port <= 65535
