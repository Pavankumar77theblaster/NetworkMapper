"""Network discovery scanner using ARP, ICMP, and Nmap."""
import asyncio
import logging
from typing import List, Dict, Optional
import nmap
from scapy.all import ARP, Ether, srp, conf
import ipaddress

# Disable scapy warnings
conf.verb = 0

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Network scanner for device discovery."""

    def __init__(self):
        self.nm = nmap.PortScanner()

    async def arp_scan(self, network: str) -> List[Dict[str, str]]:
        """
        Perform ARP scan to discover devices on local network.

        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")

        Returns:
            List of dictionaries with ip, mac, and vendor information
        """
        logger.info(f"Starting ARP scan on {network}")
        devices = []

        try:
            # Run ARP scan in thread to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._arp_scan_blocking,
                network
            )
            devices.extend(result)
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")

        logger.info(f"ARP scan found {len(devices)} devices")
        return devices

    def _arp_scan_blocking(self, network: str) -> List[Dict[str, str]]:
        """Blocking ARP scan (runs in executor)."""
        devices = []

        # Create ARP request
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Send packet and receive response
        result = srp(packet, timeout=3, verbose=0)[0]

        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": self._get_mac_vendor(received.hwsrc)
            })

        return devices

    def _get_mac_vendor(self, mac: str) -> Optional[str]:
        """Get vendor name from MAC address (simplified)."""
        # TODO: Integrate with MAC vendor lookup API or database
        # For now, return first 3 octets as vendor ID
        try:
            vendor_prefix = mac.upper()[:8]  # First 3 octets
            return f"Vendor-{vendor_prefix}"
        except:
            return "Unknown"

    async def icmp_scan(self, network: str) -> List[Dict[str, str]]:
        """
        Perform ICMP ping sweep to discover live hosts.

        Args:
            network: Network in CIDR notation

        Returns:
            List of dictionaries with ip information
        """
        logger.info(f"Starting ICMP scan on {network}")
        devices = []

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._icmp_scan_blocking,
                network
            )
            devices.extend(result)
        except Exception as e:
            logger.error(f"ICMP scan failed: {e}")

        logger.info(f"ICMP scan found {len(devices)} devices")
        return devices

    def _icmp_scan_blocking(self, network: str) -> List[Dict[str, str]]:
        """Blocking ICMP scan using Nmap."""
        devices = []

        try:
            # Use nmap for ICMP ping sweep
            self.nm.scan(hosts=network, arguments='-sn -PE')

            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    devices.append({
                        "ip": host,
                        "mac": None,
                        "vendor": None
                    })
        except Exception as e:
            logger.error(f"Nmap ICMP scan error: {e}")

        return devices

    async def nmap_discovery(self, network: str) -> List[Dict[str, str]]:
        """
        Perform Nmap host discovery.

        Args:
            network: Network in CIDR notation

        Returns:
            List of dictionaries with ip, mac, hostname, and vendor
        """
        logger.info(f"Starting Nmap discovery on {network}")
        devices = []

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._nmap_discovery_blocking,
                network
            )
            devices.extend(result)
        except Exception as e:
            logger.error(f"Nmap discovery failed: {e}")

        logger.info(f"Nmap discovery found {len(devices)} devices")
        return devices

    def _nmap_discovery_blocking(self, network: str) -> List[Dict[str, str]]:
        """Blocking Nmap discovery scan."""
        devices = []

        try:
            # Host discovery with OS detection hints
            self.nm.scan(hosts=network, arguments='-sn')

            for host in self.nm.all_hosts():
                device_info = {
                    "ip": host,
                    "mac": None,
                    "hostname": None,
                    "vendor": None
                }

                # Get hostname
                if 'hostnames' in self.nm[host]:
                    hostnames = self.nm[host]['hostnames']
                    if hostnames and len(hostnames) > 0:
                        device_info["hostname"] = hostnames[0].get('name', None)

                # Get MAC address and vendor
                if 'addresses' in self.nm[host]:
                    if 'mac' in self.nm[host]['addresses']:
                        device_info["mac"] = self.nm[host]['addresses']['mac']

                if 'vendor' in self.nm[host]:
                    vendors = self.nm[host]['vendor']
                    if vendors:
                        mac = device_info.get("mac")
                        if mac and mac in vendors:
                            device_info["vendor"] = vendors[mac]

                devices.append(device_info)

        except Exception as e:
            logger.error(f"Nmap discovery error: {e}")

        return devices

    async def discover_network(self, network: str, methods: List[str] = None) -> List[Dict[str, str]]:
        """
        Discover devices on network using multiple methods.

        Args:
            network: Network in CIDR notation
            methods: List of methods to use ["arp", "icmp", "nmap"]

        Returns:
            Combined list of discovered devices (deduplicated by IP)
        """
        if methods is None:
            methods = ["arp", "nmap"]  # Default methods

        all_devices = {}  # Use dict to deduplicate by IP

        # Run discovery methods in parallel
        tasks = []
        if "arp" in methods:
            tasks.append(self.arp_scan(network))
        if "icmp" in methods:
            tasks.append(self.icmp_scan(network))
        if "nmap" in methods:
            tasks.append(self.nmap_discovery(network))

        results = await asyncio.gather(*tasks)

        # Merge results, keeping most complete information
        for device_list in results:
            for device in device_list:
                ip = device["ip"]
                if ip not in all_devices:
                    all_devices[ip] = device
                else:
                    # Merge information (prefer non-None values)
                    existing = all_devices[ip]
                    for key, value in device.items():
                        if value and not existing.get(key):
                            existing[key] = value

        logger.info(f"Total unique devices discovered: {len(all_devices)}")
        return list(all_devices.values())


# Utility function to get default gateway
def get_default_network() -> Optional[str]:
    """Get default network CIDR for scanning."""
    try:
        # This is a simplified version - in production, detect actual local network
        return "192.168.1.0/24"
    except Exception as e:
        logger.error(f"Failed to detect default network: {e}")
        return None
