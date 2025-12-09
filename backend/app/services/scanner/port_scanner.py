"""Port scanner using Nmap for service detection."""
import asyncio
import logging
from typing import List, Dict, Optional
import nmap
from app.services.scanner.scan_profiles import get_scan_profile

logger = logging.getLogger(__name__)


class PortScanner:
    """Port scanner for scanning individual hosts."""

    def __init__(self):
        self.nm = nmap.PortScanner()

    async def scan_host(
        self,
        host: str,
        profile: str = "standard",
        progress_callback=None
    ) -> Dict:
        """
        Scan ports on a single host.

        Args:
            host: IP address to scan
            profile: Scan profile ("quick", "standard", "deep")
            progress_callback: Async callback function for progress updates

        Returns:
            Dictionary with scan results
        """
        logger.info(f"Starting {profile} port scan on {host}")

        profile_config = get_scan_profile(profile)

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._scan_host_blocking,
                host,
                profile_config
            )

            if progress_callback:
                await progress_callback({
                    "host": host,
                    "status": "completed",
                    "ports_found": len(result.get("ports", []))
                })

            return result

        except Exception as e:
            logger.error(f"Port scan failed for {host}: {e}")
            if progress_callback:
                await progress_callback({
                    "host": host,
                    "status": "failed",
                    "error": str(e)
                })
            return {
                "host": host,
                "status": "error",
                "error": str(e),
                "ports": []
            }

    def _scan_host_blocking(self, host: str, profile_config: dict) -> Dict:
        """Blocking port scan (runs in executor)."""
        result = {
            "host": host,
            "status": "completed",
            "ports": [],
            "os_guess": None
        }

        try:
            # Run nmap scan
            arguments = profile_config["arguments"]
            self.nm.scan(hosts=host, arguments=arguments)

            if host not in self.nm.all_hosts():
                result["status"] = "host_down"
                return result

            # Extract port information
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()

                for port in ports:
                    port_info = self.nm[host][proto][port]

                    port_data = {
                        "port": port,
                        "protocol": proto,
                        "state": port_info.get("state", "unknown"),
                        "service": port_info.get("name", "unknown"),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                        "extrainfo": port_info.get("extrainfo", ""),
                        "banner": None  # Can be populated with additional scan
                    }

                    result["ports"].append(port_data)

            # Extract OS detection if available
            if profile_config.get("os_detection") and 'osmatch' in self.nm[host]:
                os_matches = self.nm[host]['osmatch']
                if os_matches and len(os_matches) > 0:
                    best_match = os_matches[0]
                    result["os_guess"] = f"{best_match.get('name', 'Unknown')} (accuracy: {best_match.get('accuracy', 0)}%)"

            logger.info(f"Found {len(result['ports'])} open ports on {host}")

        except Exception as e:
            logger.error(f"Scan error for {host}: {e}")
            result["status"] = "error"
            result["error"] = str(e)

        return result

    async def scan_multiple_hosts(
        self,
        hosts: List[str],
        profile: str = "standard",
        progress_callback=None
    ) -> List[Dict]:
        """
        Scan multiple hosts concurrently.

        Args:
            hosts: List of IP addresses
            profile: Scan profile
            progress_callback: Async callback for progress

        Returns:
            List of scan results
        """
        logger.info(f"Scanning {len(hosts)} hosts with {profile} profile")

        tasks = []
        for host in hosts:
            tasks.append(self.scan_host(host, profile, progress_callback))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and return results
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
            else:
                logger.error(f"Scan task failed: {result}")

        return valid_results

    async def scan_specific_ports(
        self,
        host: str,
        ports: List[int],
        service_detection: bool = True
    ) -> Dict:
        """
        Scan specific ports on a host.

        Args:
            host: IP address
            ports: List of port numbers
            service_detection: Enable service version detection

        Returns:
            Scan results
        """
        port_str = ",".join(map(str, ports))
        arguments = f"-p{port_str}"

        if service_detection:
            arguments += " -sV"

        logger.info(f"Scanning specific ports {port_str} on {host}")

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._scan_host_blocking,
                host,
                {"arguments": arguments}
            )
            return result
        except Exception as e:
            logger.error(f"Specific port scan failed: {e}")
            return {
                "host": host,
                "status": "error",
                "error": str(e),
                "ports": []
            }
