"""Scan orchestrator for coordinating network discovery and port scanning."""
import asyncio
import logging
from datetime import datetime
from typing import Optional, Callable, Dict, List
from sqlalchemy.orm import Session
from app.models.device import Device, DeviceStatus
from app.models.scan import Scan, ScanType, ScanProfile, ScanStatus
from app.models.port import Port, PortProtocol, PortState
from app.services.scanner.network_scanner import NetworkScanner
from app.services.scanner.port_scanner import PortScanner

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates scanning operations and coordinates with database and WebSocket."""

    def __init__(self, db: Session, websocket_callback: Optional[Callable] = None):
        self.db = db
        self.websocket_callback = websocket_callback
        self.network_scanner = NetworkScanner()
        self.port_scanner = PortScanner()

    async def _emit_progress(self, message: Dict):
        """Emit progress message via WebSocket if callback is available."""
        if self.websocket_callback:
            try:
                await self.websocket_callback(message)
            except Exception as e:
                logger.error(f"Failed to emit WebSocket message: {e}")

    async def discover_network(
        self,
        network: str,
        user_id: int,
        methods: List[str] = None
    ) -> Dict:
        """
        Perform network discovery and save results to database.

        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")
            user_id: User ID performing the scan
            methods: Discovery methods to use

        Returns:
            Dictionary with scan results
        """
        logger.info(f"Starting network discovery for {network}")

        # Create scan record
        scan = Scan(
            scan_type=ScanType.discovery,
            status=ScanStatus.running,
            user_id=user_id
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        # Emit start message
        await self._emit_progress({
            "type": "scan_progress",
            "data": {
                "scan_id": scan.id,
                "phase": "discovery",
                "progress": 0,
                "message": f"Starting network discovery on {network}"
            }
        })

        try:
            # Discover devices
            devices_found = await self.network_scanner.discover_network(network, methods)

            total_devices = len(devices_found)
            saved_devices = []

            for idx, device_data in enumerate(devices_found):
                # Check if device already exists
                existing_device = self.db.query(Device).filter(
                    Device.ip_address == device_data["ip"]
                ).first()

                if existing_device:
                    # Update existing device
                    existing_device.status = DeviceStatus.up
                    existing_device.last_seen = datetime.utcnow()
                    if device_data.get("mac") and not existing_device.mac_address:
                        existing_device.mac_address = device_data["mac"]
                    if device_data.get("hostname") and not existing_device.hostname:
                        existing_device.hostname = device_data["hostname"]
                    if device_data.get("vendor") and not existing_device.vendor:
                        existing_device.vendor = device_data["vendor"]

                    device = existing_device
                else:
                    # Create new device
                    device = Device(
                        ip_address=device_data["ip"],
                        mac_address=device_data.get("mac"),
                        hostname=device_data.get("hostname"),
                        vendor=device_data.get("vendor"),
                        status=DeviceStatus.up,
                        user_id=user_id
                    )
                    self.db.add(device)

                self.db.commit()
                self.db.refresh(device)
                saved_devices.append(device)

                # Emit device discovered
                await self._emit_progress({
                    "type": "device_discovered",
                    "data": {
                        "scan_id": scan.id,
                        "device": {
                            "id": device.id,
                            "ip_address": device.ip_address,
                            "mac_address": device.mac_address,
                            "hostname": device.hostname,
                            "vendor": device.vendor,
                            "status": device.status.value
                        }
                    }
                })

                # Emit progress
                progress = int(((idx + 1) / total_devices) * 100)
                await self._emit_progress({
                    "type": "scan_progress",
                    "data": {
                        "scan_id": scan.id,
                        "phase": "discovery",
                        "progress": progress,
                        "current_device": device_data["ip"],
                        "total_devices": total_devices,
                        "message": f"Discovered {idx + 1}/{total_devices} devices"
                    }
                })

            # Update scan status
            scan.status = ScanStatus.completed
            scan.completed_at = datetime.utcnow()
            scan.duration = int((scan.completed_at - scan.started_at).total_seconds())
            self.db.commit()

            # Emit completion
            await self._emit_progress({
                "type": "scan_complete",
                "data": {
                    "scan_id": scan.id,
                    "status": "completed",
                    "devices_found": total_devices,
                    "message": f"Discovery complete: found {total_devices} devices"
                }
            })

            return {
                "scan_id": scan.id,
                "status": "completed",
                "devices_found": total_devices,
                "devices": [
                    {"id": d.id, "ip_address": d.ip_address, "hostname": d.hostname}
                    for d in saved_devices
                ]
            }

        except Exception as e:
            logger.error(f"Network discovery failed: {e}")
            scan.status = ScanStatus.failed
            scan.completed_at = datetime.utcnow()
            self.db.commit()

            await self._emit_progress({
                "type": "scan_complete",
                "data": {
                    "scan_id": scan.id,
                    "status": "failed",
                    "error": str(e)
                }
            })

            return {
                "scan_id": scan.id,
                "status": "failed",
                "error": str(e)
            }

    async def scan_device_ports(
        self,
        device_id: int,
        profile: str = "standard",
        user_id: int = None
    ) -> Dict:
        """
        Scan ports on a specific device.

        Args:
            device_id: Device ID to scan
            profile: Scan profile ("quick", "standard", "deep")
            user_id: User ID performing the scan

        Returns:
            Dictionary with scan results
        """
        # Get device
        device = self.db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return {"error": "Device not found"}

        logger.info(f"Starting port scan on device {device.ip_address}")

        # Create scan record
        scan = Scan(
            device_id=device.id,
            scan_type=ScanType.port_scan,
            scan_profile=ScanProfile[profile],
            status=ScanStatus.running,
            user_id=user_id or device.user_id
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        # Emit start message
        await self._emit_progress({
            "type": "scan_progress",
            "data": {
                "scan_id": scan.id,
                "device_id": device.id,
                "phase": "port_scanning",
                "progress": 0,
                "message": f"Starting {profile} port scan on {device.ip_address}"
            }
        })

        try:
            # Perform port scan
            scan_result = await self.port_scanner.scan_host(device.ip_address, profile)

            if scan_result["status"] == "completed":
                # Save ports to database
                for port_data in scan_result["ports"]:
                    # Check if port already exists
                    existing_port = self.db.query(Port).filter(
                        Port.device_id == device.id,
                        Port.port_number == port_data["port"],
                        Port.protocol == PortProtocol[port_data["protocol"]]
                    ).first()

                    if existing_port:
                        # Update existing port
                        existing_port.state = PortState[port_data["state"]]
                        existing_port.service_name = port_data.get("service")
                        existing_port.service_version = port_data.get("version", "")
                        existing_port.scan_id = scan.id
                    else:
                        # Create new port
                        port = Port(
                            device_id=device.id,
                            scan_id=scan.id,
                            port_number=port_data["port"],
                            protocol=PortProtocol[port_data["protocol"]],
                            state=PortState[port_data["state"]],
                            service_name=port_data.get("service"),
                            service_version=port_data.get("version", "")
                        )
                        self.db.add(port)

                    # Emit port found
                    await self._emit_progress({
                        "type": "port_found",
                        "data": {
                            "scan_id": scan.id,
                            "device_id": device.id,
                            "port": port_data["port"],
                            "protocol": port_data["protocol"],
                            "state": port_data["state"],
                            "service": port_data.get("service", "unknown")
                        }
                    })

                # Update device OS guess if available
                if scan_result.get("os_guess"):
                    device.os_guess = scan_result["os_guess"]

                device.status = DeviceStatus.up
                device.last_seen = datetime.utcnow()

                # Update scan status
                scan.status = ScanStatus.completed
                scan.completed_at = datetime.utcnow()
                scan.duration = int((scan.completed_at - scan.started_at).total_seconds())

                self.db.commit()

                # Emit completion
                await self._emit_progress({
                    "type": "scan_complete",
                    "data": {
                        "scan_id": scan.id,
                        "device_id": device.id,
                        "status": "completed",
                        "ports_found": len(scan_result["ports"]),
                        "message": f"Scan complete: found {len(scan_result['ports'])} open ports"
                    }
                })

                return {
                    "scan_id": scan.id,
                    "status": "completed",
                    "ports_found": len(scan_result["ports"])
                }

            else:
                # Scan failed
                scan.status = ScanStatus.failed
                scan.completed_at = datetime.utcnow()
                self.db.commit()

                return {
                    "scan_id": scan.id,
                    "status": "failed",
                    "error": scan_result.get("error", "Unknown error")
                }

        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            scan.status = ScanStatus.failed
            scan.completed_at = datetime.utcnow()
            self.db.commit()

            return {
                "scan_id": scan.id,
                "status": "failed",
                "error": str(e)
            }
