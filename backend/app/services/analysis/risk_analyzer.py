"""Risk analysis and scoring for devices."""
import logging
from sqlalchemy.orm import Session
from app.models.device import Device, RiskLevel
from app.models.port import Port
from app.models.finding import Finding, FindingSeverity

logger = logging.getLogger(__name__)


class RiskAnalyzer:
    """Analyzer for calculating device risk levels."""

    def __init__(self, db: Session):
        self.db = db

    def calculate_device_risk(self, device: Device) -> RiskLevel:
        """
        Calculate risk level for a device based on:
        - Number of open ports
        - Number and severity of findings
        - Type of services running

        Args:
            device: Device to analyze

        Returns:
            RiskLevel enum value
        """
        score = 0

        # Factor 1: Number of open ports (more ports = more attack surface)
        open_ports = self.db.query(Port).filter(
            Port.device_id == device.id,
            Port.state == "open"
        ).count()

        score += open_ports * 2  # 2 points per open port

        # Factor 2: Findings severity
        findings = self.db.query(Finding).filter(
            Finding.device_id == device.id,
            Finding.is_acknowledged == False
        ).all()

        severity_weights = {
            FindingSeverity.critical: 20,
            FindingSeverity.high: 10,
            FindingSeverity.medium: 5,
            FindingSeverity.low: 2,
            FindingSeverity.info: 1
        }

        for finding in findings:
            score += severity_weights.get(finding.severity, 0)

        # Calculate risk level based on score
        if score >= 50:
            return RiskLevel.critical
        elif score >= 30:
            return RiskLevel.high
        elif score >= 10:
            return RiskLevel.medium
        else:
            return RiskLevel.low

    def update_device_risk(self, device: Device) -> RiskLevel:
        """
        Calculate and update device risk level.

        Args:
            device: Device to update

        Returns:
            New risk level
        """
        new_risk_level = self.calculate_device_risk(device)

        if device.risk_level != new_risk_level:
            old_level = device.risk_level
            device.risk_level = new_risk_level
            self.db.commit()
            logger.info(f"Updated risk level for device {device.ip_address}: {old_level.value} -> {new_risk_level.value}")

        return new_risk_level

    def update_all_device_risks(self) -> dict:
        """
        Update risk levels for all devices.

        Returns:
            Dictionary with update statistics
        """
        logger.info("Updating risk levels for all devices")

        devices = self.db.query(Device).filter(Device.status == "up").all()
        risk_changes = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        }

        for device in devices:
            new_risk = self.update_device_risk(device)
            risk_changes[new_risk.value] += 1

        logger.info(f"Risk level update complete. Distribution: {risk_changes}")

        return {
            "devices_updated": len(devices),
            "risk_distribution": risk_changes
        }

    def get_high_risk_devices(self) -> list[Device]:
        """Get all devices with high or critical risk levels."""
        devices = self.db.query(Device).filter(
            Device.risk_level.in_([RiskLevel.high, RiskLevel.critical])
        ).all()

        return devices

    def get_risk_summary(self) -> dict:
        """Get summary of risk levels across all devices."""
        total_devices = self.db.query(Device).filter(Device.status == "up").count()

        low_risk = self.db.query(Device).filter(
            Device.status == "up",
            Device.risk_level == RiskLevel.low
        ).count()

        medium_risk = self.db.query(Device).filter(
            Device.status == "up",
            Device.risk_level == RiskLevel.medium
        ).count()

        high_risk = self.db.query(Device).filter(
            Device.status == "up",
            Device.risk_level == RiskLevel.high
        ).count()

        critical_risk = self.db.query(Device).filter(
            Device.status == "up",
            Device.risk_level == RiskLevel.critical
        ).count()

        return {
            "total_devices": total_devices,
            "low_risk": low_risk,
            "medium_risk": medium_risk,
            "high_risk": high_risk,
            "critical_risk": critical_risk
        }
