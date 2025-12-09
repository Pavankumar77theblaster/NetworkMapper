"""Automated finding detection based on port scan results."""
import logging
from typing import List, Dict
from sqlalchemy.orm import Session
from app.models.device import Device
from app.models.port import Port
from app.models.finding import Finding, FindingType, FindingSeverity
from app.models.scan import Scan

logger = logging.getLogger(__name__)


# Finding detection rules
FINDING_RULES = [
    {
        "ports": [21],
        "title": "FTP Service Detected",
        "description": "Unencrypted FTP service detected on port 21. FTP transmits credentials and data in plaintext, making it vulnerable to interception.",
        "recommendation": "Use SFTP (SSH File Transfer Protocol) or FTPS (FTP over SSL/TLS) instead of plain FTP.",
        "severity": FindingSeverity.medium,
        "finding_type": FindingType.vulnerable_service
    },
    {
        "ports": [23],
        "title": "Telnet Service Detected",
        "description": "Telnet service detected on port 23. Telnet transmits all data including credentials in plaintext and has no encryption.",
        "recommendation": "Disable Telnet and use SSH (port 22) for secure remote access instead.",
        "severity": FindingSeverity.high,
        "finding_type": FindingType.vulnerable_service
    },
    {
        "ports": [445, 139],
        "title": "SMB Service Exposed",
        "description": "SMB (Server Message Block) file sharing service detected. SMB is a common target for ransomware and lateral movement attacks.",
        "recommendation": "Ensure SMB signing is enabled, use SMBv3 or later, disable SMBv1, and restrict access with firewall rules. Only expose SMB to trusted networks.",
        "severity": FindingSeverity.medium,
        "finding_type": FindingType.vulnerable_service
    },
    {
        "ports": [3389],
        "title": "RDP Service Detected",
        "description": "Remote Desktop Protocol (RDP) detected on port 3389. RDP is a frequent target for brute-force attacks and exploitation.",
        "recommendation": "Use Network Level Authentication (NLA), implement account lockout policies, use VPN for remote access, enable firewall restrictions, and consider changing the default port.",
        "severity": FindingSeverity.medium,
        "finding_type": FindingType.vulnerable_service
    },
    {
        "ports": [22],
        "title": "SSH Service Detected",
        "description": "SSH service detected on port 22. While SSH is secure, it can be targeted for brute-force attacks if not properly configured.",
        "recommendation": "Use key-based authentication instead of passwords, disable root login, implement fail2ban or similar tools, and consider changing the default port.",
        "severity": FindingSeverity.info,
        "finding_type": FindingType.open_port
    },
    {
        "ports": [80, 8080, 8000],
        "title": "HTTP Service Detected",
        "description": "Unencrypted HTTP service detected. HTTP traffic is transmitted in plaintext and can be intercepted.",
        "recommendation": "Use HTTPS (TLS/SSL) for all web services. Implement HTTP to HTTPS redirection.",
        "severity": FindingSeverity.low,
        "finding_type": FindingType.weak_config
    },
    {
        "ports": [3306],
        "title": "MySQL Database Exposed",
        "description": "MySQL database service detected. Direct database exposure to the network can be a security risk.",
        "recommendation": "Restrict database access to localhost or specific trusted IPs. Use firewall rules and ensure strong authentication is enabled.",
        "severity": FindingSeverity.medium,
        "finding_type": FindingType.weak_config
    },
    {
        "ports": [5432],
        "title": "PostgreSQL Database Exposed",
        "description": "PostgreSQL database service detected. Direct database exposure to the network can be a security risk.",
        "recommendation": "Restrict database access to localhost or specific trusted IPs. Use firewall rules and ensure strong authentication is enabled.",
        "severity": FindingSeverity.medium,
        "finding_type": FindingType.weak_config
    },
    {
        "ports": [27017],
        "title": "MongoDB Database Exposed",
        "description": "MongoDB database service detected. Historically, MongoDB instances have been targeted when exposed without proper authentication.",
        "recommendation": "Enable authentication, bind to localhost only, use firewall rules, and keep MongoDB updated.",
        "severity": FindingSeverity.high,
        "finding_type": FindingType.weak_config
    },
    {
        "ports": [6379],
        "title": "Redis Cache Exposed",
        "description": "Redis service detected. Redis has limited authentication and should not be exposed directly to untrusted networks.",
        "recommendation": "Bind Redis to localhost, use firewall rules, enable AUTH, and consider using Redis ACLs.",
        "severity": FindingSeverity.medium,
        "finding_type": FindingType.weak_config
    },
]


class FindingAnalyzer:
    """Analyzer for detecting security findings based on scan results."""

    def __init__(self, db: Session):
        self.db = db

    def analyze_device_ports(self, device: Device, scan: Scan = None) -> List[Finding]:
        """
        Analyze a device's open ports and create findings.

        Args:
            device: Device to analyze
            scan: Optional scan record to associate findings with

        Returns:
            List of created findings
        """
        logger.info(f"Analyzing device {device.ip_address} for findings")

        # Get all open ports for the device
        ports = self.db.query(Port).filter(
            Port.device_id == device.id,
            Port.state == "open"
        ).all()

        open_port_numbers = [port.port_number for port in ports]
        findings = []

        # Check each rule
        for rule in FINDING_RULES:
            # Check if any of the rule's ports are open
            matching_ports = [p for p in rule["ports"] if p in open_port_numbers]

            if matching_ports:
                # Check if finding already exists for this device
                existing_finding = self.db.query(Finding).filter(
                    Finding.device_id == device.id,
                    Finding.title == rule["title"],
                    Finding.is_acknowledged == False
                ).first()

                if existing_finding:
                    logger.debug(f"Finding already exists: {rule['title']}")
                    continue

                # Create new finding
                finding = Finding(
                    device_id=device.id,
                    scan_id=scan.id if scan else None,
                    finding_type=rule["finding_type"],
                    severity=rule["severity"],
                    title=rule["title"],
                    description=f"{rule['description']} Found on port(s): {', '.join(map(str, matching_ports))}",
                    recommendation=rule["recommendation"]
                )

                self.db.add(finding)
                findings.append(finding)
                logger.info(f"Created finding: {rule['title']} for device {device.ip_address}")

        # Commit all findings
        if findings:
            self.db.commit()

        return findings

    def analyze_all_devices(self) -> Dict:
        """
        Analyze all devices and create findings.

        Returns:
            Dictionary with analysis results
        """
        logger.info("Starting analysis of all devices")

        devices = self.db.query(Device).filter(Device.status == "up").all()
        total_findings = 0

        for device in devices:
            findings = self.analyze_device_ports(device)
            total_findings += len(findings)

        logger.info(f"Analysis complete: created {total_findings} new findings across {len(devices)} devices")

        return {
            "devices_analyzed": len(devices),
            "findings_created": total_findings
        }

    def get_critical_findings(self) -> List[Finding]:
        """Get all unacknowledged critical and high severity findings."""
        findings = self.db.query(Finding).filter(
            Finding.is_acknowledged == False,
            Finding.severity.in_([FindingSeverity.critical, FindingSeverity.high])
        ).all()

        return findings
