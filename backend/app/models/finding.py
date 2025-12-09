from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.database import Base


class FindingType(str, enum.Enum):
    open_port = "open_port"
    vulnerable_service = "vulnerable_service"
    weak_config = "weak_config"
    outdated_software = "outdated_software"
    custom = "custom"


class FindingSeverity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    finding_type = Column(Enum(FindingType), nullable=False)
    severity = Column(Enum(FindingSeverity), default=FindingSeverity.info, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    is_acknowledged = Column(Boolean, default=False, nullable=False)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    device = relationship("Device", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
