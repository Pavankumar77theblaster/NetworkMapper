from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.database import Base


class ScanType(str, enum.Enum):
    discovery = "discovery"
    port_scan = "port_scan"
    service_detection = "service_detection"


class ScanProfile(str, enum.Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)  # Nullable for network discovery
    scan_type = Column(Enum(ScanType), nullable=False)
    scan_profile = Column(Enum(ScanProfile), default=ScanProfile.standard)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration = Column(Integer, nullable=True)  # Duration in seconds
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    user = relationship("User", back_populates="scans")
    device = relationship("Device", back_populates="scans")
    ports = relationship("Port", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
