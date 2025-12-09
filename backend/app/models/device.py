from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.database import Base


class DeviceStatus(str, enum.Enum):
    up = "up"
    down = "down"
    unknown = "unknown"


class RiskLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)  # IPv4/IPv6
    mac_address = Column(String(17), nullable=True)
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)  # From MAC lookup
    device_type = Column(String(50), nullable=True)  # router, switch, workstation, server, iot
    os_guess = Column(String(255), nullable=True)
    status = Column(Enum(DeviceStatus), default=DeviceStatus.unknown, nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    first_discovered = Column(DateTime(timezone=True), server_default=func.now())
    user_notes = Column(Text, nullable=True)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.low, nullable=False)
    tags = Column(JSON, default=list)  # Array of custom tags
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="devices")
    scans = relationship("Scan", back_populates="device", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="device", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="device", cascade="all, delete-orphan")
