from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.database import Base


class PortProtocol(str, enum.Enum):
    tcp = "tcp"
    udp = "udp"


class PortState(str, enum.Enum):
    open = "open"
    closed = "closed"
    filtered = "filtered"


class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    port_number = Column(Integer, nullable=False)
    protocol = Column(Enum(PortProtocol), default=PortProtocol.tcp, nullable=False)
    state = Column(Enum(PortState), default=PortState.open, nullable=False)
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(255), nullable=True)
    banner = Column(Text, nullable=True)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    device = relationship("Device", back_populates="ports")
    scan = relationship("Scan", back_populates="ports")
