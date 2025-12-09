from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ScanRequest(BaseModel):
    network: str  # CIDR notation like "192.168.1.0/24"
    profile: Optional[str] = "standard"  # quick, standard, deep
    methods: Optional[list[str]] = ["arp", "nmap"]  # arp, icmp, nmap


class DeviceScanRequest(BaseModel):
    profile: Optional[str] = "standard"  # quick, standard, deep


class ScanResponse(BaseModel):
    id: int
    scan_type: str
    scan_profile: Optional[str] = None
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[int] = None

    class Config:
        from_attributes = True


class ScanStatusResponse(BaseModel):
    scan_id: int
    status: str
    progress: Optional[int] = None
    message: Optional[str] = None
    devices_found: Optional[int] = None
    ports_found: Optional[int] = None
