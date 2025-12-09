from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class DeviceBase(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os_guess: Optional[str] = None
    user_notes: Optional[str] = None
    risk_level: Optional[str] = "low"
    tags: Optional[List[str]] = []


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    user_notes: Optional[str] = None
    risk_level: Optional[str] = None
    tags: Optional[List[str]] = None


class DeviceResponse(DeviceBase):
    id: int
    status: str
    last_seen: datetime
    first_discovered: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class PortResponse(BaseModel):
    id: int
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    discovered_at: datetime

    class Config:
        from_attributes = True
