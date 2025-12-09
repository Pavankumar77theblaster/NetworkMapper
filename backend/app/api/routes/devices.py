from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.device import Device
from app.models.port import Port
from app.schemas.device import DeviceResponse, DeviceUpdate, PortResponse
from app.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/devices", tags=["Devices"])


@router.get("/", response_model=List[DeviceResponse])
async def list_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """List all devices with optional filters."""
    query = db.query(Device)

    # Apply filters
    if status:
        query = query.filter(Device.status == status)

    if risk_level:
        query = query.filter(Device.risk_level == risk_level)

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (Device.ip_address.like(search_pattern)) |
            (Device.hostname.like(search_pattern)) |
            (Device.vendor.like(search_pattern))
        )

    # Order by last seen (most recent first)
    query = query.order_by(Device.last_seen.desc())

    devices = query.offset(skip).limit(limit).all()
    return devices


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: int,
    db: Session = Depends(get_db)
):
    """Get device details by ID."""
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    return device


@router.put("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: int,
    device_update: DeviceUpdate,
    db: Session = Depends(get_db)
):
    """Update device information (tags, notes, risk level, etc.)."""
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    # Update fields
    update_data = device_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(device, field, value)

    db.commit()
    db.refresh(device)

    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: int,
    db: Session = Depends(get_db)
):
    """Delete a device."""
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    db.delete(device)
    db.commit()

    return None


@router.get("/{device_id}/ports", response_model=List[PortResponse])
async def get_device_ports(
    device_id: int,
    db: Session = Depends(get_db)
):
    """Get all ports for a specific device."""
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    ports = db.query(Port).filter(Port.device_id == device_id).order_by(Port.port_number).all()
    return ports
