from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.device import Device
from app.schemas.scan import ScanRequest, DeviceScanRequest, ScanResponse, ScanStatusResponse
from app.dependencies import get_current_user
from app.services.scanner.scan_orchestrator import ScanOrchestrator
from app.utils.validators import validate_cidr

router = APIRouter(prefix="/scans", tags=["Scans"])


# Global WebSocket callback (will be set by WebSocket manager)
_websocket_callback = None


def set_websocket_callback(callback):
    """Set the WebSocket callback for scan progress updates."""
    global _websocket_callback
    _websocket_callback = callback


@router.post("/discovery", response_model=dict)
async def start_network_discovery(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start a network discovery scan."""
    # Validate CIDR notation
    if not validate_cidr(scan_request.network):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CIDR notation"
        )

    # Create orchestrator
    orchestrator = ScanOrchestrator(db, _websocket_callback)

    # Run discovery in background
    background_tasks.add_task(
        orchestrator.discover_network,
        scan_request.network,
        current_user.id,
        scan_request.methods
    )

    return {
        "message": "Network discovery started",
        "network": scan_request.network,
        "status": "running"
    }


@router.post("/device/{device_id}/ports", response_model=dict)
async def scan_device_ports(
    device_id: int,
    scan_request: DeviceScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start a port scan on a specific device."""
    # Check if device exists and belongs to user
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.user_id == current_user.id
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    # Validate profile
    valid_profiles = ["quick", "standard", "deep"]
    if scan_request.profile not in valid_profiles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid profile. Must be one of: {', '.join(valid_profiles)}"
        )

    # Create orchestrator
    orchestrator = ScanOrchestrator(db, _websocket_callback)

    # Run port scan in background
    background_tasks.add_task(
        orchestrator.scan_device_ports,
        device_id,
        scan_request.profile,
        current_user.id
    )

    return {
        "message": f"Port scan started on device {device.ip_address}",
        "device_id": device_id,
        "profile": scan_request.profile,
        "status": "running"
    }


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan details by ID."""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    return scan


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan status and progress."""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    return {
        "scan_id": scan.id,
        "status": scan.status.value,
        "message": f"Scan is {scan.status.value}"
    }


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all scans for the current user."""
    scans = db.query(Scan).filter(
        Scan.user_id == current_user.id
    ).order_by(Scan.started_at.desc()).offset(skip).limit(limit).all()

    return scans


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a scan record."""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    db.delete(scan)
    db.commit()

    return None
