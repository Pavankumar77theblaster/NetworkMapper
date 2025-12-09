from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.user import User
from app.models.finding import Finding
from app.models.device import Device
from app.schemas.finding import FindingResponse, FindingAcknowledge
from app.dependencies import get_current_user
from app.services.analysis.finding_analyzer import FindingAnalyzer
from app.services.analysis.risk_analyzer import RiskAnalyzer

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db)
):
    """List all findings with optional filters."""
    # Build query
    query = db.query(Finding)

    # Apply filters
    if severity:
        query = query.filter(Finding.severity == severity)

    if acknowledged is not None:
        query = query.filter(Finding.is_acknowledged == acknowledged)

    if device_id:
        query = query.filter(Finding.device_id == device_id)

    # Order by severity and discovery time
    query = query.order_by(Finding.severity.desc(), Finding.discovered_at.desc())

    findings = query.offset(skip).limit(limit).all()
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):
    """Get finding details by ID."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    return finding


@router.put("/{finding_id}/acknowledge", response_model=FindingResponse)
async def acknowledge_finding(
    finding_id: int,
    acknowledge_data: FindingAcknowledge,
    db: Session = Depends(get_db)
):
    """Acknowledge or unacknowledge a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    finding.is_acknowledged = acknowledge_data.is_acknowledged
    db.commit()
    db.refresh(finding)

    # Update device risk level after acknowledging finding
    device = db.query(Device).filter(Device.id == finding.device_id).first()
    if device:
        risk_analyzer = RiskAnalyzer(db)
        risk_analyzer.update_device_risk(device)

    return finding


@router.delete("/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):
    """Delete a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    db.delete(finding)
    db.commit()

    return None


@router.post("/analyze", response_model=dict)
async def analyze_findings(
    db: Session = Depends(get_db)
):
    """Run finding analysis on all devices."""
    # Get all devices
    devices = db.query(Device).all()

    analyzer = FindingAnalyzer(db)
    total_findings = 0

    for device in devices:
        findings = analyzer.analyze_device_ports(device)
        total_findings += len(findings)

    # Update risk levels
    risk_analyzer = RiskAnalyzer(db)
    risk_summary = risk_analyzer.update_all_device_risks()

    return {
        "message": "Finding analysis complete",
        "findings_created": total_findings,
        "devices_analyzed": len(devices),
        "risk_summary": risk_summary
    }


@router.get("/stats/summary", response_model=dict)
async def get_findings_summary(
    db: Session = Depends(get_db)
):
    """Get summary statistics for findings."""
    # Count findings by severity
    total = db.query(Finding).count()

    unacknowledged = db.query(Finding).filter(
        Finding.is_acknowledged == False
    ).count()

    critical = db.query(Finding).filter(
        Finding.severity == "critical",
        Finding.is_acknowledged == False
    ).count()

    high = db.query(Finding).filter(
        Finding.severity == "high",
        Finding.is_acknowledged == False
    ).count()

    medium = db.query(Finding).filter(
        Finding.severity == "medium",
        Finding.is_acknowledged == False
    ).count()

    # Get risk summary
    risk_analyzer = RiskAnalyzer(db)
    risk_summary = risk_analyzer.get_risk_summary()

    return {
        "total_findings": total,
        "unacknowledged_findings": unacknowledged,
        "critical_findings": critical,
        "high_findings": high,
        "medium_findings": medium,
        "risk_summary": risk_summary
    }
