from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class FindingResponse(BaseModel):
    id: int
    device_id: int
    scan_id: Optional[int] = None
    finding_type: str
    severity: str
    title: str
    description: str
    recommendation: Optional[str] = None
    is_acknowledged: bool
    discovered_at: datetime

    class Config:
        from_attributes = True


class FindingAcknowledge(BaseModel):
    is_acknowledged: bool = True
