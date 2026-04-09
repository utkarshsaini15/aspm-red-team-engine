from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel
import uuid

class ScanJob(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    target_model: str
    status: str = Field(default="PENDING") # PENDING, IN_PROGRESS, COMPLETED, FAILED
    results: Optional[str] = None # JSON string of results
    logs: str = Field(default="") # Streaming text logs
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
