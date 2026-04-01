from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import TIMESTAMP, Boolean, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.db.models.base import Base


class HealthcareProviderEntity(Base):
    __tablename__ = "healthcare_providers"

    id: Mapped[UUID] = mapped_column("id", Uuid, primary_key=True, default=uuid4)
    ura_number: Mapped[str] = mapped_column("ura_number", String)
    source_id: Mapped[Optional[str]] = mapped_column("source_id", String)
    is_source: Mapped[bool] = mapped_column("is_source", Boolean)
    is_viewer: Mapped[bool] = mapped_column("is_viewer", Boolean)
    oin: Mapped[str] = mapped_column("oin", String)
    common_name: Mapped[str] = mapped_column("common_name", String)
    deleted_at: Mapped[Optional[datetime]] = mapped_column("deleted_at", TIMESTAMP)
    status: Mapped[str] = mapped_column("status", String)
