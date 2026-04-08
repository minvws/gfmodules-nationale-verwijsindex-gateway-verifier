from sqlalchemy import select

from app.db.decorator import repository
from app.db.models.healthcare_provider import HealthcareProviderEntity
from app.db.models.oin import OinNumber
from app.db.repository.base import RepositoryBase


@repository(HealthcareProviderEntity)
class HealthcareProvidersRepository(RepositoryBase):
    def find(self, oin: OinNumber, source_id: str | None) -> list[HealthcareProviderEntity]:
        stmt = select(HealthcareProviderEntity).where(HealthcareProviderEntity.oin == str(oin))
        if source_id is not None:
            stmt = stmt.where(HealthcareProviderEntity.source_id == source_id)

        return list(self.db_session.session.scalars(stmt).all())
