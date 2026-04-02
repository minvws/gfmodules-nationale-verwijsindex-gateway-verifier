from sqlalchemy import exists, select

from app.db.decorator import repository
from app.db.models.healthcare_provider import HealthcareProviderEntity
from app.db.repository.base import RepositoryBase


@repository(HealthcareProviderEntity)
class HealthcareProvidersRepository(RepositoryBase):
    def exists(self, oin: str, ura_number: str, source_id: str | None = None) -> bool:
        conditions = [
            (HealthcareProviderEntity.oin == oin),
            (HealthcareProviderEntity.ura_number == ura_number),
        ]
        if source_id:
            conditions.append((HealthcareProviderEntity.source_id == source_id))

        stmt = select(exists(HealthcareProviderEntity)).where(*conditions)
        result = self.db_session.session.execute(stmt).scalar()
        return result or False
