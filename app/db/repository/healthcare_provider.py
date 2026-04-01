from sqlalchemy import exists, select

from app.db.decorator import repository
from app.db.models.healthcare_provider import HealthcareProviderEntity
from app.db.repository.base import RepositoryBase


@repository(HealthcareProviderEntity)
class HealthcareProvidersRepository(RepositoryBase):
    def exists(self, oin: str) -> bool:
        stmt = select(exists(HealthcareProviderEntity)).where(HealthcareProviderEntity.oin == oin)
        result = self.db_session.session.execute(stmt).scalar()
        return result or False
