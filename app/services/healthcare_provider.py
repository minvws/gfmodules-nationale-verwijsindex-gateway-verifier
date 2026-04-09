import logging

from app.db.db import Database
from app.db.models.healthcare_provider import HealthcareProviderEntity
from app.db.models.oin import OinNumber
from app.db.repository.healthcare_provider import HealthcareProvidersRepository

logger = logging.getLogger(__name__)


class HealthcareProviderService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def exists(self, oin: OinNumber, source_id: str | None = None) -> bool:
        logger.info(f"HealthcareProviderService.exists: {oin} {source_id}")
        with self.db.get_db_session() as session:
            repo = session.get_repository(HealthcareProvidersRepository)
            result = repo.find(oin, source_id)

            return len(result) > 0

    def find(self, oin: OinNumber, source_id: str | None = None) -> list[HealthcareProviderEntity]:
        logger.info(f"HealthcareProviderService.find: {oin} {source_id}")
        with self.db.get_db_session() as session:
            repo = session.get_repository(HealthcareProvidersRepository)
            return repo.find(oin, source_id)
