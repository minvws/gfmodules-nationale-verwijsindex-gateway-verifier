from app.db.db import Database
from app.db.repository.healthcare_provider import HealthcareProvidersRepository


class HeatlhcareProviderService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def exists(self, oin: str, ura_number: str, source_id: str | None = None) -> bool:
        with self.db.get_db_session() as session:
            repo = session.get_repository(HealthcareProvidersRepository)
            result = repo.exists(oin, ura_number, source_id)

            return result
