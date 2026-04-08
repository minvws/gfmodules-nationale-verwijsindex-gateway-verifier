from typing import Any, Generator

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.config import ConfigDatabase
from app.db.db import Database
from app.db.models.healthcare_provider import HealthcareProviderEntity
from app.db.repository.healthcare_provider import HealthcareProvidersRepository
from app.services.healthcare_provider import HealthcareProviderService


class MockHealthcareProviderRepository(HealthcareProvidersRepository):
    def add_one(self, data: HealthcareProviderEntity) -> HealthcareProviderEntity:
        try:
            self.db_session.add(data)
            self.db_session.commit()
            return data
        except SQLAlchemyError as e:
            self.db_session.rollback()
            raise e


@pytest.fixture()
def database() -> Generator[Database, Any, None]:
    config_database = ConfigDatabase(dsn="sqlite:///:memory:", retry_backoff=[])
    try:
        db = Database(config_database=config_database)
        db.generate_tables()
        yield db
    except Exception as e:
        raise e


@pytest.fixture()
def healthcare_provider_repository(
    database: Database,
) -> MockHealthcareProviderRepository:
    return MockHealthcareProviderRepository(db_session=database.get_db_session())


@pytest.fixture()
def healthcare_provider_service(database: Database) -> HealthcareProviderService:
    return HealthcareProviderService(database)


@pytest.fixture()
def oin() -> str:
    return "00000001123456700000"


@pytest.fixture()
def healthcare_provider_entity(oin: str) -> HealthcareProviderEntity:
    return HealthcareProviderEntity(
        ura_number="00000123",
        source_id="some_source_id",
        is_source=True,
        is_viewer=True,
        oin=oin,
        common_name="some_common_name",
        status="active",
    )
