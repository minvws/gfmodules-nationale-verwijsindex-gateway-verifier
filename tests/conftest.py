from typing import Any, Generator

import pytest

from app.config import ConfigDatabase
from app.db.db import Database
from app.db.repository.healthcare_provider import HealthcareProvidersRepository
from app.services.healthcare_provider import HeatlhcareProviderService


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
def healthcare_provider_repository(database: Database) -> HealthcareProvidersRepository:
    return HealthcareProvidersRepository(db_session=database.get_db_session())


@pytest.fixture()
def healthcare_provider_service(database: Database) -> HeatlhcareProviderService:
    return HeatlhcareProviderService(database)
