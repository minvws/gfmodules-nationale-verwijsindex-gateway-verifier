from typing import Any, Generator

import pytest

from app.config import ConfigDatabase
from app.db.db import Database
from app.db.models.healthcare_provider import HealthcareProviderEntity
from app.db.repository.healthcare_provider import HealthcareProvidersRepository
from app.models.oin_number import OinNumber
from app.models.ura_number import UraNumber
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


@pytest.fixture()
def ura_number() -> UraNumber:
    return UraNumber("00000123")


@pytest.fixture()
def oin() -> OinNumber:
    return OinNumber("00000003123456780001")


@pytest.fixture()
def healthcare_provider_entity(ura_number: UraNumber, oin: OinNumber) -> HealthcareProviderEntity:
    return HealthcareProviderEntity(
        ura_number=ura_number.value,
        source_id="some_source_id",
        is_source=True,
        is_viewer=True,
        oin=oin.value,
        common_name="some_common_name",
        status="active",
    )
