from app.db.models.healthcare_provider import HealthcareProviderEntity
from app.db.models.oin import OinNumber
from tests.conftest import MockHealthcareProviderRepository


def test_find_should_return_entity(
    healthcare_provider_repository: MockHealthcareProviderRepository,
    healthcare_provider_entity: HealthcareProviderEntity,
) -> None:
    with healthcare_provider_repository.db_session:
        data = healthcare_provider_repository.add_one(healthcare_provider_entity)
        result = healthcare_provider_repository.find(OinNumber(data.oin), None)

        assert len(result) > 0


def test_find_should_return_empty(healthcare_provider_repository: MockHealthcareProviderRepository, oin: str) -> None:
    with healthcare_provider_repository.db_session:
        result = healthcare_provider_repository.find(OinNumber(oin), None)

        assert len(result) == 0
