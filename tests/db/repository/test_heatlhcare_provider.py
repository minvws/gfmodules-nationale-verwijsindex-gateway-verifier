from app.db.models.healthcare_provider import HealthcareProviderEntity
from tests.conftest import MockHealthcareProviderRepository


def test_exists_should_return_true(
    healthcare_provider_repository: MockHealthcareProviderRepository,
    healthcare_provider_entity: HealthcareProviderEntity,
) -> None:
    with healthcare_provider_repository.db_session:
        data = healthcare_provider_repository.add_one(healthcare_provider_entity)
        expected = healthcare_provider_repository.exists(data.oin)

        assert expected is True


def test_exists_should_return_false(healthcare_provider_repository: MockHealthcareProviderRepository, oin: str) -> None:
    with healthcare_provider_repository.db_session:
        expected = healthcare_provider_repository.exists(oin)

        assert expected is False
