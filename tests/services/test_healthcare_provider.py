from app.db.models.healthcare_provider import HealthcareProviderEntity
from app.db.models.oin import OinNumber
from app.services.healthcare_provider import HealthcareProviderService
from tests.conftest import MockHealthcareProviderRepository


def test_exists_should_return_true(
    healthcare_provider_repository: MockHealthcareProviderRepository,
    healthcare_provider_service: HealthcareProviderService,
    healthcare_provider_entity: HealthcareProviderEntity,
) -> None:
    with healthcare_provider_repository.db_session:
        healthcare_provider_repository.add_one(healthcare_provider_entity)

    expected = healthcare_provider_service.exists(OinNumber(healthcare_provider_entity.oin))

    assert expected is True


def test_exists_should_return_false(
    healthcare_provider_service: HealthcareProviderService,
    healthcare_provider_entity: HealthcareProviderEntity,
) -> None:
    expected = healthcare_provider_service.exists(OinNumber(healthcare_provider_entity.oin))

    assert expected is False
