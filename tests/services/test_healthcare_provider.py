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


def test_find_should_return_entity(
    healthcare_provider_repository: MockHealthcareProviderRepository,
    healthcare_provider_service: HealthcareProviderService,
    healthcare_provider_entity: HealthcareProviderEntity,
) -> None:
    with healthcare_provider_repository.db_session:
        healthcare_provider_repository.add_one(healthcare_provider_entity)

    result = healthcare_provider_service.find(OinNumber(healthcare_provider_entity.oin))

    assert len(result) == 1
    assert result[0].oin == healthcare_provider_entity.oin


def test_find_should_return_empty_when_no_match(
    healthcare_provider_service: HealthcareProviderService,
    healthcare_provider_entity: HealthcareProviderEntity,
) -> None:
    result = healthcare_provider_service.find(OinNumber(healthcare_provider_entity.oin))

    assert result == []


def test_find_filters_by_source_id(
    healthcare_provider_repository: MockHealthcareProviderRepository,
    healthcare_provider_service: HealthcareProviderService,
    healthcare_provider_entity: HealthcareProviderEntity,
) -> None:
    with healthcare_provider_repository.db_session:
        healthcare_provider_repository.add_one(healthcare_provider_entity)

    result = healthcare_provider_service.find(OinNumber(healthcare_provider_entity.oin), source_id="other_source")

    assert result == []
