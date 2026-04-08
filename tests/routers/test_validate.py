import json
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import (
    Config,
    ConfigApp,
    ConfigDatabase,
    ConfigStats,
    ConfigTelemetry,
    ConfigUvicorn,
    reset_config,
    set_config,
)
from app.container import get_ca_service, get_healthcare_provider_service, get_jwt_service
from app.db.models.oin import OinNumber
from app.routers.healthcare_provider import router
from app.services.jwt import JwtException

OIN = "00000001123456700000"
OTHER_OIN = "00000002987654321000"


@pytest.fixture(autouse=True)
def test_config():
    cfg = Config(
        app=ConfigApp(
            oin_ca_path="/dev/null",
            issuer="test-issuer",
            audience=["test-audience"],
            jwks_url="http://localhost/jwks",
        ),
        database=ConfigDatabase(dsn="sqlite:///:memory:", retry_backoff=[]),
        telemetry=ConfigTelemetry(endpoint=None, service_name=None, tracer_name=None),
        stats=ConfigStats(host=None, port=None, module_name=None),
        uvicorn=ConfigUvicorn(ssl_base_dir=None, ssl_cert_file=None, ssl_key_file=None),
    )
    set_config(cfg)
    yield cfg
    reset_config()


@pytest.fixture
def ca_service():
    mock = MagicMock()
    mock.is_oin_certificate.return_value = (True, OinNumber(OIN))
    return mock


@pytest.fixture
def jwt_service():
    mock = MagicMock()
    token = MagicMock()
    token.claims = json.dumps({"oin": OIN})
    mock.verify.return_value = token
    return mock


@pytest.fixture
def healthcare_service():
    mock = MagicMock()
    mock.exists.return_value = True
    return mock


@pytest.fixture
def client(ca_service, jwt_service, healthcare_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_ca_service] = lambda: ca_service
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[get_healthcare_provider_service] = lambda: healthcare_service
    return TestClient(app)


def bearer(token: str = "valid.jwt.token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestMissingOrInvalidAuthorization:
    def test_no_authorization_header_returns_401(self, client: TestClient) -> None:
        response = client.get("/validate")
        assert response.status_code == 401

    def test_non_bearer_authorization_returns_401(self, client: TestClient) -> None:
        response = client.get("/validate", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert response.status_code == 401


class TestCertificateValidation:
    def test_invalid_oin_certificate_returns_403(self, client: TestClient, ca_service: MagicMock) -> None:
        ca_service.is_oin_certificate.return_value = (False, None)
        response = client.get("/validate", headers=bearer())
        assert response.status_code == 403

    def test_oin_certificate_check_called_with_request(self, client: TestClient, ca_service: MagicMock) -> None:
        client.get("/validate", headers=bearer())
        ca_service.is_oin_certificate.assert_called_once()


class TestJWTValidation:
    def test_invalid_jwt_returns_400(self, client: TestClient, jwt_service: MagicMock) -> None:
        jwt_service.verify.side_effect = JwtException("bad token")
        response = client.get("/validate", headers=bearer("bad.token"))
        assert response.status_code == 400

    def test_jwt_verified_with_configured_issuer_and_audience(self, client: TestClient, jwt_service: MagicMock) -> None:
        client.get("/validate", headers=bearer())
        jwt_service.verify.assert_called_once_with("valid.jwt.token", "test-issuer", ["test-audience"])


class TestOINMatching:
    def test_jwt_oin_mismatch_with_cert_oin_returns_400(self, client: TestClient, jwt_service: MagicMock) -> None:
        token = MagicMock()
        token.claims = json.dumps({"oin": OTHER_OIN})
        jwt_service.verify.return_value = token

        response = client.get("/validate", headers=bearer())
        assert response.status_code == 400
        assert "OIN" in response.text

    def test_jwt_oin_null_returns_400(self, client: TestClient, jwt_service: MagicMock) -> None:
        token = MagicMock()
        token.claims = json.dumps({"oin": None})
        jwt_service.verify.return_value = token

        response = client.get("/validate", headers=bearer())
        assert response.status_code == 400


class TestHealthcareProviderLookup:
    def test_oin_found_returns_200(self, client: TestClient, healthcare_service: MagicMock) -> None:
        healthcare_service.exists.return_value = True
        response = client.get("/validate", headers=bearer())
        assert response.status_code == 200

    def test_oin_not_found_returns_404(self, client: TestClient, healthcare_service: MagicMock) -> None:
        healthcare_service.exists.return_value = False
        response = client.get("/validate", headers=bearer())
        assert response.status_code == 404

    def test_source_id_header_passed_to_service(self, client: TestClient, healthcare_service: MagicMock) -> None:
        client.get("/validate", headers={**bearer(), "X-Source-Id": "my-source"})
        healthcare_service.exists.assert_called_once_with(OinNumber(OIN), "my-source")

    def test_missing_source_id_header_passes_none_to_service(
        self, client: TestClient, healthcare_service: MagicMock
    ) -> None:
        client.get("/validate", headers=bearer())
        healthcare_service.exists.assert_called_once_with(OinNumber(OIN), None)
