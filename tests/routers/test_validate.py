import json
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import (
    Config,
    ConfigApp,
    ConfigKongProxy,
    ConfigOin,
    ConfigStats,
    ConfigTelemetry,
    ConfigUvicorn,
    reset_config,
    set_config,
)
from app.container import get_ca_service, get_jwt_service
from app.models.oin import OinNumber
from app.routers.validator import router
from app.services.jwt import JwtException

OIN = "00000001123456700000"
OTHER_OIN = "00000002987654321000"


@pytest.fixture(autouse=True)
def test_config():
    cfg = Config(
        app=ConfigApp(),
        oin=ConfigOin(
            oin_ca_path="/dev/null",
            issuer="test-issuer",
            audience=["test-audience"],
            jwks_url="http://localhost/jwks",
        ),
        telemetry=ConfigTelemetry(endpoint=None, service_name=None, tracer_name=None),
        stats=ConfigStats(host=None, port=None, module_name=None),
        uvicorn=ConfigUvicorn(ssl_base_dir=None, ssl_cert_file=None, ssl_key_file=None),
        kong_proxy=ConfigKongProxy(url="http://kong.example.com"),
    )
    set_config(cfg)
    yield cfg
    reset_config()


@pytest.fixture
def ca_service():
    mock = MagicMock()
    mock.is_oin_certificate.return_value = (True, OinNumber(OIN))
    mock.check_cert_fingerprint.return_value = True
    return mock


@pytest.fixture
def jwt_service():
    mock = MagicMock()
    token = MagicMock()
    token.claims = json.dumps(
        {
            "oin": OIN,
            "sub": "00000123",
            "aud": "test-audience",
            "scope": "test-scope",
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    mock.verify.return_value = token
    return mock


ENTITY_ID = UUID("12345678-1234-5678-1234-567812345678")


def make_entity(**kwargs: object) -> MagicMock:
    entity = MagicMock()
    entity.id = kwargs.get("id", ENTITY_ID)
    entity.oin = kwargs.get("oin", OIN)
    entity.ura_number = kwargs.get("ura_number", "00000123")
    entity.source_id = kwargs.get("source_id", None)
    entity.common_name = kwargs.get("common_name", "Test Provider")
    entity.is_source = kwargs.get("is_source", True)
    entity.is_viewer = kwargs.get("is_viewer", False)
    entity.status = kwargs.get("status", "active")
    entity.deleted_at = kwargs.get("deleted_at", None)
    return entity


@pytest.fixture
def client(ca_service, jwt_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_ca_service] = lambda: ca_service
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service
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
        token.claims = json.dumps(
            {
                "oin": OTHER_OIN,
                "aud": "test-audience",
                "cnf": {"x5t#S256": "t"},
            }
        )
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


class TestCertificateFingerprint:
    def test_missing_cnf_claim_returns_400(self, client: TestClient, jwt_service: MagicMock) -> None:
        token = MagicMock()
        token.claims = json.dumps(
            {
                "oin": OIN,
                "sub": "00000123",
                "aud": "test-audience",
            }
        )
        jwt_service.verify.return_value = token
        response = client.get("/validate", headers=bearer())
        assert response.status_code == 400
        assert "fingerprint" in response.text.lower()

    def test_fingerprint_mismatch_returns_400(self, client: TestClient, ca_service: MagicMock) -> None:
        ca_service.check_cert_fingerprint.return_value = False
        response = client.get("/validate", headers=bearer())
        assert response.status_code == 400
        assert "fingerprint" in response.text.lower()

    def test_fingerprint_check_called_with_correct_thumbprint(
        self, client: TestClient, ca_service: MagicMock, jwt_service: MagicMock
    ) -> None:
        token = MagicMock()
        token.claims = json.dumps(
            {
                "oin": OIN,
                "sub": "00000123",
                "aud": "test-audience",
                "scope": "test-scope",
                "cnf": {"x5t#S256": "abc123thumbprint"},
            }
        )
        jwt_service.verify.return_value = token
        client.get("/validate", headers=bearer())
        ca_service.check_cert_fingerprint.assert_called_once()
        call_args = ca_service.check_cert_fingerprint.call_args
        assert call_args[0][1] == "abc123thumbprint"
