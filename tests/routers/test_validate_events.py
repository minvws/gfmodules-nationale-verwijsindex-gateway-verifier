"""Asserts each /validate branch emits the correct NVI-AUTH audit event (issue 994)."""

import json
import logging
from unittest.mock import MagicMock

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
from app.logging.events import Log
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
    mock.get_presented_thumbprint.return_value = "presentedthumb"
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


@pytest.fixture
def client(ca_service, jwt_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_ca_service] = lambda: ca_service
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service
    return TestClient(app)


def bearer(token: str = "valid.jwt.token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _record(caplog: pytest.LogCaptureFixture, event_id: str) -> logging.LogRecord:
    matches = [r for r in caplog.records if getattr(r, "event_id", None) == event_id]
    assert matches, (
        f"no log record with event_id={event_id}; got {[getattr(r, 'event_id', None) for r in caplog.records]}"
    )
    return matches[-1]


def test_missing_header_logs_005(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get("/validate")
    record = _record(caplog, Log.MISSING_AUTHORIZATION_HEADER.event_id)
    assert record.token_present is False  # type: ignore[attr-defined]


def test_non_bearer_header_logs_001(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers={"Authorization": "Basic xx"})
    record = _record(caplog, Log.JWT_VERIFICATION_FAILED.event_id)
    assert record.error_reason == "malformed_authorization_header"  # type: ignore[attr-defined]
    assert record.token_present is True  # type: ignore[attr-defined]


def test_invalid_cert_logs_002(client: TestClient, ca_service: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    ca_service.is_oin_certificate.return_value = (False, None)
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=bearer())
    _record(caplog, Log.MTLS_BINDING_MISMATCH.event_id)


def test_jwt_verify_failure_logs_001(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    jwt_service.verify.side_effect = JwtException("expired")
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=bearer())
    record = _record(caplog, Log.JWT_VERIFICATION_FAILED.event_id)
    assert record.error_reason == "expired"  # type: ignore[attr-defined]


def test_missing_cnf_logs_002(client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    token = MagicMock()
    token.claims = json.dumps({"oin": OIN, "sub": "00000123", "aud": "test-audience"})
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=bearer())
    record = _record(caplog, Log.MTLS_BINDING_MISMATCH.event_id)
    assert record.cert_thumbprint_jwt is None  # type: ignore[attr-defined]
    assert record.cert_thumbprint_presented == "presentedthumb"  # type: ignore[attr-defined]


def test_fingerprint_mismatch_logs_002(
    client: TestClient, ca_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    ca_service.check_cert_fingerprint.return_value = False
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=bearer())
    record = _record(caplog, Log.MTLS_BINDING_MISMATCH.event_id)
    assert record.cert_thumbprint_jwt == "validthumbprint"  # type: ignore[attr-defined]


def test_oin_mismatch_logs_003(client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    token = MagicMock()
    token.claims = json.dumps({"oin": OTHER_OIN, "sub": "00000123", "cnf": {"x5t#S256": "validthumbprint"}})
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=bearer())
    record = _record(caplog, Log.URA_AUTHORIZATION_MISMATCH.event_id)
    assert record.resource_ura == OIN  # type: ignore[attr-defined]
    assert record.resource_id == OTHER_OIN  # type: ignore[attr-defined]


def test_success_logs_004(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        response = client.get("/validate", headers=bearer())
    assert response.status_code == 200
    record = _record(caplog, Log.AUTHENTICATION_SUCCESS.event_id)
    assert record.ura_number == "00000123"  # type: ignore[attr-defined]
    # prefix only, never the full thumbprint
    assert record.cert_thumbprint_prefix == "validthu"  # type: ignore[attr-defined]
    assert record.scope == "test-scope"  # type: ignore[attr-defined]
