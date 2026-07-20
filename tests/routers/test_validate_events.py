"""Asserts each /validate branch emits the correct audit event.

NVI-AUTH events per issue 994 (default), PRS-AUTH events per issue 1034 when
``logging.application_log_type`` is set to ``prs``.
"""

import json
import logging
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import (
    ApplicationLogType,
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
from app.container import get_jwt_service
from app.logging.events import NviLog, PrsLog
from app.routers.validator import router
from app.services.jwt import JwtException

CLIENT_ORGANIZATION_ID = "00000001123456700000"
ORGANIZATION_ID = "00000001123456780000"
OTHER_ORGANIZATION_ID = "00000002987654321000"


@pytest.fixture(autouse=True)
def test_config():
    cfg = Config(
        app=ConfigApp(),
        oin=ConfigOin(
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
def jwt_service():
    mock = MagicMock()
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": CLIENT_ORGANIZATION_ID,
            "act": {"sub": ORGANIZATION_ID},
            "aud": "test-audience",
            "scope": "test-scope",
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    mock.verify.return_value = token
    return mock


@pytest.fixture
def client(jwt_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service
    return TestClient(app)


def headers(token: str = "valid.jwt.token") -> dict[str, str]:
    return {
        "x-gf-client-organization-id": CLIENT_ORGANIZATION_ID,
        "x-gf-client-common-name": "common-name",
        "Authorization": "Bearer valid.jwt.token",
    }


def _record(caplog: pytest.LogCaptureFixture, event_id: str) -> logging.LogRecord:
    matches = [r for r in caplog.records if getattr(r, "event_id", None) == event_id]
    assert matches, (
        f"no log record with event_id={event_id}; got {[getattr(r, 'event_id', None) for r in caplog.records]}"
    )
    return matches[-1]


def test_missing_header_logs_005(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get("/validate")
    record = _record(caplog, NviLog.MISSING_AUTHORIZATION_HEADER.event_id)
    assert record.token_present is False  # type: ignore[attr-defined]


def test_non_bearer_header_logs_001(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get(
            "/validate",
            headers={
                "x-gf-client-organization-id": CLIENT_ORGANIZATION_ID,
                "x-gf-client-common-name": "common-name",
                "Authorization": "Basic xx",
            },
        )
    record = _record(caplog, NviLog.JWT_VERIFICATION_FAILED.event_id)
    assert record.error_reason == "malformed_authorization_header"  # type: ignore[attr-defined]
    assert record.token_present is True  # type: ignore[attr-defined]


def test_jwt_verify_failure_logs_001(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    jwt_service.verify.side_effect = JwtException("expired")
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, NviLog.JWT_VERIFICATION_FAILED.event_id)
    assert record.error_reason == "expired"  # type: ignore[attr-defined]


def test_oin_mismatch_logs_003(client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "oin": OTHER_ORGANIZATION_ID,
            "sub": OTHER_ORGANIZATION_ID,
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, NviLog.URA_AUTHORIZATION_MISMATCH.event_id)
    assert record.sub == OTHER_ORGANIZATION_ID  # type: ignore[attr-defined]


def test_success_logs_004(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        response = client.get("/validate", headers=headers())
    assert response.status_code == 200
    record = _record(caplog, NviLog.AUTHENTICATION_SUCCESS.event_id)
    assert record.sub == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]
    assert record.scope == "test-scope"  # type: ignore[attr-defined]


# --- PRS-AUTH variants (logging.application_log_type = prs, issue 1034) ---


@pytest.fixture
def prs_config(test_config: Config) -> Config:
    test_config.logging.application_log_type = ApplicationLogType.prs
    return test_config


def test_prs_missing_header_logs_200404(
    prs_config: Config, client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get("/validate")
    record = _record(caplog, PrsLog.MISSING_AUTHORIZATION_HEADER.event_id)
    assert record.token_present is False  # type: ignore[attr-defined]


def test_prs_jwt_verify_failure_logs_200400(
    prs_config: Config,
    client: TestClient,
    jwt_service: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    jwt_service.verify.side_effect = JwtException("expired")
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, PrsLog.JWT_VERIFICATION_FAILED.event_id)
    assert record.error_reason == "expired"  # type: ignore[attr-defined]


def test_prs_oin_mismatch_logs_200406(
    prs_config: Config,
    client: TestClient,
    jwt_service: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "oin": OTHER_ORGANIZATION_ID,
            "sub": OTHER_ORGANIZATION_ID,
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, PrsLog.TOKEN_BINDING_INVALID.event_id)
    assert record.failure_reason == "oin_mismatch"  # type: ignore[attr-defined]
    assert record.sub == OTHER_ORGANIZATION_ID  # type: ignore[attr-defined]


def test_prs_success_logs_200403(prs_config: Config, client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        response = client.get("/validate", headers=headers())
    assert response.status_code == 200
    record = _record(caplog, PrsLog.AUTHENTICATION_SUCCESS.event_id)
    assert record.sub == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]
    # prefix only, never the full thumbprint
    assert record.scope == "test-scope"  # type: ignore[attr-defined]
