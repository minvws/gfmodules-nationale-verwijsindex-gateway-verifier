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
from app.container import get_jwt_service
from app.logging.events import Log
from app.routers.validator import router
from app.services.jwt import JwtException

CLIENT_ORGANIZATION_ID = "00000001123456700000"
CLIENT_COMMON_NAME = "common-name"
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
            "sub": ORGANIZATION_ID,
            "act": {"sub": CLIENT_ORGANIZATION_ID, "cn": CLIENT_COMMON_NAME},
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
        "x-gf-act-sub": CLIENT_ORGANIZATION_ID,
        "x-gf-act-cn": "common-name",
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
    record = _record(caplog, Log.MISSING_AUTHORIZATION_HEADER.event_id)
    assert record.token_present is False  # type: ignore[attr-defined]


def test_non_bearer_header_logs_001(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get(
            "/validate",
            headers={
                "x-gf-act-sub": CLIENT_ORGANIZATION_ID,
                "x-gf-act-cn": "common-name",
                "Authorization": "Basic xx",
            },
        )
    record = _record(caplog, Log.MALFORMED_AUTHORIZATION_HEADER.event_id)
    assert record.error_reason == "malformed_authorization_header"  # type: ignore[attr-defined]
    assert record.token_present is True  # type: ignore[attr-defined]


def test_jwt_verify_failure_logs_001(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    jwt_service.verify.side_effect = JwtException("expired")
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.JWT_VERIFICATION_FAILED.event_id)
    assert record.error_reason == "expired"  # type: ignore[attr-defined]


def test_missing_act_logs_missing_act_claim(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": OTHER_ORGANIZATION_ID,
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.MISSING_ACT_CLAIM.event_id)
    assert record.claims["sub"] == OTHER_ORGANIZATION_ID  # type: ignore[attr-defined]


def test_missing_act_sub_logs_missing_organization_claim(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": OTHER_ORGANIZATION_ID,
            "act": {"cn": "other-common-name"},
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.MISSING_ORGANIZATION_CLAIM.event_id)
    assert record.claims["act"] == {"cn": "other-common-name"}  # type: ignore[attr-defined]


def test_oin_mismatch_logs_003(client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": OTHER_ORGANIZATION_ID,
            "act": {"sub": OTHER_ORGANIZATION_ID, "cn": "other-common-name"},
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.ORGANIZATION_AUTHORIZATION_MISMATCH.event_id)
    assert record.claims["sub"] == OTHER_ORGANIZATION_ID  # type: ignore[attr-defined]


def test_common_name_mismatch_logs_common_name_authorization_mismatch(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": ORGANIZATION_ID,
            "act": {"sub": CLIENT_ORGANIZATION_ID, "cn": "other-common-name"},
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.COMMON_NAME_AUTHORIZATION_MISMATCH.event_id)
    assert record.claims["act"]["cn"] == "other-common-name"  # type: ignore[attr-defined]


def test_success_logs_004(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        response = client.get("/validate", headers=headers())
    assert response.status_code == 200
    record = _record(caplog, Log.AUTHENTICATION_SUCCESS.event_id)
    assert record.claims["sub"] == ORGANIZATION_ID  # type: ignore[attr-defined]
    assert record.claims["act"]["cn"] == CLIENT_COMMON_NAME  # type: ignore[attr-defined]
    assert record.claims["act"]["sub"] == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]
    assert record.claims["scope"] == "test-scope"  # type: ignore[attr-defined]
