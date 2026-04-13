import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import (
    Config,
    ConfigApp,
    ConfigDatabase,
    ConfigKongProxy,
    ConfigStats,
    ConfigTelemetry,
    ConfigUvicorn,
    reset_config,
    set_config,
)
from app.container import get_ca_service, get_healthcare_provider_service, get_jwt_service
from app.db.models.oin import OinNumber
from app.routers.proxy import router
from app.services.jwt import JwtException

OIN = "00000001123456700000"
KONG_URL = "http://kong.example.com/service"

VALID_CLAIMS = json.dumps(
    {"oin": OIN, "sub": "00000123", "authorized_role": "test-role", "aud": "test-audience", "scope": "test-scope"}
)


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
        kong_proxy=ConfigKongProxy(enabled=True, url=KONG_URL),
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
    token.claims = VALID_CLAIMS
    mock.verify.return_value = token
    return mock


@pytest.fixture
def healthcare_service():
    mock = MagicMock()
    entity = MagicMock()
    entity.ura_number = "00000123"
    mock.find.return_value = [entity]
    return mock


@pytest.fixture
def client(ca_service, jwt_service, healthcare_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_ca_service] = lambda: ca_service
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[get_healthcare_provider_service] = lambda: healthcare_service
    return TestClient(app)


def bearer() -> dict[str, str]:
    return {"Authorization": "Bearer valid.jwt.token"}


def kong_ok() -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.content = b"ok"
    return response


class TestProxyDisabled:
    def test_returns_503_when_disabled(self, client: TestClient, test_config: Config) -> None:
        test_config.kong_proxy.enabled = False
        response = client.post("/proxy", headers=bearer())
        assert response.status_code == 503


class TestProxyValidation:
    def test_missing_auth_returns_401(self, client: TestClient) -> None:
        response = client.post("/proxy")
        assert response.status_code == 401

    def test_invalid_cert_returns_403(self, client: TestClient, ca_service: MagicMock) -> None:
        ca_service.is_oin_certificate.return_value = (False, None)
        response = client.post("/proxy", headers=bearer())
        assert response.status_code == 403

    def test_invalid_jwt_returns_400(self, client: TestClient, jwt_service: MagicMock) -> None:
        jwt_service.verify.side_effect = JwtException("bad token")
        response = client.post("/proxy", headers=bearer())
        assert response.status_code == 400

    def test_no_match_returns_404(self, client: TestClient, healthcare_service: MagicMock) -> None:
        healthcare_service.find.return_value = []
        response = client.post("/proxy", headers=bearer())
        assert response.status_code == 404


class TestProxyForwarding:
    def test_forwards_to_kong_url(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post("/proxy", headers=bearer(), content=b'{"key": "value"}')
            mock_req.assert_called_once()
            assert mock_req.call_args[0][1] == KONG_URL

    def test_forwards_using_same_method(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.put("/proxy", headers=bearer())
            assert mock_req.call_args[0][0] == "PUT"

    def test_get_method_forwarded(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.get("/proxy", headers=bearer())
            assert mock_req.call_args[0][0] == "GET"

    def test_x_headers_sent_to_kong(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post("/proxy", headers=bearer())
            sent_headers = mock_req.call_args[1]["headers"]
            assert "X-Oin-Number" in sent_headers
            assert sent_headers["X-Oin-Number"] == OIN
            assert "X-Ura-Number" in sent_headers

    def test_original_body_forwarded(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post("/proxy", headers=bearer(), content=b"hello")
            assert mock_req.call_args[1]["data"] == b"hello"

    def test_kong_response_status_returned(self, client: TestClient) -> None:
        kong = MagicMock()
        kong.status_code = 201
        kong.content = b"created"
        with patch("app.routers.proxy.http_requests.request", return_value=kong):
            response = client.post("/proxy", headers=bearer())
            assert response.status_code == 201
