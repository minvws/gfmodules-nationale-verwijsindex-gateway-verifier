import json
from unittest.mock import MagicMock, patch

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
from app.routers.proxy import router

CLIENT_ORGANIZATION_ID = "00000001123456700000"
ORGANIZATION_ID = "00000001123456780000"
KONG_URL = "http://kong.example.com/service"

VALID_CLAIMS = json.dumps(
    {
        "sub": CLIENT_ORGANIZATION_ID,
        "org_oin": ORGANIZATION_ID,
        "aud": "test-audience",
        "scope": "test-scope",
        "cnf": {"x5t#S256": "validthumbprint"},
    }
)


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
        kong_proxy=ConfigKongProxy(enabled=True, url=KONG_URL),
    )
    set_config(cfg)
    yield cfg
    reset_config()


@pytest.fixture
def jwt_service():
    mock = MagicMock()
    token = MagicMock()
    token.claims = VALID_CLAIMS
    mock.verify.return_value = token
    return mock


@pytest.fixture
def client(jwt_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service
    return TestClient(app)


def headers() -> dict[str, str]:
    return {
        "x-gf-client-organization-id": CLIENT_ORGANIZATION_ID,
        "x-gf-client-common-name": "common-name",
        "Authorization": "Bearer valid.jwt.token",
    }


def kong_ok() -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.content = b"ok"
    response.headers = {"content-type": "application/json"}
    return response


class TestProxyDisabled:
    def test_returns_503_when_disabled(self, client: TestClient, test_config: Config) -> None:
        test_config.kong_proxy.enabled = False
        response = client.post("/proxy", headers=headers())
        assert response.status_code == 503


class TestProxyValidation:
    def test_invalid_auth_returns_401(self, client: TestClient) -> None:
        response = client.post(
            "/proxy",
            headers={
                "x-gf-client-organization-id": "organization-id",
                "x-gf-client-common-name": "common-name",
                "Authorization": "INVALID",
            },
        )
        assert response.status_code == 401

    def test_missing_auth_returns_500(self, client: TestClient) -> None:
        response = client.post(
            "/proxy",
            headers={
                "x-gf-client-organization-id": "organization-id",
                "x-gf-client-common-name": "common-name",
            },
        )
        assert response.status_code == 500

    def test_missing_client_id_returns_500(self, client: TestClient) -> None:
        response = client.post(
            "/proxy",
            headers={
                "x-gf-client-common-name": "common-name",
            },
        )
        assert response.status_code == 500

    def test_missing_common_name(self, client: TestClient, jwt_service: MagicMock) -> None:
        response = client.post(
            "/proxy",
            headers={
                "x-gf-client-organization-id": "organization-id",
            },
        )
        assert response.status_code == 500


class TestProxyForwarding:
    def test_forwards_to_kong_url(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post(
                "/proxy",
                headers=headers(),
                content=b'{"key": "value"}',
            )
            mock_req.assert_called_once()
            assert mock_req.call_args[0][1] == KONG_URL

    def test_forwards_using_same_method(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.put("/proxy", headers=headers())
            assert mock_req.call_args[0][0] == "PUT"

    def test_get_method_forwarded(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.get("/proxy", headers=headers())
            assert mock_req.call_args[0][0] == "GET"

    def test_x_headers_sent_to_kong(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post("/proxy", headers=headers())
            sent_headers = mock_req.call_args[1]["headers"]
            assert "x-gf-oin" in sent_headers
            assert sent_headers["x-gf-oin"] == ORGANIZATION_ID

    def test_original_body_forwarded(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post("/proxy", headers=headers(), content=b"hello")
            assert mock_req.call_args[1]["data"] == b"hello"

    def test_kong_response_status_returned(self, client: TestClient) -> None:
        kong = MagicMock()
        kong.status_code = 201
        kong.content = b"created"
        kong.headers = {}
        with patch("app.routers.proxy.http_requests.request", return_value=kong):
            response = client.post("/proxy", headers=headers())
            assert response.status_code == 201


class TestProxyTransparentForwarding:
    def test_subpath_preserved(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.get("/proxy/fhir/List", headers=headers())
            assert mock_req.call_args[0][1] == f"{KONG_URL}/fhir/List"

    def test_query_string_preserved(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.get("/proxy/fhir/List", params={"subject": "abc"}, headers=headers())
            assert mock_req.call_args[0][1] == f"{KONG_URL}/fhir/List?subject=abc"

    def test_bare_proxy_forwards_to_root(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post("/proxy", headers=headers())
            assert mock_req.call_args[0][1] == KONG_URL

    def test_client_cert_header_forwarded(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post(
                "/proxy",
                headers={**headers(), "X-Forwarded-Tls-Client-Cert": "PEMDATA"},
            )
            sent_headers = mock_req.call_args[1]["headers"]
            assert sent_headers["x-forwarded-tls-client-cert"] == "PEMDATA"

    def test_spoofed_identity_header_overwritten(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.post("/proxy", headers={**headers(), "x-gf-oin": "99999999999999999999"})
            sent_headers = mock_req.call_args[1]["headers"]
            assert sent_headers["x-gf-oin"] == ORGANIZATION_ID

    def test_backend_content_type_returned(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()):
            response = client.post("/proxy", headers=headers())
            assert response.headers["content-type"] == "application/json"


class TestProxyHealthPassthrough:
    def test_health_skips_auth_and_forwards(self, client: TestClient) -> None:
        # No Authorization header and no client cert: still forwarded, not 401.
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            response = client.get("/proxy/health")
            assert response.status_code == 200
            assert mock_req.call_args[0][1] == f"{KONG_URL}/health"

    def test_health_does_not_inject_identity(self, client: TestClient) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()) as mock_req:
            client.get("/proxy/health")
            sent_headers = mock_req.call_args[1]["headers"]
            assert not any(key.lower().startswith("x-gf-") for key in sent_headers)

    def test_health_does_not_validate(self, client: TestClient, jwt_service: MagicMock) -> None:
        with patch("app.routers.proxy.http_requests.request", return_value=kong_ok()):
            client.get("/proxy/health")
            jwt_service.verify.assert_not_called()
