from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import HTTPError, Timeout

from app.services.http_service import HttpService

PATCHED_MODULE = "app.services.http_service.request"


@pytest.fixture()
def http_service() -> HttpService:
    return HttpService(
        endpoint="https://example.com/api",
        timeout=5,
        mtls_cert="path/to/cert",
        mtls_key="path/to/key",
        verify_ca=True,
    )


@patch(PATCHED_MODULE)
def test_do_request_should_succeed(response: MagicMock, http_service: HttpService) -> None:
    data = {"message": "hello world"}
    mock_call = MagicMock()
    mock_call.status_code = 200
    mock_call.json.return_value = data
    response.return_value = mock_call

    actual = http_service.do_request("GET")

    assert actual.status_code == 200
    assert actual.json() == data


@patch(PATCHED_MODULE)
def test_do_request_raise_excetion_with_timeout(response: MagicMock, http_service: HttpService) -> None:
    response.side_effect = Timeout
    with pytest.raises(Timeout):
        http_service.do_request("GET")


@patch(PATCHED_MODULE)
def test_do_request_raise_excetion_with_connection_error(response: MagicMock, http_service: HttpService) -> None:
    response.side_effect = ConnectionError
    with pytest.raises(ConnectionError):
        http_service.do_request("GET")


@patch(PATCHED_MODULE)
def test_do_request_raise_excetion_with_general_http_error(response: MagicMock, http_service: HttpService) -> None:
    response.side_effect = HTTPError
    with pytest.raises(HTTPError):
        http_service.do_request("GET")


@patch(PATCHED_MODULE)
def test_do_request_sends_json_data(response: MagicMock, http_service: HttpService) -> None:
    mock_response = MagicMock()
    mock_response.status_code = 201
    response.return_value = mock_response

    http_service.do_request("POST", json={"name": "test"})

    _, kwargs = response.call_args
    assert kwargs["json"] == {"name": "test"}


@patch(PATCHED_MODULE)
def test_do_request_builds_url_with_sub_route(response: MagicMock, http_service: HttpService) -> None:
    mock_response = MagicMock()
    mock_response.status_code = 200
    response.return_value = mock_response

    http_service.do_request("GET", sub_route="resource/1")

    _, kwargs = response.call_args
    assert kwargs["url"] == "https://example.com/api/resource/1"


@patch(PATCHED_MODULE)
def test_do_request_uses_base_url_without_sub_route(response: MagicMock, http_service: HttpService) -> None:
    mock_response = MagicMock()
    mock_response.status_code = 200
    response.return_value = mock_response

    http_service.do_request("GET")

    _, kwargs = response.call_args
    assert kwargs["url"] == "https://example.com/api"


@patch(PATCHED_MODULE)
def test_do_request_passes_params_and_headers(response: MagicMock, http_service: HttpService) -> None:
    mock_response = MagicMock()
    mock_response.status_code = 200
    response.return_value = mock_response

    http_service.do_request("GET", params={"q": "search"}, headers={"Authorization": "Bearer token"})

    _, kwargs = response.call_args
    assert kwargs["params"] == {"q": "search"}
    assert kwargs["headers"] == {"Authorization": "Bearer token"}


@patch(PATCHED_MODULE)
def test_do_request_without_mtls_cert(response: MagicMock) -> None:
    service = HttpService(
        endpoint="https://example.com/api",
        timeout=5,
        mtls_cert=None,
        mtls_key=None,
        verify_ca=False,
    )
    mock_response = MagicMock()
    mock_response.status_code = 200
    response.return_value = mock_response

    service.do_request("GET")

    _, kwargs = response.call_args
    assert kwargs["cert"] is None
    assert kwargs["verify"] is False
