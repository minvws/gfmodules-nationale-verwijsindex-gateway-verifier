from typing import Any, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.logging.context import (
    CLIENT_TRACE_ID_HEADER,
    CORRELATION_ID_HEADER,
    REQUEST_ID_HEADER,
    UNSET,
    correlation_id_var,
    endpoint_var,
    method_var,
    request_id_var,
)
from app.logging.middleware import RequestContextMiddleware

CORRELATION_ID = "some-generated-id"


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = FastAPI()

    @app.get("/echo")
    def echo() -> dict[str, Any]:
        return {
            "correlation_id": correlation_id_var.get(),
            "request_id": request_id_var.get(),
            "endpoint": endpoint_var.get(),
            "method": method_var.get(),
        }

    app.add_middleware(RequestContextMiddleware)

    with TestClient(app) as test_client:
        yield test_client


def test_inbound_correlation_id_reaches_the_endpoint(client: TestClient) -> None:
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: CORRELATION_ID})

    assert response.json()["correlation_id"] == CORRELATION_ID


def test_correlation_id_is_echoed_on_the_response(client: TestClient) -> None:
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: CORRELATION_ID})

    assert response.headers[CORRELATION_ID_HEADER] == CORRELATION_ID
    assert response.headers[REQUEST_ID_HEADER]


def test_missing_correlation_id_is_not_invented_or_echoed(client: TestClient) -> None:
    response = client.get("/echo")

    assert response.json()["correlation_id"] == UNSET
    assert CORRELATION_ID_HEADER not in response.headers


def test_correlation_id_header_lookup_is_case_insensitive(client: TestClient) -> None:
    response = client.get("/echo", headers={"x-gf-correlation-id": CORRELATION_ID})

    assert response.json()["correlation_id"] == CORRELATION_ID


def test_unsafe_characters_are_stripped(client: TestClient) -> None:
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: "abc$%^123"})

    assert response.json()["correlation_id"] == "abc123"


def test_correlation_id_is_truncated(client: TestClient) -> None:
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: "a" * 200})

    assert response.json()["correlation_id"] == "a" * 64


def test_fully_unsafe_correlation_id_falls_back_to_the_sentinel(client: TestClient) -> None:
    # Sanitizing to an empty string must not yield an empty header value.
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: "$$$"})

    assert response.json()["correlation_id"] == UNSET
    assert CORRELATION_ID_HEADER not in response.headers


def test_client_trace_id_is_echoed_alongside(client: TestClient) -> None:
    response = client.get("/echo", headers={CLIENT_TRACE_ID_HEADER: "trace-1"})

    assert response.headers[CLIENT_TRACE_ID_HEADER] == "trace-1"


def test_endpoint_and_method_are_bound(client: TestClient) -> None:
    body = client.get("/echo").json()

    assert body["endpoint"] == "/echo"
    assert body["method"] == "GET"


def test_context_does_not_leak_between_requests(client: TestClient) -> None:
    client.get("/echo", headers={CORRELATION_ID_HEADER: CORRELATION_ID})

    assert client.get("/echo").json()["correlation_id"] == UNSET
    assert correlation_id_var.get() == UNSET


def test_each_request_gets_a_distinct_request_id(client: TestClient) -> None:
    first = client.get("/echo").headers[REQUEST_ID_HEADER]
    second = client.get("/echo").headers[REQUEST_ID_HEADER]

    assert first != second
