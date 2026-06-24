"""Verifies per-field stream routing (APP == stroom 2, SIEM == stroom 3) for the gateway events."""

import io
import json
import logging
from typing import Any, Iterator

import pytest

from app.logging.context import endpoint_var, ip_var, method_var, request_id_var
from app.logging.events import Log
from app.logging.filters import AppFilter, LoggingStreams, SiemFilter
from app.logging.formatter import JsonFormatter


@pytest.fixture
def streams() -> Iterator[tuple[logging.Logger, io.StringIO, io.StringIO]]:
    app_buf, siem_buf = io.StringIO(), io.StringIO()

    app_handler = logging.StreamHandler(app_buf)
    app_handler.addFilter(AppFilter())
    app_handler.setFormatter(JsonFormatter(include_traces=False, stream=LoggingStreams.APP))

    siem_handler = logging.StreamHandler(siem_buf)
    siem_handler.addFilter(SiemFilter())
    siem_handler.setFormatter(JsonFormatter(include_traces=False, stream=LoggingStreams.SIEM))

    logger = logging.getLogger("app.test_stream_routing")
    logger.setLevel(logging.DEBUG)
    logger.handlers = [app_handler, siem_handler]
    logger.propagate = False

    tokens = [
        request_id_var.set("req-1"),
        ip_var.set("10.0.0.1"),
        endpoint_var.set("/validate"),
        method_var.set("GET"),
    ]
    try:
        yield logger, app_buf, siem_buf
    finally:
        logger.handlers = []
        request_id_var.reset(tokens[0])
        ip_var.reset(tokens[1])
        endpoint_var.reset(tokens[2])
        method_var.reset(tokens[3])


def _messages(buf: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line)["message"] for line in buf.getvalue().splitlines()]


def test_binding_mismatch_withholds_endpoint_from_siem(
    streams: tuple[logging.Logger, io.StringIO, io.StringIO],
) -> None:
    logger, app_buf, siem_buf = streams
    Log.event(
        logger,
        Log.MTLS_BINDING_MISMATCH,
        "mismatch",
        jwt_ura="00000123",
        cert_thumbprint_jwt="abc",
        cert_thumbprint_presented="def",
        client_id="00000001",
    )

    app_msg = _messages(app_buf)[0]
    siem_msg = _messages(siem_buf)[0]

    # APP (stroom 2) includes endpoint; SIEM (stroom 3) does not for NVI-AUTH-002
    assert app_msg["endpoint"] == "/validate"
    assert "endpoint" not in siem_msg

    # both streams keep the thumbprints + client_id + jwt_ura
    for msg in (app_msg, siem_msg):
        assert msg["jwt_ura"] == "00000123"
        assert msg["cert_thumbprint_presented"] == "def"
        assert msg["client_id"] == "00000001"


def test_authorization_mismatch_drops_resource_id_and_method_from_siem(
    streams: tuple[logging.Logger, io.StringIO, io.StringIO],
) -> None:
    logger, app_buf, siem_buf = streams
    Log.event(
        logger,
        Log.URA_AUTHORIZATION_MISMATCH,
        "mismatch",
        jwt_ura="00000123",
        resource_ura="00000001",
        resource_id="00000002",
        client_id="00000001",
    )

    app_msg = _messages(app_buf)[0]
    siem_msg = _messages(siem_buf)[0]

    # APP keeps resource_id + method; SIEM keeps neither
    assert app_msg["resource_id"] == "00000002"
    assert app_msg["method"] == "GET"
    assert "resource_id" not in siem_msg
    assert "method" not in siem_msg
    # resource_ura/jwt_ura in both
    assert siem_msg["resource_ura"] == "00000001"
    assert siem_msg["jwt_ura"] == "00000123"


def test_success_keeps_thumbprint_prefix_only_in_app(
    streams: tuple[logging.Logger, io.StringIO, io.StringIO],
) -> None:
    logger, app_buf, siem_buf = streams
    Log.event(
        logger,
        Log.AUTHENTICATION_SUCCESS,
        "ok",
        ura_number="00000123",
        cert_thumbprint_prefix="validthu",
        scope="test-scope",
    )

    app_msg = _messages(app_buf)[0]
    siem_msg = _messages(siem_buf)[0]

    assert app_msg["cert_thumbprint_prefix"] == "validthu"
    assert "cert_thumbprint_prefix" not in siem_msg  # not in SIEM allow-list for 004
    # ura/scope/endpoint/method in both
    for msg in (app_msg, siem_msg):
        assert msg["ura_number"] == "00000123"
        assert msg["scope"] == "test-scope"
        assert msg["endpoint"] == "/validate"
