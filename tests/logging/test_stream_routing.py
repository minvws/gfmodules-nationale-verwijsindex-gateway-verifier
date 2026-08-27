"""Verifies per-field stream routing (APP == stroom 2, SIEM == stroom 3) for the gateway events."""

import io
import json
import logging
from collections.abc import Iterator
from contextlib import ExitStack
from typing import Any

import gfmodules.logging as gflog
import pytest
from gfmodules.logging import LoggingStreams, bind_context
from gfmodules.logging.formatter import JsonFormatter
from gfmodules.logging.testing import capture_stream

from app.logging.events import NviLog, PrsLog

_LOGGER_NAME = "app.test_stream_routing"

Messages = list[dict[str, Any]]
Streams = tuple[logging.Logger, Messages, Messages]


@pytest.fixture
def streams() -> Iterator[Streams]:
    logger = logging.getLogger(_LOGGER_NAME)

    with ExitStack() as stack:
        app_messages = stack.enter_context(capture_stream(LoggingStreams.APP, _LOGGER_NAME))
        siem_messages = stack.enter_context(capture_stream(LoggingStreams.SIEM, _LOGGER_NAME))
        stack.enter_context(
            bind_context(
                {
                    "request_id": "req-1",
                    "ip": "10.0.0.1",
                    "endpoint": "/validate",
                    "method": "GET",
                    "correlation_id": "corr-1",
                }
            )
        )
        yield logger, app_messages, siem_messages


def test_binding_mismatch_withholds_endpoint_from_siem(
    streams: Streams,
) -> None:
    logger, app_messages, siem_messages = streams
    gflog.emit(
        logger,
        NviLog.MTLS_BINDING_MISMATCH,
        "mismatch",
        fields={
            "jwt_ura": "00000123",
            "cert_thumbprint_jwt": "abc",
            "cert_thumbprint_presented": "def",
            "client_id": "00000001",
        },
    )

    app_msg = app_messages[0]
    siem_msg = siem_messages[0]

    # APP (stroom 2) includes endpoint; SIEM (stroom 3) does not for NVI-AUTH-002
    assert app_msg["endpoint"] == "/validate"
    assert "endpoint" not in siem_msg

    # both streams keep the thumbprints + client_id + jwt_ura
    for msg in (app_msg, siem_msg):
        assert msg["jwt_ura"] == "00000123"
        assert msg["cert_thumbprint_presented"] == "def"
        assert msg["client_id"] == "00000001"


def test_authorization_mismatch_drops_resource_id_and_method_from_siem(
    streams: Streams,
) -> None:
    logger, app_messages, siem_messages = streams
    gflog.emit(
        logger,
        NviLog.URA_AUTHORIZATION_MISMATCH,
        "mismatch",
        fields={"jwt_ura": "00000123", "resource_ura": "00000001", "resource_id": "00000002", "client_id": "00000001"},
    )

    app_msg = app_messages[0]
    siem_msg = siem_messages[0]

    # APP keeps resource_id + method; SIEM keeps neither
    assert app_msg["resource_id"] == "00000002"
    assert app_msg["method"] == "GET"
    assert "resource_id" not in siem_msg
    assert "method" not in siem_msg
    # resource_ura/jwt_ura in both
    assert siem_msg["resource_ura"] == "00000001"
    assert siem_msg["jwt_ura"] == "00000123"


def test_success_keeps_thumbprint_prefix_only_in_app(
    streams: Streams,
) -> None:
    logger, app_messages, siem_messages = streams
    gflog.emit(
        logger,
        NviLog.AUTHENTICATION_SUCCESS,
        "ok",
        fields={"ura_number": "00000123", "cert_thumbprint_prefix": "validthu", "scope": "test-scope"},
    )

    app_msg = app_messages[0]
    siem_msg = siem_messages[0]

    assert app_msg["cert_thumbprint_prefix"] == "validthu"
    assert "cert_thumbprint_prefix" not in siem_msg  # not in SIEM allow-list for 004
    # ura/scope/endpoint/method in both
    for msg in (app_msg, siem_msg):
        assert msg["ura_number"] == "00000123"
        assert msg["scope"] == "test-scope"
        assert msg["endpoint"] == "/validate"


def test_prs_success_keeps_thumbprint_prefix_only_in_app(
    streams: Streams,
) -> None:
    logger, app_messages, siem_messages = streams
    gflog.emit(
        logger,
        PrsLog.AUTHENTICATION_SUCCESS,
        "ok",
        fields={
            "handelende_oin": "00000001123456700000",
            "ura_number": "00000123",
            "cert_thumbprint_prefix": "validthu",
            "scope": "test-scope",
        },
    )

    app_msg = app_messages[0]
    siem_msg = siem_messages[0]

    assert app_msg["cert_thumbprint_prefix"] == "validthu"
    assert "cert_thumbprint_prefix" not in siem_msg  # not in SIEM allow-list for PRS-AUTH-004
    # oin/scope/endpoint/method in both, NVI-only fields in neither
    for msg in (app_msg, siem_msg):
        assert msg["handelende_oin"] == "00000001123456700000"
        assert msg["scope"] == "test-scope"
        assert msg["endpoint"] == "/validate"
        assert msg["method"] == "GET"
        assert "ura_number" not in msg


def test_prs_token_binding_drops_failure_reason_from_siem(
    streams: Streams,
) -> None:
    logger, app_messages, siem_messages = streams
    gflog.emit(
        logger,
        PrsLog.TOKEN_BINDING_INVALID,
        "missing cnf claim",
        fields={
            "handelende_oin": "00000001123456700000",
            "failure_reason": "missing_cnf_claim",
            "cert_thumbprint_presented": "presentedthumb",
        },
    )

    app_msg = app_messages[0]
    siem_msg = siem_messages[0]

    assert app_msg["failure_reason"] == "missing_cnf_claim"
    assert "failure_reason" not in siem_msg  # not in SIEM allow-list for PRS-AUTH-007
    for msg in (app_msg, siem_msg):
        assert msg["handelende_oin"] == "00000001123456700000"
        assert msg["endpoint"] == "/validate"
        assert "cert_thumbprint_presented" not in msg


def test_records_carry_stream_id_and_application_id() -> None:
    # On the shared syslog channel the log server tells streams and
    # applications apart by the stream_id/application_id stamped per record.
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(
        JsonFormatter(
            include_traces=False,
            stream=LoggingStreams.APP,
            stream_id="app",
            application_id="nationale-verwijsindex-gateway-verifier",
        )
    )

    logger = logging.getLogger("app.test_stream_routing_ids")
    logger.setLevel(logging.DEBUG)
    logger.handlers = [handler]
    logger.propagate = False
    try:
        gflog.emit(logger, NviLog.AUTHENTICATION_SUCCESS, "authenticated", fields={"ura_number": "12345678"})
    finally:
        logger.handlers = []

    record = json.loads(buf.getvalue())
    assert record["stream_id"] == "app"
    assert record["application_id"] == "nationale-verwijsindex-gateway-verifier"
