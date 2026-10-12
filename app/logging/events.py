import hashlib
import logging

from gfmodules.logging import DefaultEventCatalogue, LogEvent, LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM

_Base = DefaultEventCatalogue

# Length of the certificate thumbprint prefix logged on success (never the full value).
_THUMBPRINT_PREFIX_LEN = 8


class Log(_Base):
    JWT_VERIFICATION_FAILED = LogEvent(
        "200400",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("error_reason", "token_present"),
            _SIEM: ("error_reason", "token_present"),
        },
    )
    MALFORMED_AUTHORIZATION_HEADER = LogEvent(
        "200409",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("error_reason", "token_present"),
            _SIEM: ("error_reason", "token_present"),
        },
    )
    MTLS_BINDING_MISMATCH = LogEvent(
        "200401",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: (
                "certificate_organization_identifier",
                "cert_thumbprint_jwt",
                "cert_thumbprint_presented",
                "client_id",
            ),
            _SIEM: (
                "certificate_organization_identifier",
                "cert_thumbprint_presented",
                "cert_thumbprint_jwt",
                "client_id",
            ),
        },
    )
    TOKEN_BINDING_INVALID = LogEvent(
        "200406",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("certificate_organization_identifier", "failure_reason"),
            _SIEM: ("certificate_organization_identifier",),
        },
    )
    ORGANIZATION_AUTHORIZATION_MISMATCH = LogEvent(
        "200407",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: (
                "certificate_organization_identifier",
                "resource_organization_identifier",
                "resource_id",
                "client_id",
            ),
            _SIEM: ("certificate_organization_identifier", "resource_organization_identifier", "client_id"),
        },
    )
    MISSING_ORGANIZATION_CLAIM = LogEvent(
        "200408",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("certificate_organization_identifier", "client_id"),
            _SIEM: ("certificate_organization_identifier", "client_id"),
        },
    )
    MISSING_ACT_CLAIM = LogEvent(
        "200410",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("certificate_organization_identifier", "client_id"),
            _SIEM: ("certificate_organization_identifier", "client_id"),
        },
    )
    COMMON_NAME_AUTHORIZATION_MISMATCH = LogEvent(
        "200411",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("certificate_organization_identifier", "client_id"),
            _SIEM: ("certificate_organization_identifier", "client_id"),
        },
    )
    AUTHENTICATION_SUCCESS = LogEvent(
        "200403",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: (
                "certificate_organization_identifier",
                "represented_organization_identifier",
                "cert_thumbprint_prefix",
            ),
            _SIEM: ("certificate_organization_identifier", "represented_organization_identifier"),
        },
    )
    MISSING_AUTHORIZATION_HEADER = LogEvent(
        "200404",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("token_present", "client_id", "certificate_organization_identifier"),
            _SIEM: ("client_id", "certificate_organization_identifier"),
        },
    )
    SYS_APP_STARTED = _Base.SYS_APP_STARTED.with_id("200601")
    SYS_APP_STOPPED = _Base.SYS_APP_STOPPED.with_id("200602")
    SYS_APP_CRASHED = _Base.SYS_APP_CRASHED.with_id("200602")
    SYS_UNHANDLED_EXCEPTION = _Base.SYS_UNHANDLED_EXCEPTION.with_id("200604")
    SYS_MISSING_CORRELATION_ID = _Base.SYS_MISSING_CORRELATION_ID.with_id("200606")

    @staticmethod
    def thumbprint_prefix(value: str | None) -> str | None:
        if not value:
            return None
        return value[:_THUMBPRINT_PREFIX_LEN]

    @staticmethod
    def hash_thumbprint(value: str | None) -> str | None:
        if not value:
            return None
        return hashlib.sha256(value.encode("ascii")).hexdigest()[:16]
