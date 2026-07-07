import hashlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.config import ApplicationLogType, get_config
from app.logging.filters import LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM

# Length of the certificate thumbprint prefix logged on success (never the full value).
_THUMBPRINT_PREFIX_LEN = 8


@dataclass(frozen=True)
class LogEvent:
    event_id: str
    level: int
    streams: tuple[LoggingStreams, ...]
    # Per-stream allow-list of field names. APP == "stroom 2", SIEM == "stroom 3".
    # When empty, no per-field routing is applied and every field is sent to all
    # streams in ``streams``.
    fields: Mapping[LoggingStreams, tuple[str, ...]] = field(default_factory=dict)


class BaseLog:
    """Audit events for the gateway verifier.

    The verifier can front different systems (NVI, PRS) that each define their
    own event IDs and per-stream field specs for the same validation triggers.
    Subclasses bind each trigger below to the system-specific event; call sites
    pass the union of both systems' fields and the per-stream allow-lists route
    what each event actually emits.
    """

    JWT_VERIFICATION_FAILED: ClassVar[LogEvent]
    MTLS_BINDING_MISMATCH: ClassVar[LogEvent]
    # Token-binding claim (cnf/x5t#S256) missing, or the token identity does not
    # match the TLS identity. NVI has no separate event for this trigger; PRS
    # defines a dedicated one (PRS-AUTH-007).
    TOKEN_BINDING_INVALID: ClassVar[LogEvent]
    URA_AUTHORIZATION_MISMATCH: ClassVar[LogEvent]
    AUTHENTICATION_SUCCESS: ClassVar[LogEvent]
    MISSING_AUTHORIZATION_HEADER: ClassVar[LogEvent]

    @staticmethod
    def thumbprint_prefix(value: str | None) -> str | None:
        """Return a short, non-reversible prefix of a certificate thumbprint.

        The spec requires logging a prefix rather than the full thumbprint on
        successful authentication (NVI-AUTH-004 / PRS-AUTH-004).
        """
        if not value:
            return None
        return value[:_THUMBPRINT_PREFIX_LEN]

    @staticmethod
    def hash_thumbprint(value: str | None) -> str | None:
        if not value:
            return None
        return hashlib.sha256(value.encode("ascii")).hexdigest()[:16]

    @staticmethod
    def event(
        logger: logging.Logger,
        event: LogEvent,
        message: str,
        *,
        exc_info: Any = None,
        **fields: Any,
    ) -> None:
        extra: dict[str, Any] = {
            "event_id": event.event_id,
            "stream": list(event.streams),
        }
        if event.fields:
            extra["field_streams"] = event.fields
        extra.update(fields)
        logger.log(event.level, message, extra=extra, exc_info=exc_info)


class NviLog(BaseLog):
    # Authentication / Authorization (NVI-AUTH) for the gateway verifier.
    # See https://github.com/minvws/gfmodules-coordination-private/issues/994
    # The ``fields`` map mirrors the "Stroom 2" (APP) / "Stroom 3" (SIEM) columns.
    JWT_VERIFICATION_FAILED = LogEvent(  # NVI-AUTH-001
        "094445",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("error_reason", "token_present", "endpoint"),
            _SIEM: ("error_reason", "token_present", "endpoint"),
        },
    )
    MTLS_BINDING_MISMATCH = LogEvent(  # NVI-AUTH-002
        "094446",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("jwt_ura", "cert_thumbprint_jwt", "cert_thumbprint_presented", "endpoint", "client_id"),
            _SIEM: ("jwt_ura", "cert_thumbprint_presented", "cert_thumbprint_jwt", "client_id"),
        },
    )
    # NVI-AUTH has no dedicated token-binding event; this trigger logs as NVI-AUTH-002.
    TOKEN_BINDING_INVALID = MTLS_BINDING_MISMATCH
    URA_AUTHORIZATION_MISMATCH = LogEvent(  # NVI-AUTH-003
        "094447",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("jwt_ura", "resource_ura", "resource_id", "endpoint", "method", "client_id"),
            _SIEM: ("jwt_ura", "resource_ura", "endpoint", "client_id"),
        },
    )
    AUTHENTICATION_SUCCESS = LogEvent(  # NVI-AUTH-004
        "091111",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: ("ura_number", "cert_thumbprint_prefix", "endpoint", "method", "ip", "scope"),
            _SIEM: ("ura_number", "endpoint", "method", "ip", "scope"),
        },
    )
    MISSING_AUTHORIZATION_HEADER = LogEvent(  # NVI-AUTH-005
        "094449",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("endpoint", "method", "token_present", "client_id"),
            _SIEM: ("endpoint", "client_id"),
        },
    )


class PrsLog(BaseLog):
    # Authentication / Authorization (PRS-AUTH) for the gateway verifier.
    # See https://github.com/minvws/gfmodules-coordination-private/issues/1034
    # The ``fields`` map mirrors the "Stroom 2" (APP) / "Stroom 3" (SIEM) columns.
    # Not defined here: PRS-AUTH-003 (200402, autorisatie geweigerd) is emitted
    # by the PRS application itself, and PRS-AUTH-006 (200405, rate limit
    # exceeded) belongs to the rate limiter (KONG).
    JWT_VERIFICATION_FAILED = LogEvent(  # PRS-AUTH-001
        "200400",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("error_reason", "token_present", "endpoint", "method"),
            _SIEM: ("error_reason", "token_present", "endpoint"),
        },
    )
    MTLS_BINDING_MISMATCH = LogEvent(  # PRS-AUTH-002
        "200401",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("handelende_oin", "cert_thumbprint_jwt", "cert_thumbprint_presented", "endpoint"),
            _SIEM: ("handelende_oin", "cert_thumbprint_presented", "cert_thumbprint_jwt"),
        },
    )
    TOKEN_BINDING_INVALID = LogEvent(  # PRS-AUTH-007
        "200406",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("handelende_oin", "endpoint", "failure_reason"),
            _SIEM: ("handelende_oin", "endpoint"),
        },
    )
    # A token OIN that does not match the certificate OIN is a token-binding
    # failure in PRS terms (PRS-AUTH-007: "matcht de TLS-identiteit niet").
    URA_AUTHORIZATION_MISMATCH = TOKEN_BINDING_INVALID
    AUTHENTICATION_SUCCESS = LogEvent(  # PRS-AUTH-004
        "200403",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: ("handelende_oin", "namens_oin", "cert_thumbprint_prefix", "endpoint", "method", "ip", "scope"),
            _SIEM: ("handelende_oin", "namens_oin", "endpoint", "method", "ip", "scope"),
        },
    )
    MISSING_AUTHORIZATION_HEADER = LogEvent(  # PRS-AUTH-005
        "200404",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("endpoint", "method", "token_present", "handelende_oin"),
            _SIEM: ("endpoint", "handelende_oin"),
        },
    )


def get_application_log() -> type[BaseLog]:
    """Return the event definitions for the system this verifier fronts."""
    if get_config().logging.application_log_type == ApplicationLogType.prs:
        return PrsLog
    return NviLog
