import hashlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.logging.filters import LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM

# Length of the certificate thumbprint prefix logged on success (never the full value).
_THUMBPRINT_PREFIX_LEN = 8


@dataclass(frozen=True)
class NVIEvent:
    event_id: str
    level: int
    streams: tuple[LoggingStreams, ...]
    # Per-stream allow-list of field names. APP == "stroom 2", SIEM == "stroom 3".
    # When empty, no per-field routing is applied and every field is sent to all
    # streams in ``streams``.
    fields: Mapping[LoggingStreams, tuple[str, ...]] = field(default_factory=dict)


class Log:
    # Authentication / Authorization (NVI-AUTH) for the gateway verifier.
    # See https://github.com/minvws/gfmodules-coordination-private/issues/994
    # The ``fields`` map mirrors the "Stroom 2" (APP) / "Stroom 3" (SIEM) columns.
    JWT_VERIFICATION_FAILED = NVIEvent(  # NVI-AUTH-001
        "094445",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("error_reason", "token_present", "endpoint"),
            _SIEM: ("error_reason", "token_present", "endpoint"),
        },
    )
    MTLS_BINDING_MISMATCH = NVIEvent(  # NVI-AUTH-002
        "094446",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("jwt_ura", "cert_thumbprint_jwt", "cert_thumbprint_presented", "endpoint", "client_id"),
            _SIEM: ("jwt_ura", "cert_thumbprint_presented", "cert_thumbprint_jwt", "client_id"),
        },
    )
    URA_AUTHORIZATION_MISMATCH = NVIEvent(  # NVI-AUTH-003
        "094447",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("jwt_ura", "resource_ura", "resource_id", "endpoint", "method", "client_id"),
            _SIEM: ("jwt_ura", "resource_ura", "endpoint", "client_id"),
        },
    )
    AUTHENTICATION_SUCCESS = NVIEvent(  # NVI-AUTH-004
        "091111",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: ("ura_number", "cert_thumbprint_prefix", "endpoint", "method", "ip", "scope"),
            _SIEM: ("ura_number", "endpoint", "method", "ip", "scope"),
        },
    )
    MISSING_AUTHORIZATION_HEADER = NVIEvent(  # NVI-AUTH-005
        "094449",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("endpoint", "method", "token_present", "client_id"),
            _SIEM: ("endpoint", "client_id"),
        },
    )

    @staticmethod
    def thumbprint_prefix(value: str | None) -> str | None:
        """Return a short, non-reversible prefix of a certificate thumbprint.

        The spec requires logging a prefix rather than the full thumbprint on
        successful authentication (NVI-AUTH-004).
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
        event: NVIEvent,
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
