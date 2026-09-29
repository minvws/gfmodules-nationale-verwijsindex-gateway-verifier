import pytest
from gfmodules.logging import LogEvent, declared_events
from gfmodules.logging.testing import assert_catalogue_complete

from app.logging.events import Log


def test_defines_every_required_event() -> None:
    assert_catalogue_complete(Log)


def test_every_declared_event_routes_at_least_one_stream() -> None:
    for name, event in declared_events(Log):
        assert event.streams, f"{name} declares no stream"


def test_every_allow_list_names_a_stream_the_event_routes() -> None:
    for name, event in declared_events(Log):
        unrouted = set(event.fields) - set(event.streams)
        assert not unrouted, f"{name} allow-lists fields for streams it does not route: {unrouted}"


@pytest.mark.parametrize(
    "name,event_id",
    [
        ("JWT_VERIFICATION_FAILED", "200400"),
        ("MTLS_BINDING_MISMATCH", "200401"),
        ("TOKEN_BINDING_INVALID", "200406"),
        ("ORGANIZATION_AUTHORIZATION_MISMATCH", "200407"),
        ("MISSING_ORGANIZATION_CLAIM", "200408"),
        ("MALFORMED_AUTHORIZATION_HEADER", "200409"),
        ("MISSING_ACT_CLAIM", "200410"),
        ("COMMON_NAME_AUTHORIZATION_MISMATCH", "200411"),
        ("AUTHENTICATION_SUCCESS", "200403"),
        ("MISSING_AUTHORIZATION_HEADER", "200404"),
        ("SYS_APP_STARTED", "200601"),
        ("SYS_APP_STOPPED", "200602"),
        ("SYS_APP_CRASHED", "200602"),
        ("SYS_UNHANDLED_EXCEPTION", "200604"),
        ("SYS_MISSING_CORRELATION_ID", "200606"),
    ],
)
def test_carries_the_event_id_the_spec_assigns(name: str, event_id: str) -> None:
    assert getattr(Log, name).event_id == event_id


def test_every_gateway_verifier_event_id_is_in_the_200xxx_range() -> None:
    for name, event in vars(Log).items():
        if isinstance(event, LogEvent):
            assert event.event_id.startswith("200"), f"{name} has event id {event.event_id!r}, expected a 200xxx id"
