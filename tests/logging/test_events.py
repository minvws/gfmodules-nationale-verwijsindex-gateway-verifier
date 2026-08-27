import pytest
from gfmodules.logging import (
    DefaultEventCatalogue,
    EventCatalogue,
    LoggingStreams,
    declared_events,
)
from gfmodules.logging.testing import assert_catalogue_complete

from app.config import ApplicationLogType
from app.logging.events import BaseLog, NviLog, PrsLog, get_application_log

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM

_CATALOGUES = [NviLog, PrsLog]


@pytest.mark.parametrize("catalogue", _CATALOGUES)
class TestBothCatalogues:
    def test_defines_every_required_event(self, catalogue: type[EventCatalogue]) -> None:
        assert_catalogue_complete(catalogue, access_logs=False)

    def test_every_declared_event_routes_at_least_one_stream(self, catalogue: type[EventCatalogue]) -> None:
        for name, event in declared_events(catalogue):
            assert event.streams, f"{name} declares no stream"

    def test_every_allow_list_names_a_stream_the_event_routes(self, catalogue: type[EventCatalogue]) -> None:
        for name, event in declared_events(catalogue):
            unrouted = set(event.fields) - set(event.streams)
            assert not unrouted, f"{name} allow-lists fields for streams it does not route: {unrouted}"

    def test_binds_every_trigger_the_verifier_logs(self, catalogue: type[EventCatalogue]) -> None:
        for name in BaseLog.__annotations__:
            assert getattr(catalogue, name, None) is not None, f"{name} is unbound"


class TestNviEventIds:
    @pytest.mark.parametrize(
        "name,event_id",
        [
            ("JWT_VERIFICATION_FAILED", "094445"),
            ("MTLS_BINDING_MISMATCH", "094446"),
            ("URA_AUTHORIZATION_MISMATCH", "094447"),
            ("AUTHENTICATION_SUCCESS", "091111"),
            ("MISSING_AUTHORIZATION_HEADER", "094449"),
            ("SYS_APP_STARTED", "100601"),
            ("SYS_APP_STOPPED", "100602"),
            ("SYS_APP_CRASHED", "100602"),
            ("SYS_UNHANDLED_EXCEPTION", "100604"),
            ("SYS_MISSING_CORRELATION_ID", "100606"),
            ("ACCESS_REQUEST", "094500"),
        ],
    )
    def test_carries_the_event_id_the_spec_assigns(self, name: str, event_id: str) -> None:
        assert getattr(NviLog, name).event_id == event_id


class TestPrsEventIds:
    @pytest.mark.parametrize(
        "name,event_id",
        [
            ("JWT_VERIFICATION_FAILED", "200400"),
            ("MTLS_BINDING_MISMATCH", "200401"),
            ("TOKEN_BINDING_INVALID", "200406"),
            ("AUTHENTICATION_SUCCESS", "200403"),
            ("MISSING_AUTHORIZATION_HEADER", "200404"),
            ("SYS_APP_STARTED", "270401"),
            ("SYS_APP_STOPPED", "270402"),
            ("SYS_APP_CRASHED", "270402"),
            ("SYS_UNHANDLED_EXCEPTION", "270404"),
            ("SYS_MISSING_CORRELATION_ID", "270407"),
        ],
    )
    def test_carries_the_event_id_the_spec_assigns(self, name: str, event_id: str) -> None:
        assert getattr(PrsLog, name).event_id == event_id


class TestTheSystemsUseDistinctIds:
    def test_no_shared_trigger_reports_the_same_id_in_both_systems(self) -> None:
        for name in BaseLog.__annotations__:
            assert getattr(NviLog, name).event_id != getattr(PrsLog, name).event_id, name


class TestCatalogueSelection:
    def test_defaults_to_nvi(self) -> None:
        assert get_application_log() is NviLog

    def test_both_report_a_missing_correlation_id_to_siem(self) -> None:
        assert DefaultEventCatalogue.SYS_MISSING_CORRELATION_ID.streams == (_APP,)
        for catalogue in _CATALOGUES:
            assert catalogue.SYS_MISSING_CORRELATION_ID.streams == (_APP, _SIEM)

    def test_the_selection_covers_every_configured_log_type(self) -> None:
        assert {ApplicationLogType.nvi, ApplicationLogType.prs} == set(ApplicationLogType)


class TestClaimsAreNotTrusted:
    def test_a_claim_named_after_a_record_attribute_is_dropped(self) -> None:
        from app.routers.validator import _loggable

        assert _loggable({"scope": "read", "name": "spoofed", "message": "spoofed"}) == {"scope": "read"}
