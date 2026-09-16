import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from jwcrypto import jwk, jwt
from jwcrypto.common import base64url_decode, base64url_encode
from requests import Response
from requests.exceptions import HTTPError

from app.services.jwt import JWKS_TTL, JwtException, JWTService

ISSUER = "https://issuer.example"
AUDIENCE = ["nvi"]
TRUSTED_KID = "trusted-rsa-key"
PS256_KID = "trusted-ps256-key"
TIME_MARGIN_SECONDS = 3600


def valid_claims(**overrides: object) -> dict[str, object]:
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE[0],
        "exp": now + TIME_MARGIN_SECONDS,
        "nbf": now - TIME_MARGIN_SECONDS,
        "iat": now - TIME_MARGIN_SECONDS,
        "sub": "test-subject",
    }
    claims.update(overrides)
    return claims


def sign_token(
    signing_key: jwk.JWK,
    claims: dict[str, object],
    *,
    algorithm: str = "RS256",
    kid: str = TRUSTED_KID,
) -> str:
    token = jwt.JWT(
        header={"alg": algorithm, "kid": kid},
        claims=claims,
    )
    token.make_signed_token(signing_key)
    serialized = token.serialize()
    assert isinstance(serialized, str)
    return serialized


def corrupt_signature(token: str) -> str:
    protected, payload, encoded_signature = token.split(".")
    signature = bytearray(base64url_decode(encoded_signature))
    signature[0] ^= 1
    return f"{protected}.{payload}.{base64url_encode(bytes(signature))}"


def public_jwks_json(signing_key: jwk.JWK) -> str:
    public_jwks = jwk.JWKSet()
    public_jwks.add(jwk.JWK.from_json(signing_key.export_public()))
    serialized = public_jwks.export(private_keys=False)
    assert isinstance(serialized, str)
    return serialized


@pytest.fixture(scope="module")
def trusted_signing_key() -> jwk.JWK:
    return jwk.JWK.generate(
        kty="RSA",
        size=2048,
        kid=TRUSTED_KID,
        alg="RS256",
        use="sig",
    )


@pytest.fixture(scope="module")
def ps256_signing_key() -> jwk.JWK:
    return jwk.JWK.generate(
        kty="RSA",
        size=2048,
        kid=PS256_KID,
        alg="PS256",
        use="sig",
    )


@pytest.fixture(scope="module")
def untrusted_signing_key() -> jwk.JWK:
    return jwk.JWK.generate(
        kty="RSA",
        size=2048,
        kid="untrusted-rsa-key",
        alg="RS256",
        use="sig",
    )


@pytest.fixture()
def jwt_service(trusted_signing_key: jwk.JWK, ps256_signing_key: jwk.JWK) -> JWTService:
    trusted_jwks = jwk.JWKSet()
    trusted_jwks.add(jwk.JWK.from_json(trusted_signing_key.export_public()))
    trusted_jwks.add(jwk.JWK.from_json(ps256_signing_key.export_public()))

    service = JWTService(
        "https://unused.invalid/jwks",
        mtls_cert=None,
        mtls_key=None,
        verify_ca=True,
    )
    service.jwks_store = trusted_jwks
    service.jwks_ttl = datetime.max.replace(tzinfo=timezone.utc)
    return service


def test_accepts_valid_token(jwt_service: JWTService, trusted_signing_key: jwk.JWK) -> None:
    claims = valid_claims()

    verified_token = jwt_service.verify(sign_token(trusted_signing_key, claims), ISSUER, AUDIENCE)

    assert json.loads(verified_token.claims) == claims


def test_accepts_valid_ps256_token(jwt_service: JWTService, ps256_signing_key: jwk.JWK) -> None:
    claims = valid_claims()

    verified_token = jwt_service.verify(
        sign_token(ps256_signing_key, claims, algorithm="PS256", kid=PS256_KID),
        ISSUER,
        AUDIENCE,
    )

    assert json.loads(verified_token.claims) == claims


def test_rejects_token_signed_by_untrusted_key(
    jwt_service: JWTService,
    untrusted_signing_key: jwk.JWK,
) -> None:
    # Keep the trusted kid so rejection depends on signature verification, not key lookup.
    token = sign_token(untrusted_signing_key, valid_claims())

    with pytest.raises(JwtException):
        jwt_service.verify(token, ISSUER, AUDIENCE)


def test_rejects_corrupted_signature(jwt_service: JWTService, trusted_signing_key: jwk.JWK) -> None:
    token = sign_token(trusted_signing_key, valid_claims())

    with pytest.raises(JwtException):
        jwt_service.verify(corrupt_signature(token), ISSUER, AUDIENCE)


def test_rejects_wrong_issuer(jwt_service: JWTService, trusted_signing_key: jwk.JWK) -> None:
    token = sign_token(trusted_signing_key, valid_claims(iss="https://other-issuer.example"))

    with pytest.raises(JwtException):
        jwt_service.verify(token, ISSUER, AUDIENCE)


def test_rejects_nonmatching_audience(jwt_service: JWTService, trusted_signing_key: jwk.JWK) -> None:
    token = sign_token(trusted_signing_key, valid_claims(aud="other-service"))

    with pytest.raises(JwtException):
        jwt_service.verify(token, ISSUER, AUDIENCE)


def test_rejects_expired_token(jwt_service: JWTService, trusted_signing_key: jwk.JWK) -> None:
    token = sign_token(
        trusted_signing_key,
        valid_claims(exp=int(time.time()) - TIME_MARGIN_SECONDS),
    )

    with pytest.raises(JwtException):
        jwt_service.verify(token, ISSUER, AUDIENCE)


def test_rejects_token_that_is_not_yet_valid(jwt_service: JWTService, trusted_signing_key: jwk.JWK) -> None:
    token = sign_token(
        trusted_signing_key,
        valid_claims(nbf=int(time.time()) + TIME_MARGIN_SECONDS),
    )

    with pytest.raises(JwtException):
        jwt_service.verify(token, ISSUER, AUDIENCE)


@pytest.mark.parametrize("claim", ["iss", "aud", "exp", "nbf", "iat"])
def test_rejects_missing_required_claim(
    jwt_service: JWTService,
    trusted_signing_key: jwk.JWK,
    claim: str,
) -> None:
    claims = valid_claims()
    del claims[claim]
    token = sign_token(trusted_signing_key, claims)

    with pytest.raises(JwtException):
        jwt_service.verify(token, ISSUER, AUDIENCE)


def test_refresh_jwks_fetches_and_parses_public_jwks(
    jwt_service: JWTService,
    trusted_signing_key: jwk.JWK,
) -> None:
    jwks_json = public_jwks_json(trusted_signing_key)
    response = MagicMock(spec=Response)
    response.text = jwks_json
    jwt_service.jwks_store = None

    with patch.object(jwt_service._http_service, "do_request", return_value=response) as do_request:
        jwt_service.refresh_jwks()

    do_request.assert_called_once_with(method="GET")
    response.raise_for_status.assert_called_once_with()
    assert jwt_service.jwks_store is not None
    assert json.loads(jwt_service.jwks_store.export(private_keys=False)) == json.loads(jwks_json)


def test_get_jwks_returns_unexpired_cache_without_http(jwt_service: JWTService) -> None:
    now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    cached_jwks = jwt_service.jwks_store
    cached_ttl = now + timedelta(seconds=1)
    jwt_service.jwks_ttl = cached_ttl

    with (
        patch.object(jwt_service._http_service, "do_request") as do_request,
        patch("app.services.jwt.datetime") as datetime_mock,
    ):
        datetime_mock.now.return_value = now
        actual = jwt_service._get_jwks()

    assert actual is cached_jwks
    assert jwt_service.jwks_ttl == cached_ttl
    do_request.assert_not_called()


@pytest.mark.parametrize("cache_state", ["empty", "expired"])
def test_get_jwks_refreshes_empty_or_expired_cache(
    jwt_service: JWTService,
    trusted_signing_key: jwk.JWK,
    cache_state: str,
) -> None:
    now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    jwks_json = public_jwks_json(trusted_signing_key)
    response = MagicMock(spec=Response)
    response.text = jwks_json

    if cache_state == "empty":
        jwt_service.jwks_store = None
        jwt_service.jwks_ttl = now + timedelta(seconds=1)
    else:
        jwt_service.jwks_ttl = now - timedelta(seconds=1)

    with (
        patch.object(jwt_service._http_service, "do_request", return_value=response) as do_request,
        patch("app.services.jwt.datetime") as datetime_mock,
    ):
        datetime_mock.now.return_value = now
        actual = jwt_service._get_jwks()

    do_request.assert_called_once_with(method="GET")
    response.raise_for_status.assert_called_once_with()
    assert actual is jwt_service.jwks_store
    assert jwt_service.jwks_ttl == now + JWKS_TTL


def test_get_jwks_propagates_refresh_error_and_preserves_expired_cache(
    jwt_service: JWTService,
) -> None:
    now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    previous_store = jwt_service.jwks_store
    previous_ttl = now - timedelta(seconds=1)
    jwt_service.jwks_ttl = previous_ttl
    response = MagicMock(spec=Response)
    response.raise_for_status.side_effect = HTTPError("JWKS unavailable")

    with (
        patch.object(jwt_service._http_service, "do_request", return_value=response) as do_request,
        patch("app.services.jwt.datetime") as datetime_mock,
    ):
        datetime_mock.now.return_value = now
        with pytest.raises(HTTPError, match="JWKS unavailable"):
            jwt_service._get_jwks()

    do_request.assert_called_once_with(method="GET")
    response.raise_for_status.assert_called_once_with()
    assert jwt_service.jwks_store is previous_store
    assert jwt_service.jwks_ttl == previous_ttl
