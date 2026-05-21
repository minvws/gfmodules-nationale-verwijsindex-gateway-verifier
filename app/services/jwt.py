import logging
from datetime import datetime, timedelta, timezone

from jwcrypto import jwk, jwt
from jwcrypto.common import JWException
from jwcrypto.jwt import JWT

from app.services.http_service import HttpService

# Cache time for JWKS
JWKS_TTL = timedelta(minutes=15)

logger = logging.getLogger(__name__)


class JwtException(Exception):
    pass


class JWTService:
    def __init__(self, jwks_url: str, mtls_cert: str | None, mtls_key: str | None, verify_ca: str | bool) -> None:
        self.jwks_store: jwk.JWKSet | None = None
        self.jwks_ttl: datetime | None = None
        self._http_service = HttpService(
            jwks_url, timeout=5, mtls_cert=mtls_cert, mtls_key=mtls_key, verify_ca=verify_ca
        )

    def health_check(self) -> bool:
        return self._http_service.server_healthy()

    def refresh_jwks(self) -> None:
        logger.debug("Requesting new JWKS")
        r = self._http_service.do_request(method="GET")
        r.raise_for_status()
        self.jwks_store = jwk.JWKSet.from_json(r.text)

    def _get_jwks(self) -> jwk.JWKSet:
        now = datetime.now(timezone.utc)

        if self.jwks_store is None or self.jwks_ttl is None or self.jwks_ttl < now:
            logger.debug("Cache expired or not found. Refreshing JWKS")
            self.refresh_jwks()
            self.jwks_ttl = now + JWKS_TTL

        return self.jwks_store

    def verify(self, token_str: str, issuer: str, audience: list[str]) -> JWT:
        try:
            return jwt.JWT(
                jwt=token_str,
                key=self._get_jwks(),
                check_claims={
                    "iss": issuer,
                    "aud": audience,
                    "exp": None,
                    "nbf": None,
                    "iat": None,
                },
                expected_type="JWS",
            )
        except JWException as e:
            logger.error(f"JWT verification error: {e}")
            raise JwtException(f"JWT validation failed: {e}") from e
        except Exception as e:
            logger.error(f"Global JWT verification error: {e}")
            raise JwtException(f"Unexpected JWT validation error: {e}") from e
