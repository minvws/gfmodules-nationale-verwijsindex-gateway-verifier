from datetime import datetime, timedelta, timezone

import requests
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException
from jwcrypto.jwt import JWT

# Cache time for JWKS
JWKS_TTL = timedelta(minutes=15)


class JwtException(Exception):
    pass


class JWTService:
    def __init__(self, jwks_url: str) -> None:
        self.jwks_url = jwks_url
        self.jwks_store: jwk.JWKSet | None = None
        self.jwks_ttl: datetime | None = None

    def refresh_jwks(self) -> None:
        r = requests.get(self.jwks_url, timeout=5)
        r.raise_for_status()
        self.jwks_store = jwk.JWKSet.from_json(r.text)

    def _get_jwks(self) -> jwk.JWKSet:
        now = datetime.now(timezone.utc)

        if self.jwks_store is None or self.jwks_ttl is None or self.jwks_ttl < now:
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
            raise JwtException(f"JWT validation failed: {e}") from e
        except Exception as e:
            raise JwtException(f"Unexpected JWT validation error: {e}") from e
