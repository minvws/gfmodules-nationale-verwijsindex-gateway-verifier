import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse

from app.config import Config, get_config
from app.container import get_ca_service, get_jwt_service
from app.logging.events import BaseLog, get_application_log
from app.models.oin import OinNumber
from app.services.ca import CaService
from app.services.jwt import JwtException, JWTService

logger = logging.getLogger(__name__)
router = APIRouter()


def _aud_str(aud: object) -> str:
    """Normalise the JWT aud claim to a string — it can legally be a string or a list."""
    if isinstance(aud, list):
        return ", ".join(str(a) for a in aud)
    return str(aud) if aud is not None else ""


def run_validate(
    request: Request,
    ca_service: CaService,
    jwt_service: JWTService,
) -> Response:
    logger.debug("Received request for /validate endpoint")
    config = get_config()
    log = get_application_log()

    auth = request.headers.get("Authorization")
    if auth is None:
        client_id = _client_id(ca_service, request)
        log.event(
            logger,
            log.MISSING_AUTHORIZATION_HEADER,
            "request to protected endpoint without Authorization header",
            token_present=False,
            client_id=client_id,
            handelende_oin=client_id,
        )
        return Response("Bearer authorization header is required", status_code=401)
    if not auth.startswith("Bearer "):
        log.event(
            logger,
            log.JWT_VERIFICATION_FAILED,
            "malformed Authorization header",
            error_reason="malformed_authorization_header",
            token_present=True,
        )
        return Response("Bearer authorization header is required", status_code=401)

    token = auth[len("Bearer ") :]
    ok, cert_oin = ca_service.is_oin_certificate(request)
    if ok and cert_oin is not None:
        return _validate_oin(log, cert_oin, token, request, ca_service, jwt_service, config)

    # No (valid) client certificate presented to bind the token to.
    log.event(
        logger,
        log.MTLS_BINDING_MISMATCH,
        "no valid client certificate presented",
        cert_thumbprint_presented=ca_service.get_presented_thumbprint(request),
    )
    return Response("Authentication failed", status_code=403)


def _client_id(ca_service: CaService, request: Request) -> str | None:
    """Best-effort client identity (the presented certificate's OIN) for audit logging."""
    _, cert_oin = ca_service.is_oin_certificate(request)
    return str(cert_oin) if cert_oin is not None else None


def _check_cert_fingerprint(
    log: type[BaseLog],
    claims: dict[str, object],
    request: Request,
    ca_service: CaService,
    cert_oin: OinNumber,
) -> Response | None:
    """Returns an error Response if the cnf/x5t#S256 fingerprint is missing or doesn't match the cert."""
    cnf = claims.get("cnf")
    thumbprint = cnf.get("x5t#S256") if isinstance(cnf, dict) else None
    if not thumbprint:
        log.event(
            logger,
            log.TOKEN_BINDING_INVALID,
            "missing cnf/x5t#S256 claim in token",
            jwt_ura=claims.get("sub"),
            cert_thumbprint_jwt=None,
            cert_thumbprint_presented=ca_service.get_presented_thumbprint(request),
            client_id=str(cert_oin),
            handelende_oin=str(cert_oin),
            failure_reason="missing_cnf_claim",
        )
        return Response("Missing certificate fingerprint claim in token", status_code=400)
    if not ca_service.check_cert_fingerprint(request, thumbprint):
        log.event(
            logger,
            log.MTLS_BINDING_MISMATCH,
            "certificate fingerprint does not match cnf/x5t#S256 claim",
            jwt_ura=claims.get("sub"),
            cert_thumbprint_jwt=thumbprint,
            cert_thumbprint_presented=ca_service.get_presented_thumbprint(request),
            client_id=str(cert_oin),
            handelende_oin=str(cert_oin),
        )
        return Response("Certificate fingerprint mismatch", status_code=400)
    return None


def _validate_oin(
    log: type[BaseLog],
    cert_oin: OinNumber,
    token: str,
    request: Request,
    ca_service: CaService,
    jwt_service: JWTService,
    config: Config,
) -> Response:
    try:
        verified_token = jwt_service.verify(token, config.oin.issuer, config.oin.audience)
    except JwtException as e:
        log.event(
            logger,
            log.JWT_VERIFICATION_FAILED,
            "failed to verify JWT",
            error_reason=str(e),
            token_present=True,
        )
        return Response("Token verification failed", status_code=400)

    claims = json.loads(verified_token.claims)

    if err := _check_cert_fingerprint(log, claims, request, ca_service, cert_oin):
        return err

    jwt_oin = claims.get("oin") or claims.get("sub")
    if not jwt_oin:
        log.event(
            logger,
            log.URA_AUTHORIZATION_MISMATCH,
            "missing OIN claim in token",
            jwt_ura=claims.get("sub"),
            resource_ura=str(cert_oin),
            client_id=str(cert_oin),
            handelende_oin=str(cert_oin),
            failure_reason="missing_oin_claim",
        )
        return Response("Missing OIN claim in token", status_code=400)
    if str(jwt_oin) != str(cert_oin):
        log.event(
            logger,
            log.URA_AUTHORIZATION_MISMATCH,
            "certificate OIN does not match JWT OIN",
            jwt_ura=claims.get("sub"),
            resource_ura=str(cert_oin),
            resource_id=str(jwt_oin),
            client_id=str(cert_oin),
            handelende_oin=str(cert_oin),
            failure_reason="oin_mismatch",
        )
        return Response("Certificate OIN does not match JWT OIN", status_code=400)

    cnf = claims.get("cnf")
    thumbprint = cnf.get("x5t#S256") if isinstance(cnf, dict) else None
    log.event(
        logger,
        log.AUTHENTICATION_SUCCESS,
        "successfully validated JWT + mTLS",
        ura_number=claims.get("sub"),
        cert_thumbprint_prefix=log.thumbprint_prefix(thumbprint),
        scope=claims.get("scope", ""),
        client_id=str(cert_oin),
        handelende_oin=str(cert_oin),
    )

    headers: dict[str, str] = {
        "x-gf-cert-type": "OIN",
        "x-gf-audience": _aud_str(claims.get("aud")),
        "x-gf-scope": claims.get("scope", ""),
        "x-gf-sub": claims.get("sub"),
    }
    # check if PRS claims are present
    if claims.get("org_oin") is not None:
        # subject is the oin
        headers["x-gf-oin"] = str(claims["org_oin"])
    else:
        # otherwise default to NVI
        headers["x-gf-oin"] = str(claims["oin"])
    if claims.get("source_id"):
        headers["x-gf-source-id"] = str(claims["source_id"])
    if claims.get("organization_name"):
        headers["x-gf-organization-name"] = str(claims["organization_name"])

    return JSONResponse(headers, status_code=200)


@router.get("/validate")
def validate(
    request: Request,
    ca_service: Annotated[CaService, Depends(get_ca_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    return run_validate(request, ca_service, jwt_service)
