import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.responses import JSONResponse

from app.config import Config, get_config
from app.container import get_jwt_service
from app.logging.events import BaseLog, get_application_log
from app.models.auth_headers import AuthHeaders
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
    jwt_service: JWTService,
) -> Response:
    logger.debug("Received request for /validate endpoint")
    config = get_config()
    log = get_application_log()

    try:
        auth_headers = AuthHeaders.from_request(request)
    except ValueError:
        log.event(
            logger,
            log.MISSING_AUTHORIZATION_HEADER,
            message="Headers are not correctly enforced in gateway, invalid authorization headers in request.",
            failure_reason="missing_oin_claim",
            token_present=False,
            exc_info=True,
            **request.headers,
        )
        raise HTTPException(status_code=500, detail="Unauthorized request")
    if not auth_headers.bearer.startswith("Bearer "):
        log.event(
            logger,
            log.JWT_VERIFICATION_FAILED,
            "malformed Authorization header",
            error_reason="malformed_authorization_header",
            token_present=True,
        )
        return Response("Bearer authorization header is required", status_code=401)

    token = auth_headers.bearer[len("Bearer ") :]
    return _validate_oin(
        log=log,
        auth_headers=auth_headers,
        token=token,
        jwt_service=jwt_service,
        config=config,
    )


def _validate_oin(
    log: type[BaseLog],
    auth_headers: AuthHeaders,
    token: str,
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

    jwt_oin = claims.get("sub")
    if not jwt_oin:
        log.event(
            logger,
            log.URA_AUTHORIZATION_MISMATCH,
            "missing OIN claim in token",
            client_organization_id=auth_headers.client_organization_id,
            client_common_name=auth_headers.client_common_name,
            failure_reason="missing_oin_claim",
            **claims,
        )
        return Response("Missing OIN claim in token", status_code=400)
    if str(jwt_oin) != str(auth_headers.client_organization_id):
        log.event(
            logger,
            log.URA_AUTHORIZATION_MISMATCH,
            "certificate OIN does not match JWT OIN",
            client_organization_id=auth_headers.client_organization_id,
            client_common_name=auth_headers.client_common_name,
            failure_reason="oin_mismatch",
            **claims,
        )
        return Response("Certificate OIN does not match JWT OIN", status_code=400)

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
    log.event(
        logger,
        log.AUTHENTICATION_SUCCESS,
        "successfully validated JWT + Client",
        **claims,
    )

    return JSONResponse(headers, status_code=200)


@router.get("/validate")
def validate(
    request: Request,
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> Response:
    return run_validate(request, jwt_service)
